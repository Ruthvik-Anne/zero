//! Session log (SES-01, SES-07): a stable, append-only JSONL schema plus a
//! streaming index and chunked attach.
//!
//! Ordering is by `seq`, never by timestamp. `generation` changes when a session
//! is rewritten (compaction/import); a cursor is `{generation, sequence}`.

use crate::jsonl::{repair_raw, scan_raw, JsonlWriter};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use zero_types::error::{ErrorCode, Result, ZeroError};

pub const ENTRY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileTouch {
    pub path: String,
    pub edits: u64,
    #[serde(default)]
    pub last_seq: u64,
}

/// The six required sections plus cumulative file tracking (SES-04).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchSummary {
    pub goal: String,
    #[serde(default)]
    pub constraints: Vec<String>,
    #[serde(default)]
    pub progress: Vec<String>,
    #[serde(default)]
    pub decisions: Vec<String>,
    #[serde(default)]
    pub next_steps: Vec<String>,
    #[serde(default)]
    pub critical_context: Vec<String>,
    #[serde(default)]
    pub files: BTreeMap<String, FileTouch>,
}

impl BranchSummary {
    /// Shape validation: every section exists (serde default would hide a
    /// missing key, so parsing is done through [`parse_strict`]).
    pub fn parse_strict(text: &str) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_str(text)?;
        let obj = value.as_object().ok_or_else(|| {
            ZeroError::new(ErrorCode::SummaryInvalid, "branch summary must be a JSON object")
        })?;
        for section in [
            "goal",
            "constraints",
            "progress",
            "decisions",
            "next_steps",
            "critical_context",
            "files",
        ] {
            if !obj.contains_key(section) {
                return Err(ZeroError::new(
                    ErrorCode::SummaryInvalid,
                    format!("branch summary is missing the `{section}` section"),
                ));
            }
        }
        if obj["goal"].as_str().map(|g| g.trim().is_empty()).unwrap_or(true) {
            return Err(ZeroError::new(ErrorCode::SummaryInvalid, "branch summary goal is empty"));
        }
        Ok(serde_json::from_value(value)?)
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("GOAL: {}\n", self.goal));
        for (title, items) in [
            ("CONSTRAINTS", &self.constraints),
            ("PROGRESS", &self.progress),
            ("DECISIONS", &self.decisions),
            ("NEXT STEPS", &self.next_steps),
            ("CRITICAL CONTEXT", &self.critical_context),
        ] {
            out.push_str(&format!("{title}:\n"));
            if items.is_empty() {
                out.push_str("- (none)\n");
            }
            for item in items {
                out.push_str(&format!("- {item}\n"));
            }
        }
        out.push_str("FILES:\n");
        if self.files.is_empty() {
            out.push_str("- (none)\n");
        }
        for (path, touch) in &self.files {
            out.push_str(&format!("- {path} ({} edits, last seq {})\n", touch.edits, touch.last_seq));
        }
        out
    }
}

/// One session entry. The tag is stable; new kinds are additive only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Entry {
    Message {
        role: Role,
        text: String,
        #[serde(default)]
        tool_calls: Vec<ToolCall>,
        #[serde(default)]
        tool_call_id: Option<String>,
    },
    ModelChange { provider: String, model: String },
    ThinkingLevel { level: String },
    ServiceTier { tier: String },
    Compaction {
        summary: String,
        keep_from_seq: u64,
        removed_entries: u64,
    },
    BranchSummary { summary: BranchSummary },
    Custom { name: String, data: serde_json::Value },
    ChildUsage {
        child: String,
        input_tokens: u64,
        output_tokens: u64,
        cost_micros: u64,
    },
    Label { name: String },
    Info { text: String },
    State { key: String, value: serde_json::Value },
    Status { state: String },
    GitState {
        #[serde(default)]
        branch: Option<String>,
        #[serde(default)]
        commit: Option<String>,
        #[serde(default)]
        dirty: bool,
    },
}

impl Entry {
    pub fn kind(&self) -> &'static str {
        match self {
            Entry::Message { .. } => "message",
            Entry::ModelChange { .. } => "model_change",
            Entry::ThinkingLevel { .. } => "thinking_level",
            Entry::ServiceTier { .. } => "service_tier",
            Entry::Compaction { .. } => "compaction",
            Entry::BranchSummary { .. } => "branch_summary",
            Entry::Custom { .. } => "custom",
            Entry::ChildUsage { .. } => "child_usage",
            Entry::Label { .. } => "label",
            Entry::Info { .. } => "info",
            Entry::State { .. } => "state",
            Entry::Status { .. } => "status",
            Entry::GitState { .. } => "git_state",
        }
    }

    pub fn message_text(&self) -> Option<&str> {
        match self {
            Entry::Message { text, .. } => Some(text),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub seq: u64,
    pub ts: i64,
    #[serde(flatten)]
    pub entry: Entry,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SessionMeta {
    pub schema: u32,
    pub generation: u64,
    pub created_ts: i64,
    pub name: String,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub parent: Option<String>,
}

pub fn meta_path(log: &Path) -> PathBuf {
    log.with_extension("meta.json")
}

pub fn index_path(log: &Path) -> PathBuf {
    log.with_extension("idx")
}

pub fn read_meta(log: &Path) -> Result<SessionMeta> {
    let text = std::fs::read_to_string(meta_path(log))?;
    Ok(serde_json::from_str(&text)?)
}

pub fn write_meta(log: &Path, meta: &SessionMeta) -> Result<()> {
    let path = meta_path(log);
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(meta)?)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Append-only session log with fsync per record and monotonic seq assignment.
pub struct SessionLog {
    path: PathBuf,
    writer: JsonlWriter,
    next_seq: u64,
    meta: SessionMeta,
}

impl SessionLog {
    pub fn create(path: impl AsRef<Path>, meta: SessionMeta) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        repair_raw(&path)?;
        let writer = JsonlWriter::open(&path)?;
        write_meta(&path, &meta)?;
        Ok(Self { path, writer, next_seq: 0, meta })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Err(ZeroError::new(
                ErrorCode::SessionNotFound,
                format!("session log {} does not exist", path.display()),
            ));
        }
        repair_raw(&path)?;
        let (records, _) = scan_raw::<Record>(&path)?;
        let next_seq = records.last().map(|r| r.seq + 1).unwrap_or(0);
        let meta = read_meta(&path).unwrap_or_else(|_| SessionMeta {
            schema: ENTRY_SCHEMA_VERSION,
            generation: 1,
            created_ts: 0,
            name: path.file_stem().and_then(|s| s.to_str()).unwrap_or("session").to_string(),
            project: None,
            parent: None,
        });
        let writer = JsonlWriter::open(&path)?;
        Ok(Self { path, writer, next_seq, meta })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn meta(&self) -> &SessionMeta {
        &self.meta
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    pub fn append(&mut self, ts: i64, entry: Entry) -> Result<Record> {
        let record = Record { seq: self.next_seq, ts, entry };
        self.writer.append(&record)?;
        self.next_seq += 1;
        Ok(record)
    }

    pub fn bump_generation(&mut self) -> Result<u64> {
        self.meta.generation += 1;
        write_meta(&self.path, &self.meta)?;
        Ok(self.meta.generation)
    }

    /// Read the whole log. Used by export and compaction; attach uses the index.
    pub fn records(&self) -> Result<Vec<Record>> {
        let (records, _) = scan_raw::<Record>(&self.path)?;
        Ok(records)
    }

    /// The entries "visible" after the last compaction: the compaction marker,
    /// anything after it, plus retained kernel/state/status entries.
    pub fn visible_records(&self) -> Result<Vec<Record>> {
        let records = self.records()?;
        Ok(visible_slice(&records))
    }
}

pub fn visible_slice(records: &[Record]) -> Vec<Record> {
    let last_compaction = records
        .iter()
        .rposition(|r| matches!(r.entry, Entry::Compaction { .. }));
    let Some(idx) = last_compaction else {
        return records.to_vec();
    };
    let keep_from = match &records[idx].entry {
        Entry::Compaction { keep_from_seq, .. } => *keep_from_seq,
        _ => unreachable!(),
    };
    records
        .iter()
        .filter(|r| r.seq >= keep_from || matches!(r.entry, Entry::State { .. } | Entry::Status { .. }))
        .cloned()
        .collect()
}

/// Cursor: a generation plus a sequence within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    pub generation: u64,
    pub sequence: u64,
}

impl Cursor {
    pub fn new(generation: u64, sequence: u64) -> Self {
        Self { generation, sequence }
    }

    pub fn is_stale(&self, current_generation: u64) -> bool {
        self.generation != current_generation
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttachStats {
    pub index_rebuilt: bool,
    pub index_bytes_read: u64,
    pub tail_bytes_read: u64,
    pub records_returned: usize,
    pub total_records: u64,
    pub bytes_scanned_for_index: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AttachSnapshot {
    pub cursor: Cursor,
    pub entries: Vec<Record>,
    pub stats: AttachStats,
    /// Bytes still to stream after the snapshot when the client wants history.
    pub history_bytes: u64,
}

const INDEX_MAGIC: &[u8; 8] = b"ZIDX0001";

fn build_index(log: &Path, index: &Path) -> Result<AttachStats> {
    let file = File::open(log)?;
    let source_len = file.metadata()?.len();
    let tmp = index.with_extension("tmp");
    let mut out = std::io::BufWriter::new(File::create(&tmp)?);
    out.write_all(INDEX_MAGIC)?;
    out.write_all(&source_len.to_le_bytes())?;
    // Count placeholder, patched at the end.
    out.write_all(&0u64.to_le_bytes())?;
    let mut reader = BufReader::with_capacity(256 * 1024, file);
    let mut offset = 0u64;
    let mut count = 0u64;
    let mut line = Vec::with_capacity(256);
    loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        if line.last() != Some(&b'\n') {
            // Torn tail.
            break;
        }
        out.write_all(&offset.to_le_bytes())?;
        offset += n as u64;
        count += 1;
    }
    out.write_all(&count.to_le_bytes())?;
    out.flush()?;
    out.get_ref().sync_all()?;
    drop(out);
    std::fs::rename(&tmp, index)?;
    Ok(AttachStats {
        index_rebuilt: true,
        index_bytes_read: 0,
        tail_bytes_read: 0,
        records_returned: 0,
        total_records: count,
        bytes_scanned_for_index: source_len,
    })
}

pub fn ensure_index(log: &Path, index: &Path) -> Result<(u64, bool)> {
    let source_len = std::fs::metadata(log)?.len();
    if let Ok(mut f) = File::open(index) {
        let mut magic = [0u8; 8];
        if f.read_exact(&mut magic).is_ok() && &magic == INDEX_MAGIC {
            let mut len = [0u8; 8];
            if f.read_exact(&mut len).is_ok() {
                let recorded = u64::from_le_bytes(len);
                let mut trailer = Vec::new();
                f.seek(SeekFrom::End(-8))?;
                f.read_to_end(&mut trailer)?;
                let count = u64::from_le_bytes(trailer[..8].try_into().expect("8 bytes"));
                if recorded == source_len {
                    return Ok((count, false));
                }
            }
        }
    }
    let stats = build_index(log, index)?;
    Ok((stats.total_records, true))
}

/// Attach without loading history: the index is streamed once (if stale), then
/// only the last `max_entries` records are read from the log.
pub fn attach(
    log: impl AsRef<Path>,
    index: impl AsRef<Path>,
    max_entries: usize,
) -> Result<AttachSnapshot> {
    let log = log.as_ref();
    let index = index.as_ref();
    let source_len = std::fs::metadata(log)?.len();
    let (count, rebuilt) = ensure_index(log, index)?;
    let mut stats = AttachStats {
        index_rebuilt: rebuilt,
        total_records: count,
        bytes_scanned_for_index: if rebuilt { source_len } else { 0 },
        ..AttachStats::default()
    };

    let take = (max_entries as u64).min(count) as usize;
    let mut offsets = Vec::with_capacity(take);
    if take > 0 {
        let mut idx = File::open(index)?;
        let start = 8 + 8 + 8 + (count - take as u64) * 8;
        idx.seek(SeekFrom::Start(start))?;
        let mut raw = vec![0u8; take * 8];
        idx.read_exact(&mut raw)?;
        stats.index_bytes_read = raw.len() as u64;
        for chunk in raw.chunks(8) {
            offsets.push(u64::from_le_bytes(chunk.try_into().expect("8 bytes")));
        }
    }

    let meta = read_meta(log).unwrap_or_default();
    let mut entries = Vec::with_capacity(take);
    let mut data = File::open(log)?;
    let mut tail_bytes = 0u64;
    let mut history_bytes = 0u64;
    for (i, offset) in offsets.iter().enumerate() {
        data.seek(SeekFrom::Start(*offset))?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            let n = data.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            tail_bytes += n as u64;
            if let Some(pos) = chunk[..n].iter().position(|b| *b == b'\n') {
                buf.extend_from_slice(&chunk[..pos]);
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let record: Record = serde_json::from_slice(&buf)?;
        entries.push(record);
        // Bytes before the first returned record are history the client may stream.
        if i == 0 {
            history_bytes = *offset;
        }
    }
    stats.tail_bytes_read = tail_bytes;
    stats.records_returned = entries.len();
    let sequence = entries.last().map(|r| r.seq + 1).unwrap_or(0);
    Ok(AttachSnapshot {
        cursor: Cursor::new(meta.generation.max(1), sequence),
        entries,
        stats,
        history_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_kinds() -> Vec<Entry> {
        vec![
            Entry::Message {
                role: Role::User,
                text: "hello".into(),
                tool_calls: vec![ToolCall {
                    id: "call-1".into(),
                    name: "echo".into(),
                    arguments: serde_json::json!({"x": 1}),
                }],
                tool_call_id: None,
            },
            Entry::ModelChange { provider: "openai".into(), model: "gpt".into() },
            Entry::ThinkingLevel { level: "high".into() },
            Entry::ServiceTier { tier: "priority".into() },
            Entry::Compaction { summary: "short".into(), keep_from_seq: 3, removed_entries: 2 },
            Entry::BranchSummary {
                summary: BranchSummary {
                    goal: "ship".into(),
                    constraints: vec!["no network".into()],
                    progress: vec!["wrote log".into()],
                    decisions: vec!["append-only".into()],
                    next_steps: vec!["compact".into()],
                    critical_context: vec!["seq is the order".into()],
                    files: BTreeMap::from([(
                        "a.rs".into(),
                        FileTouch { path: "a.rs".into(), edits: 2, last_seq: 9 },
                    )]),
                },
            },
            Entry::Custom { name: "artifact".into(), data: serde_json::json!({"id":"b1"}) },
            Entry::ChildUsage { child: "child-1".into(), input_tokens: 10, output_tokens: 20, cost_micros: 30 },
            Entry::Label { name: "checkpoint".into() },
            Entry::Info { text: "note".into() },
            Entry::State { key: "kernel.var.x".into(), value: serde_json::json!(5) },
            Entry::Status { state: "running".into() },
            Entry::GitState { branch: Some("main".into()), commit: Some("abc".into()), dirty: true },
        ]
    }

    #[test]
    fn round_trip_covers_every_entry_kind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.jsonl");
        let mut log = SessionLog::create(
            &path,
            SessionMeta { schema: ENTRY_SCHEMA_VERSION, generation: 1, created_ts: 0, name: "t".into(), project: None, parent: None },
        )
        .unwrap();
        for entry in all_kinds() {
            log.append(1_700_000_000_000, entry).unwrap();
        }
        let records = log.records().unwrap();
        assert_eq!(records.len(), all_kinds().len());
        for (record, entry) in records.iter().zip(all_kinds()) {
            assert_eq!(record.entry, entry, "kind {}", entry.kind());
        }
        // The tag is stable on the wire.
        let first: serde_json::Value = serde_json::from_str(
            std::fs::read_to_string(&path).unwrap().lines().next().unwrap(),
        )
        .unwrap();
        assert_eq!(first["kind"], "message");
        assert_eq!(first["role"], "user");
        // Every kind has a distinct name.
        let kinds: std::collections::BTreeSet<&str> = all_kinds().iter().map(|e| e.kind()).collect();
        assert_eq!(kinds.len(), 13);
    }

    #[test]
    fn visible_slice_keeps_the_tail_and_kernel_state() {
        let mut records = Vec::new();
        for i in 0..10 {
            records.push(Record {
                seq: i,
                ts: i as i64,
                entry: Entry::Message { role: Role::User, text: format!("m{i}"), tool_calls: vec![], tool_call_id: None },
            });
        }
        records.push(Record { seq: 10, ts: 10, entry: Entry::State { key: "kernel.x".into(), value: serde_json::json!(1) } });
        records.push(Record { seq: 11, ts: 11, entry: Entry::Compaction { summary: "s".into(), keep_from_seq: 8, removed_entries: 8 } });
        let visible = visible_slice(&records);
        let texts: Vec<String> = visible.iter().filter_map(|r| r.entry.message_text().map(str::to_string)).collect();
        assert_eq!(texts, vec!["m8", "m9"]);
        assert!(visible.iter().any(|r| matches!(&r.entry, Entry::State { .. })));
        assert!(visible.iter().any(|r| matches!(r.entry, Entry::Compaction { .. })));
    }

    #[test]
    fn branch_summary_shape_is_enforced() {
        let good = serde_json::json!({
            "goal":"g","constraints":[],"progress":[],"decisions":[],
            "next_steps":[],"critical_context":[],"files":{}
        });
        let summary = BranchSummary::parse_strict(&good.to_string()).unwrap();
        assert_eq!(summary.goal, "g");
        assert!(summary.render().contains("GOAL: g"));
        let bad = serde_json::json!({"goal":"g"});
        let err = BranchSummary::parse_strict(&bad.to_string()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::SummaryInvalid);
        let empty = serde_json::json!({
            "goal":"  ","constraints":[],"progress":[],"decisions":[],
            "next_steps":[],"critical_context":[],"files":{}
        });
        assert_eq!(BranchSummary::parse_strict(&empty.to_string()).unwrap_err().code(), ErrorCode::SummaryInvalid);
    }
}
