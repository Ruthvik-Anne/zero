//! Edit operations, anchors, receipts, journal/undo, and the no-delete rule
//! (EDT-01..EDT-04, EDT-06).
//!
//! Anchors are exact text or a line range pinned by a content hash. A drifted
//! anchor is refused rather than editing the wrong text. Receipts never echo a
//! file body and bound failure context to three lines.

use crate::overwrite_journal::OverwriteJournal;
use crate::trash::TrashService;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Anchor {
    /// Inclusive occurrence (0-based) of exact text.
    Text { exact: String, occurrence: usize },
    /// 1-based line range pinned by the hash of those bytes.
    Lines { start: usize, count: usize, hash: String },
}

impl Anchor {
    pub fn text(exact: impl Into<String>) -> Self {
        Anchor::Text { exact: exact.into(), occurrence: 0 }
    }

    pub fn lines(text: &str, start: usize, count: usize) -> Self {
        let range = line_range(text, start, count).unwrap_or(0..0);
        Anchor::Lines { start, count, hash: blake3::hash(text[range].as_bytes()).to_hex().to_string() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditOp {
    Replace { anchor: Anchor, text: String },
    Insert { anchor: Anchor, text: String },
    Delete { anchor: Anchor },
    Wrap { anchor: Anchor, prefix: String, suffix: String },
    MoveLines { start: usize, count: usize, to: usize },
    CopyLines { start: usize, count: usize, to: usize },
    Rename { to: PathBuf },
    Write { content: String },
    Patch { patch: String },
    /// EDT-06: editing never deletes a file.
    DeleteFile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSummary {
    pub path: PathBuf,
    pub before_lines: u64,
    pub after_lines: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptError {
    pub code: String,
    pub message: String,
    /// At most three lines; never a file body.
    pub context: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EditReceipt {
    pub ok: bool,
    pub files: Vec<FileSummary>,
    pub first_error: Option<ReceiptError>,
}

impl EditReceipt {
    pub fn summary(&self) -> String {
        format!(
            "ok={} files={} first_error={}",
            self.ok,
            self.files.len(),
            self.first_error.as_ref().map(|e| e.code.as_str()).unwrap_or("-")
        )
    }
}

fn line_starts(text: &str) -> Vec<usize> {
    let mut starts = vec![0];
    for (i, b) in text.bytes().enumerate() {
        if b == b'\n' {
            starts.push(i + 1);
        }
    }
    starts
}

fn line_range(text: &str, start: usize, count: usize) -> Option<std::ops::Range<usize>> {
    if start == 0 || count == 0 {
        return None;
    }
    let starts = line_starts(text);
    let begin = *starts.get(start - 1)?;
    let end = if start - 1 + count < starts.len() {
        starts[start - 1 + count]
    } else {
        text.len()
    };
    Some(begin..end)
}

fn resolve(anchor: &Anchor, text: &str) -> Result<std::ops::Range<usize>> {
    match anchor {
        Anchor::Text { exact, occurrence } => {
            let mut from = 0;
            for i in 0..=*occurrence {
                let Some(pos) = text[from..].find(exact) else {
                    return Err(ZeroError::new(
                        ErrorCode::AnchorDrift,
                        format!("anchor text not found (occurrence {i}): {}", preview(exact)),
                    ));
                };
                let start = from + pos;
                if i == *occurrence {
                    return Ok(start..start + exact.len());
                }
                from = start + exact.len();
            }
            unreachable!()
        }
        Anchor::Lines { start, count, hash } => {
            let range = line_range(text, *start, *count).ok_or_else(|| {
                ZeroError::new(ErrorCode::AnchorDrift, format!("line range {start}+{count} is out of bounds"))
            })?;
            let actual = blake3::hash(text[range.clone()].as_bytes()).to_hex().to_string();
            if &actual != hash {
                return Err(ZeroError::new(
                    ErrorCode::AnchorDrift,
                    format!("line range {start}+{count} changed since the anchor was taken"),
                ));
            }
            Ok(range)
        }
    }
}

fn preview(text: &str) -> String {
    let text = text.lines().next().unwrap_or("");
    if text.len() > 60 {
        format!("{}…", &text[..60])
    } else {
        text.to_string()
    }
}

/// Apply text operations. Rename/DeleteFile are refused here (file operations).
pub fn apply_to_text(text: &str, ops: &[EditOp]) -> Result<(String, EditReceipt)> {
    let before_lines = crate::manager::line_count(text.as_bytes());
    let mut current = text.to_string();
    for (index, op) in ops.iter().enumerate() {
        let result: Result<()> = (|| {
            match op {
                EditOp::Replace { anchor, text: replacement } => {
                    let range = resolve(anchor, &current)?;
                    current.replace_range(range, replacement);
                }
                EditOp::Insert { anchor, text: inserted } => {
                    let range = resolve(anchor, &current)?;
                    current.insert_str(range.start, inserted);
                }
                EditOp::Delete { anchor } => {
                    let range = resolve(anchor, &current)?;
                    current.replace_range(range, "");
                }
                EditOp::Wrap { anchor, prefix, suffix } => {
                    let range = resolve(anchor, &current)?;
                    current.insert_str(range.end, suffix);
                    current.insert_str(range.start, prefix);
                }
                EditOp::MoveLines { start, count, to } => {
                    let range = line_range(&current, *start, *count)
                        .ok_or_else(|| ZeroError::new(ErrorCode::AnchorDrift, "move range is out of bounds"))?;
                    let block: String = current.drain(range).collect();
                    let target = line_range(&current, (*to).min(line_count(&current)), 1)
                        .map(|r| r.start)
                        .unwrap_or(current.len());
                    current.insert_str(target, &block);
                }
                EditOp::CopyLines { start, count, to } => {
                    let range = line_range(&current, *start, *count)
                        .ok_or_else(|| ZeroError::new(ErrorCode::AnchorDrift, "copy range is out of bounds"))?;
                    let block: String = current[range].to_string();
                    let target = line_range(&current, (*to).min(line_count(&current)), 1)
                        .map(|r| r.start)
                        .unwrap_or(current.len());
                    current.insert_str(target, &block);
                }
                EditOp::Write { content } => {
                    current = content.clone();
                }
                EditOp::Patch { patch } => {
                    current = apply_patch(&current, patch)?;
                }
                EditOp::Rename { .. } => {
                    return Err(ZeroError::new(ErrorCode::InvalidInput, "rename is a file operation"));
                }
                EditOp::DeleteFile => {
                    return Err(ZeroError::new(
                        ErrorCode::DeletionBlocked,
                        "editing never deletes a file; use the `trash` tool",
                    ));
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            return Ok((
                text.to_string(),
                EditReceipt {
                    ok: false,
                    files: Vec::new(),
                    first_error: Some(ReceiptError {
                        code: error.code().as_str().into(),
                        message: preview(error.message()),
                        context: vec![format!("operation {index}: {}", op_name(op))],
                    }),
                },
            ));
        }
    }
    let after_lines = crate::manager::line_count(current.as_bytes());
    let receipt = EditReceipt {
        ok: true,
        files: vec![FileSummary {
            path: PathBuf::from("<memory>"),
            before_lines,
            after_lines,
            bytes: current.len() as u64,
        }],
        first_error: None,
    };
    Ok((current, receipt))
}

fn op_name(op: &EditOp) -> &'static str {
    match op {
        EditOp::Replace { .. } => "replace",
        EditOp::Insert { .. } => "insert",
        EditOp::Delete { .. } => "delete",
        EditOp::Wrap { .. } => "wrap",
        EditOp::MoveLines { .. } => "move",
        EditOp::CopyLines { .. } => "copy",
        EditOp::Rename { .. } => "rename",
        EditOp::Write { .. } => "write",
        EditOp::Patch { .. } => "patch",
        EditOp::DeleteFile => "delete_file",
    }
}

fn line_count(text: &str) -> usize {
    if text.is_empty() {
        0
    } else if text.ends_with('\n') {
        text.bytes().filter(|b| *b == b'\n').count()
    } else {
        text.bytes().filter(|b| *b == b'\n').count() + 1
    }
}

fn apply_patch(base: &str, patch: &str) -> Result<String> {
    let mut lines: Vec<String> = base.split_inclusive('\n').map(str::to_string).collect();
    let mut hunks: Vec<(usize, Vec<String>)> = Vec::new();
    let mut current: Option<(usize, Vec<String>)> = None;
    for raw in patch.lines() {
        if raw.starts_with("@@") {
            if let Some(hunk) = current.take() {
                hunks.push(hunk);
            }
            // @@ -start,count +start,count @@
            let start = raw
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.trim_start_matches('-').split(',').next())
                .and_then(|s| s.parse::<usize>().ok())
                .ok_or_else(|| ZeroError::new(ErrorCode::InvalidInput, "patch hunk has no base line"))?;
            current = Some((start.saturating_sub(1), Vec::new()));
            continue;
        }
        let Some((_, out)) = current.as_mut() else {
            continue;
        };
        if let Some(rest) = raw.strip_prefix('+') {
            out.push(rest.to_string() + "\n");
        } else if let Some(rest) = raw.strip_prefix('-') {
            let _ = rest;
        } else if let Some(rest) = raw.strip_prefix(' ') {
            out.push(rest.to_string() + "\n");
        }
    }
    if let Some(hunk) = current.take() {
        hunks.push(hunk);
    }
    if hunks.is_empty() {
        return Err(ZeroError::new(ErrorCode::InvalidInput, "patch contains no hunks"));
    }
    for (start, replacement) in hunks.into_iter().rev() {
        let removes = patch
            .lines()
            .skip_while(|l| !l.starts_with("@@"))
            .filter(|l| l.starts_with('-'))
            .count();
        let end = (start + removes.max(1)).min(lines.len());
        lines.splice(start..end, replacement);
    }
    Ok(lines.join(""))
}

/// File-level edits: snapshot, apply text ops, rename, or write. Delete is
/// refused.
pub struct EditSession {
    journal: OverwriteJournal,
    trash: TrashService,
    batches: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BatchManifest {
    id: String,
    entries: Vec<ManifestEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ManifestEntry {
    path: PathBuf,
    snapshot: Option<String>,
}

impl EditSession {
    pub fn open(journal_root: impl AsRef<Path>, trash: TrashService) -> Result<Self> {
        let root = journal_root.as_ref().to_path_buf();
        let batches = root.join("batches");
        std::fs::create_dir_all(&batches)?;
        Ok(Self { journal: OverwriteJournal::open(root.join("files"))?, trash, batches })
    }

    /// Apply edits to one or more files as a reversible batch.
    pub fn apply(&mut self, files: &[(PathBuf, Vec<EditOp>)], now_ms: i64) -> Result<(String, EditReceipt)> {
        let id = format!("edit-{now_ms}");
        let mut entries = Vec::new();
        for (path, _) in files {
            if path.is_dir() {
                return Err(ZeroError::new(ErrorCode::InvalidInput, format!("{} is a directory", path.display())));
            }
            let snapshot = self.journal.snapshot(path, now_ms)?.map(|s| s.id);
            entries.push(ManifestEntry { path: path.clone(), snapshot });
        }
        let manifest = BatchManifest { id: id.clone(), entries };
        self.write_manifest(&manifest)?;

        let mut summaries = Vec::new();
        for (path, ops) in files {
            let before = std::fs::read(path).unwrap_or_default();
            let text = String::from_utf8_lossy(&before).to_string();
            let text_ops: Vec<EditOp> = ops.iter().filter(|op| !matches!(op, EditOp::Rename { .. })).cloned().collect();
            let rename = ops.iter().find_map(|op| match op {
                EditOp::Rename { to } => Some(to.clone()),
                _ => None,
            });
            match apply_to_text(&text, &text_ops) {
                Ok((output, _)) => {
                    write_atomic(path, output.as_bytes())?;
                    let final_path = match &rename {
                        Some(to) => {
                            let target = if to.is_absolute() {
                                to.clone()
                            } else {
                                path.parent().unwrap_or_else(|| Path::new(".")).join(to)
                            };
                            if let Some(parent) = target.parent() {
                                std::fs::create_dir_all(parent)?;
                            }
                            std::fs::rename(path, &target)?;
                            target
                        }
                        None => path.clone(),
                    };
                    summaries.push(FileSummary {
                        path: final_path,
                        before_lines: crate::manager::line_count(&before),
                        after_lines: crate::manager::line_count(output.as_bytes()),
                        bytes: output.len() as u64,
                    });
                }
                Err(error) => {
                    self.undo(&id)?;
                    return Ok((
                        id,
                        EditReceipt {
                            ok: false,
                            files: Vec::new(),
                            first_error: Some(ReceiptError {
                                code: error.code().as_str().into(),
                                message: preview(error.message()),
                                context: vec![format!("file: {}", path.display())],
                            }),
                        },
                    ));
                }
            }
        }
        Ok((id, EditReceipt { ok: true, files: summaries, first_error: None }))
    }

    fn write_manifest(&self, manifest: &BatchManifest) -> Result<()> {
        let path = self.batches.join(format!("{}.json", manifest.id));
        std::fs::write(&path, serde_json::to_vec_pretty(manifest)?)?;
        Ok(())
    }

    /// Restore every file in the batch byte-exactly; files created by the batch
    /// go to the trash.
    pub fn undo(&mut self, id: &str) -> Result<Vec<PathBuf>> {
        let path = self.batches.join(format!("{id}.json"));
        let manifest: BatchManifest = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
        let mut restored = Vec::new();
        for entry in &manifest.entries {
            match &entry.snapshot {
                Some(snapshot) => {
                    self.journal.undo(snapshot)?;
                    restored.push(entry.path.clone());
                }
                None => {
                    if entry.path.exists() {
                        let _ = self.trash.trash(&entry.path)?;
                    }
                    restored.push(entry.path.clone());
                }
            }
        }
        let _ = std::fs::remove_file(&path);
        Ok(restored)
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    crate::manager::atomic_write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_types::paths::Platform;
    use zero_types::protected::ProtectedPaths;

    #[test]
    fn every_text_operation_has_a_fixture() {
        let text = "alpha\nbeta\ngamma\n";
        let (out, receipt) = apply_to_text(
            text,
            &[EditOp::Replace { anchor: Anchor::text("beta"), text: "BETA".into() }],
        )
        .unwrap();
        assert!(receipt.ok);
        assert_eq!(out, "alpha\nBETA\ngamma\n");

        let (out, _) = apply_to_text(&out, &[EditOp::Insert { anchor: Anchor::text("gamma"), text: "inserted\n".into() }]).unwrap();
        assert!(out.contains("inserted\ngamma"));

        let (out, _) = apply_to_text(&out, &[EditOp::Delete { anchor: Anchor::text("inserted\n") }]).unwrap();
        assert!(!out.contains("inserted"));

        let (out, _) = apply_to_text(&out, &[EditOp::Wrap {
            anchor: Anchor::text("BETA"),
            prefix: "[".into(),
            suffix: "]".into(),
        }])
        .unwrap();
        assert!(out.contains("[BETA]"));

        let (out, _) = apply_to_text(&out, &[EditOp::MoveLines { start: 3, count: 1, to: 1 }]).unwrap();
        assert!(out.starts_with("gamma\n"), "{out:?}");

        let (out, _) = apply_to_text(&out, &[EditOp::CopyLines { start: 1, count: 1, to: 3 }]).unwrap();
        assert!(out.matches("gamma\n").count() >= 2);

        let (out, _) = apply_to_text(&out, &[EditOp::Write { content: "fresh\n".into() }]).unwrap();
        assert_eq!(out, "fresh\n");

        let patch = "@@ -1,1 +1,1 @@\n-old\n+fresh\n";
        let (out, _) = apply_to_text("old\n", &[EditOp::Patch { patch: patch.into() }]).unwrap();
        assert_eq!(out, "fresh\n");
    }

    #[test]
    fn a_drifted_anchor_refuses_instead_of_editing() {
        let text = "one\ntwo\nthree\n";
        let anchor = Anchor::lines(text, 2, 1);
        let changed = "one\nTWO\ntwo\nthree\n";
        let (out, receipt) = apply_to_text(changed, &[EditOp::Delete { anchor }]).unwrap();
        assert!(!receipt.ok);
        assert_eq!(receipt.first_error.as_ref().unwrap().code, ErrorCode::AnchorDrift.as_str());
        assert_eq!(out, changed, "nothing was edited");
    }

    #[test]
    fn receipts_are_bounded_and_never_echo_the_file() {
        let big = "secret-body\n".repeat(1000);
        let (_, receipt) = apply_to_text(&big, &[EditOp::Replace { anchor: Anchor::text("missing"), text: "x".into() }]).unwrap();
        assert!(!receipt.ok);
        let error = receipt.first_error.unwrap();
        assert!(error.context.len() <= 3);
        let json = serde_json::to_string(&error).unwrap();
        assert!(!json.contains("secret-body"));
        assert!(json.len() < 1024, "receipt is bounded: {} bytes", json.len());
    }

    #[test]
    fn deleting_files_is_refused_with_a_task_suggestion() {
        let (_, receipt) = apply_to_text("x", &[EditOp::DeleteFile]).unwrap();
        assert!(!receipt.ok);
        let error = receipt.first_error.unwrap();
        assert_eq!(error.code, ErrorCode::DeletionBlocked.as_str());
        assert!(error.message.contains("trash"));
    }

    fn session(dir: &Path) -> EditSession {
        let trash = TrashService::new(ProtectedPaths::new(
            dir,
            dir.join(".zero"),
            dir.join(".zero-config"),
            if cfg!(windows) { Platform::Windows } else { Platform::Linux },
        ));
        EditSession::open(dir.join("journal"), trash).unwrap()
    }

    #[test]
    fn a_fifty_file_batch_undoes_byte_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let mut session = session(dir.path());
        let mut files = Vec::new();
        for i in 0..50 {
            let path = dir.path().join(format!("file-{i}.txt"));
            std::fs::write(&path, format!("original {i}\n")).unwrap();
            files.push((
                path.clone(),
                vec![EditOp::Replace { anchor: Anchor::text(format!("original {i}")), text: format!("edited {i}") }],
            ));
        }
        let (id, receipt) = session.apply(&files, 1).unwrap();
        assert!(receipt.ok);
        assert_eq!(receipt.files.len(), 50);
        for (path, _) in &files {
            assert!(std::fs::read_to_string(path).unwrap().contains("edited"));
        }
        let restored = session.undo(&id).unwrap();
        assert_eq!(restored.len(), 50);
        for (i, (path, _)) in files.iter().enumerate() {
            assert_eq!(std::fs::read_to_string(path).unwrap(), format!("original {i}\n"));
        }
        // Undo removes the manifest so it cannot be replayed twice.
        assert!(session.undo(&id).is_err());
    }

    #[test]
    fn file_level_edits_write_and_rename() {
        let dir = tempfile::tempdir().unwrap();
        let mut session = session(dir.path());
        let path = dir.path().join("a.txt");
        std::fs::write(&path, "one\n").unwrap();
        let (_, receipt) = session
            .apply(&[(path.clone(), vec![EditOp::Write { content: "two\n".into() }])], 1)
            .unwrap();
        assert!(receipt.ok);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "two\n");

        let (_, receipt) = session
            .apply(&[(path.clone(), vec![EditOp::Rename { to: PathBuf::from("renamed.txt") }])], 2)
            .unwrap();
        assert!(receipt.ok);
        assert!(!path.exists());
        assert_eq!(std::fs::read_to_string(dir.path().join("renamed.txt")).unwrap(), "two\n");
    }
}
