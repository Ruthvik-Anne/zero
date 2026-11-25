//! Copy-on-write overlays with a three-way line merge (FS-05, FS-08).
//!
//! Each agent works in a scratch layer over a shared base. Merging compares both
//! layers against the base: non-overlapping changes combine, and overlapping ones
//! produce a precise conflict with the file and line. Nothing is silently
//! overwritten.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use zero_types::error::Result;

#[derive(Debug, Clone)]
pub struct Overlay {
    base: PathBuf,
    scratch: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conflict {
    pub path: PathBuf,
    pub line: Option<usize>,
    pub message: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeReport {
    pub merged: Vec<PathBuf>,
    pub unchanged: Vec<PathBuf>,
    pub conflicts: Vec<Conflict>,
}

impl Overlay {
    pub fn open(base: impl AsRef<Path>, scratch: impl AsRef<Path>) -> Result<Self> {
        std::fs::create_dir_all(scratch.as_ref())?;
        Ok(Self { base: base.as_ref().to_path_buf(), scratch: scratch.as_ref().to_path_buf() })
    }

    pub fn base(&self) -> &Path {
        &self.base
    }

    pub fn scratch(&self) -> &Path {
        &self.scratch
    }

    fn scratch_path(&self, rel: &Path) -> PathBuf {
        self.scratch.join(rel)
    }

    pub fn write(&self, rel: impl AsRef<Path>, bytes: &[u8]) -> Result<()> {
        let path = self.scratch_path(rel.as_ref());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, bytes)?;
        Ok(())
    }

    pub fn read(&self, rel: impl AsRef<Path>) -> Result<Vec<u8>> {
        let rel = rel.as_ref();
        let scratch = self.scratch_path(rel);
        if scratch.exists() {
            return Ok(std::fs::read(scratch)?);
        }
        Ok(std::fs::read(self.base.join(rel))?)
    }

    pub fn base_bytes(&self, rel: impl AsRef<Path>) -> Option<Vec<u8>> {
        std::fs::read(self.base.join(rel.as_ref())).ok()
    }

    pub fn changed_paths(&self) -> Result<BTreeSet<PathBuf>> {
        let mut out = BTreeSet::new();
        collect(&self.scratch, &self.scratch, &mut out)?;
        Ok(out)
    }

    /// Three-way merge `theirs` into `ours`. Conflicts are reported, not applied.
    pub fn merge(ours: &Overlay, theirs: &Overlay) -> Result<MergeReport> {
        let mut paths = ours.changed_paths()?;
        paths.extend(theirs.changed_paths()?);
        let mut report = MergeReport::default();
        for rel in paths {
            let base = ours.base_bytes(&rel);
            let mine = read_layer(ours, &rel, base.as_deref())?;
            let other = read_layer(theirs, &rel, base.as_deref())?;
            if mine == other {
                report.unchanged.push(rel);
                continue;
            }
            match &base {
                None => {
                    let mine_created = ours.scratch_path(&rel).exists();
                    let other_created = theirs.scratch_path(&rel).exists();
                    match (mine_created, other_created) {
                        (true, true) if mine != other => report.conflicts.push(Conflict {
                            path: rel.clone(),
                            line: None,
                            message: "both layers created the file with different content".into(),
                        }),
                        (false, true) => {
                            ours.write(&rel, &other)?;
                            report.merged.push(rel);
                        }
                        _ => report.merged.push(rel),
                    }
                }
                Some(base) => {
                    if &mine == base {
                        ours.write(&rel, &other)?;
                        report.merged.push(rel);
                    } else if &other == base {
                        report.merged.push(rel);
                    } else {
                        match merge_lines(base, &mine, &other) {
                            Ok(merged) => {
                                ours.write(&rel, &merged)?;
                                report.merged.push(rel);
                            }
                            Err(line) => report.conflicts.push(Conflict {
                                path: rel.clone(),
                                line: Some(line),
                                message: format!("both layers changed line {line}"),
                            }),
                        }
                    }
                }
            }
        }
        Ok(report)
    }
}

fn read_layer(overlay: &Overlay, rel: &Path, base: Option<&[u8]>) -> Result<Vec<u8>> {
    let scratch = overlay.scratch_path(rel);
    if scratch.exists() {
        return Ok(std::fs::read(scratch)?);
    }
    Ok(base.unwrap_or(&[]).to_vec())
}

fn collect(root: &Path, dir: &Path, out: &mut BTreeSet<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect(root, &path, out)?;
        } else {
            if let Ok(rel) = path.strip_prefix(root) {
                out.insert(rel.to_path_buf());
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Change {
    start: usize,
    end: usize,
    lines: Vec<String>,
}

fn split_lines(bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    if text.is_empty() {
        return Vec::new();
    }
    text.split_inclusive('\n').map(str::to_string).collect()
}

/// Line diff (LCS). Returns changed ranges in ascending order.
fn changes(base: &[String], other: &[String]) -> Vec<Change> {
    if other.is_empty() && !base.is_empty() {
        return vec![Change { start: 0, end: base.len(), lines: Vec::new() }];
    }
    let n = base.len();
    let m = other.len();
    if n > 4000 || m > 4000 {
        // Too large to diff cheaply; treat the whole file as one change.
        return if base == other {
            Vec::new()
        } else {
            vec![Change { start: 0, end: n, lines: other.to_vec() }]
        };
    }
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if base[i] == other[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n || j < m {
        if i < n && j < m && base[i] == other[j] {
            i += 1;
            j += 1;
            continue;
        }
        let start = i;
        let start_other = j;
        loop {
            let take_base = if i >= n {
                false
            } else if j >= m {
                true
            } else {
                lcs[i + 1][j] >= lcs[i][j + 1]
            };
            if take_base {
                i += 1;
            } else {
                j += 1;
            }
            let synced = i < n && j < m && base[i] == other[j];
            if synced || (i >= n && j >= m) {
                break;
            }
        }
        out.push(Change { start, end: i, lines: other[start_other..j].to_vec() });
    }
    out
}

/// Merge two change sets. Returns the merged text, or the 1-based line of the
/// first overlap.
fn merge_lines(base: &[u8], ours: &[u8], theirs: &[u8]) -> std::result::Result<Vec<u8>, usize> {
    let base_lines = split_lines(base);
    let our_changes = changes(&base_lines, &split_lines(ours));
    let their_changes = changes(&base_lines, &split_lines(theirs));

    for a in &our_changes {
        for b in &their_changes {
            let overlap = if a.start == a.end && b.start == b.end {
                a.start == b.start && a.lines != b.lines
            } else if a.start == a.end {
                a.start >= b.start && a.start < b.end
            } else if b.start == b.end {
                b.start >= a.start && b.start < a.end
            } else {
                a.start < b.end && b.start < a.end
            };
            if overlap {
                return Err(a.start.min(b.start) + 1);
            }
        }
    }

    let mut all = our_changes;
    all.extend(their_changes);
    all.sort_by_key(|change| std::cmp::Reverse(change.start));
    let mut merged = base_lines;
    for change in all {
        merged.splice(change.start..change.end, change.lines);
    }
    Ok(merged.join("").into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overlay(root: &Path, name: &str) -> Overlay {
        Overlay::open(root.join("base"), root.join(name)).unwrap()
    }

    #[test]
    fn two_agents_merge_disjoint_edits() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("base")).unwrap();
        std::fs::write(dir.path().join("base/logic.rs"), b"fn a() {}\nfn b() {}\nfn c() {}\n").unwrap();
        let ours = overlay(dir.path(), "ours");
        let theirs = overlay(dir.path(), "theirs");
        ours.write("logic.rs", b"fn a() { /* ours */ }\nfn b() {}\nfn c() {}\n").unwrap();
        theirs.write("logic.rs", b"fn a() {}\nfn b() {}\nfn c() { /* theirs */ }\n").unwrap();

        let report = Overlay::merge(&ours, &theirs).unwrap();
        assert!(report.conflicts.is_empty(), "{report:?}");
        let merged = String::from_utf8(ours.read("logic.rs").unwrap()).unwrap();
        assert!(merged.contains("/* ours */"));
        assert!(merged.contains("/* theirs */"));
    }

    #[test]
    fn the_same_line_conflicts_with_a_precise_line() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("base")).unwrap();
        std::fs::write(dir.path().join("base/a.txt"), b"one\ntwo\nthree\n").unwrap();
        let ours = overlay(dir.path(), "ours");
        let theirs = overlay(dir.path(), "theirs");
        ours.write("a.txt", b"one\nours\nthree\n").unwrap();
        theirs.write("a.txt", b"one\ntheirs\nthree\n").unwrap();

        let report = Overlay::merge(&ours, &theirs).unwrap();
        assert_eq!(report.conflicts.len(), 1);
        assert_eq!(report.conflicts[0].line, Some(2));
        assert_eq!(report.conflicts[0].path, PathBuf::from("a.txt"));
        // Nothing was written on conflict.
        assert_eq!(ours.read("a.txt").unwrap(), b"one\nours\nthree\n");
    }

    #[test]
    fn creating_different_files_in_each_layer_merges_both() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("base")).unwrap();
        let ours = overlay(dir.path(), "ours");
        let theirs = overlay(dir.path(), "theirs");
        ours.write("new-a.txt", b"a").unwrap();
        theirs.write("new-b.txt", b"b").unwrap();
        let report = Overlay::merge(&ours, &theirs).unwrap();
        assert!(report.conflicts.is_empty());
        assert!(ours.read("new-a.txt").is_ok());
        assert!(ours.read("new-b.txt").is_ok());
    }

    #[test]
    fn a_one_sided_change_is_taken_and_a_creation_collision_conflicts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("base")).unwrap();
        std::fs::write(dir.path().join("base/a.txt"), b"base\n").unwrap();
        let ours = overlay(dir.path(), "ours");
        let theirs = overlay(dir.path(), "theirs");
        theirs.write("a.txt", b"base changed\n").unwrap();
        let report = Overlay::merge(&ours, &theirs).unwrap();
        assert!(report.conflicts.is_empty());
        assert_eq!(ours.read("a.txt").unwrap(), b"base changed\n");

        ours.write("same.txt", b"ours").unwrap();
        theirs.write("same.txt", b"theirs").unwrap();
        let report = Overlay::merge(&ours, &theirs).unwrap();
        assert_eq!(report.conflicts.len(), 1);
        assert!(report.conflicts[0].message.contains("created"));
    }
}
