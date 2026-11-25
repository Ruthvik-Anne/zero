//! Large-file range reads, a lazy line index, and O(edits) range edits
//! (EDT-05).
//!
//! Edits are recorded as byte-range splices and never read the surrounding file,
//! so a small change to a 1 GB file costs the edit, not the file. The line index
//! is built once by a streaming scan and reused.

use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone)]
pub struct LargeFile {
    path: PathBuf,
    len: u64,
}

impl LargeFile {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let len = std::fs::metadata(&path)?.len();
        Ok(Self { path, len })
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read only the requested range; the rest of the file is never touched.
    pub fn read_range(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        if offset > self.len {
            return Err(ZeroError::new(ErrorCode::InvalidInput, "range starts past the end of the file"));
        }
        let mut file = std::fs::File::open(&self.path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut out = vec![0u8; len.min((self.len - offset) as usize)];
        file.read_exact(&mut out)?;
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeEdit {
    pub offset: u64,
    pub delete: u64,
    pub insert: Vec<u8>,
}

pub struct RangeEditor {
    file: LargeFile,
    edits: Vec<RangeEdit>,
    line_offsets: Option<Vec<u64>>,
    /// Bytes read from the base file; range edits add nothing.
    pub bytes_read: u64,
}

impl RangeEditor {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self { file: LargeFile::open(path)?, edits: Vec::new(), line_offsets: None, bytes_read: 0 })
    }

    pub fn file(&self) -> &LargeFile {
        &self.file
    }

    pub fn edits(&self) -> &[RangeEdit] {
        &self.edits
    }

    /// Record a splice. Recording is O(1) and reads no bytes.
    pub fn edit(&mut self, offset: u64, delete: u64, insert: impl Into<Vec<u8>>) -> Result<()> {
        if offset > self.file.len() || offset + delete > self.file.len() {
            return Err(ZeroError::new(ErrorCode::InvalidInput, "edit range is outside the file"));
        }
        self.edits.push(RangeEdit { offset, delete, insert: insert.into() });
        Ok(())
    }

    /// Line start offsets, built once by a streaming scan (about 1 MiB buffers).
    pub fn line_offsets(&mut self) -> Result<&[u64]> {
        if self.line_offsets.is_none() {
            let mut offsets = vec![0u64];
            let mut file = std::fs::File::open(self.file.path())?;
            let mut buf = vec![0u8; 1024 * 1024];
            let mut position = 0u64;
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                self.bytes_read += n as u64;
                for (i, byte) in buf[..n].iter().enumerate() {
                    if *byte == b'\n' {
                        offsets.push(position + i as u64 + 1);
                    }
                }
                position += n as u64;
            }
            if offsets.last() == Some(&position) && position > 0 {
                offsets.pop();
            }
            self.line_offsets = Some(offsets);
        }
        Ok(self.line_offsets.as_deref().unwrap_or(&[]))
    }

    /// Materialise the edited file by streaming the base once and applying the
    /// splices in order.
    pub fn save(&self, out: impl AsRef<Path>) -> Result<u64> {
        let mut edits = self.edits.clone();
        edits.sort_by_key(|e| e.offset);
        for pair in edits.windows(2) {
            if pair[0].offset + pair[0].delete > pair[1].offset {
                return Err(ZeroError::new(ErrorCode::Conflict, "overlapping range edits"));
            }
        }
        let out = out.as_ref();
        let tmp = out.with_extension("zero-tmp");
        let mut source = std::fs::File::open(self.file.path())?;
        let mut dest = std::fs::File::create(&tmp)?;
        let mut cursor = 0u64;
        let mut written = 0u64;
        let mut buf = vec![0u8; 256 * 1024];
        for edit in &edits {
            copy_range(&mut source, &mut dest, cursor, edit.offset - cursor, &mut buf, &mut written)?;
            dest.write_all(&edit.insert)?;
            written += edit.insert.len() as u64;
            cursor = edit.offset + edit.delete;
        }
        copy_range(&mut source, &mut dest, cursor, self.file.len() - cursor, &mut buf, &mut written)?;
        dest.sync_all()?;
        drop(dest);
        std::fs::rename(&tmp, out)?;
        Ok(written)
    }
}

fn copy_range(
    source: &mut std::fs::File,
    dest: &mut std::fs::File,
    offset: u64,
    len: u64,
    buf: &mut [u8],
    written: &mut u64,
) -> Result<()> {
    if len == 0 {
        return Ok(());
    }
    source.seek(SeekFrom::Start(offset))?;
    let mut remaining = len;
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let n = source.read(&mut buf[..want])?;
        if n == 0 {
            return Err(ZeroError::new(ErrorCode::Io, "unexpected end of file"));
        }
        dest.write_all(&buf[..n])?;
        *written += n as u64;
        remaining -= n as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_edits_on_a_one_gigabyte_file_are_o_edits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.bin");
        {
            let file = std::fs::File::create(&path).unwrap();
            file.set_len(1024 * 1024 * 1024).unwrap();
        }
        let mut editor = RangeEditor::open(&path).unwrap();
        let started = std::time::Instant::now();
        for i in 0..100u64 {
            editor.edit(i * 10_000_000, 8, format!("edit-{i}")).unwrap();
        }
        let elapsed = started.elapsed();
        assert_eq!(editor.edits().len(), 100);
        assert_eq!(editor.bytes_read, 0, "edits read no base bytes");
        assert!(elapsed < std::time::Duration::from_secs(5), "edits took {elapsed:?}");
        // A line index is built lazily, and only then is the file streamed once.
        let offsets = editor.line_offsets().unwrap().to_vec();
        assert_eq!(offsets.first(), Some(&0));
        assert!(editor.bytes_read >= 1024 * 1024 * 1024, "the lazy scan reads once");
        let second = editor.line_offsets().unwrap().len();
        assert_eq!(offsets.len(), second, "the index is cached, not rebuilt");
        assert!(editor.bytes_read <= 1024 * 1024 * 1024 + 1024 * 1024);
    }

    #[test]
    fn saved_edits_are_exact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("base.txt");
        std::fs::write(&path, "0123456789").unwrap();
        let mut editor = RangeEditor::open(&path).unwrap();
        editor.edit(2, 3, "AB").unwrap();
        editor.edit(8, 1, "XYZ").unwrap();
        let out = dir.path().join("out.txt");
        let written = editor.save(&out).unwrap();
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "01AB567XYZ9");
        assert_eq!(written, 11);

        // Overlapping edits are refused instead of corrupting the output.
        let mut bad = RangeEditor::open(&path).unwrap();
        bad.edit(2, 5, "x").unwrap();
        bad.edit(4, 2, "y").unwrap();
        let err = bad.save(dir.path().join("bad.txt")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Conflict);
    }

    #[test]
    fn sqlite_like_line_offsets_are_correct() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lines.txt");
        std::fs::write(&path, "a\nbb\nccc\n").unwrap();
        let mut editor = RangeEditor::open(&path).unwrap();
        let offsets = editor.line_offsets().unwrap().to_vec();
        assert_eq!(offsets, vec![0, 2, 5]);
        let range = editor.file().read_range(2, 2).unwrap();
        assert_eq!(range, b"bb");
    }
}
