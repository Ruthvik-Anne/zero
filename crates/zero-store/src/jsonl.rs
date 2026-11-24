//! Append-only JSONL log with fsync durability and torn-tail recovery (FND-09).
//!
//! A crash can truncate the last line. The reader treats an unterminated final
//! line as a torn tail: it is never returned as a record, and [`repair`]
//! truncates it so the next append starts from a clean boundary.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub ts: i64,
    pub kind: String,
    pub payload: serde_json::Value,
}

/// Writer that appends one complete line per record and fsyncs before returning.
pub struct JsonlWriter {
    path: PathBuf,
    file: File,
    offset: u64,
}

impl JsonlWriter {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new().create(true).append(true).read(true).open(&path)?;
        let offset = file.metadata()?.len();
        Ok(Self { path, file, offset })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Append a record and fsync. The whole line is written before the fsync.
    pub fn append<T: Serialize>(&mut self, record: &T) -> Result<u64> {
        let mut line = serde_json::to_vec(record)?;
        line.push(b'\n');
        let start = self.offset;
        self.file.write_all(&line)?;
        self.file.flush()?;
        self.file.sync_data().map_err(|e| {
            ZeroError::new(ErrorCode::Io, format!("fsync failed after {} bytes: {e}", line.len()))
        })?;
        self.offset += line.len() as u64;
        Ok(start)
    }

    pub fn sync(&self) -> Result<()> {
        self.file.sync_data()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    pub records: Vec<Event>,
    pub torn_tail_bytes: u64,
    pub total_bytes: u64,
}

/// Read every complete record, reporting a torn tail instead of failing.
pub fn scan(path: impl AsRef<Path>) -> Result<ScanReport> {
    let path = path.as_ref();
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ScanReport { records: Vec::new(), torn_tail_bytes: 0, total_bytes: 0 })
        }
        Err(e) => return Err(e.into()),
    };
    let total_bytes = file.metadata()?.len();
    file.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::new(file);
    let mut records = Vec::new();
    let mut buf = Vec::new();
    let mut last_complete_offset = 0u64;
    loop {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        let complete = buf.last() == Some(&b'\n');
        if complete {
            buf.pop();
            if buf.is_empty() {
                last_complete_offset += (n) as u64;
                continue;
            }
            match serde_json::from_slice::<Event>(&buf) {
                Ok(event) => {
                    records.push(event);
                    last_complete_offset += n as u64;
                }
                Err(e) => {
                    // A complete line that does not parse is corruption, not a
                    // torn tail: refuse rather than silently dropping data.
                    return Err(ZeroError::new(
                        ErrorCode::Corrupt,
                        format!("{}: unparseable record at byte {last_complete_offset}: {e}", path.display()),
                    ));
                }
            }
        } else {
            // Unterminated final line: a torn tail from a crash mid-write.
            return Ok(ScanReport {
                records,
                torn_tail_bytes: total_bytes - last_complete_offset,
                total_bytes,
            });
        }
    }
    Ok(ScanReport { records, torn_tail_bytes: 0, total_bytes })
}

/// Truncate a torn tail so the file ends at a record boundary. Returns bytes cut.
pub fn repair(path: impl AsRef<Path>) -> Result<u64> {
    let path = path.as_ref();
    let report = scan(path)?;
    if report.torn_tail_bytes == 0 {
        return Ok(0);
    }
    let keep = report.total_bytes - report.torn_tail_bytes;
    let file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.set_len(keep)?;
    file.sync_all()?;
    Ok(report.torn_tail_bytes)
}

/// Repair a torn tail without parsing record contents. Used by typed logs whose
/// records are not the `Event` envelope.
pub fn repair_raw(path: impl AsRef<Path>) -> Result<u64> {
    let path = path.as_ref();
    let file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(0);
    }
    let mut reader = BufReader::new(file.try_clone()?);
    let window = 64 * 1024u64;
    let start = len.saturating_sub(window);
    reader.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    if buf.last() == Some(&b'\n') {
        return Ok(0);
    }
    let cut = match buf.iter().rposition(|b| *b == b'\n') {
        Some(pos) => start + pos as u64 + 1,
        None if start == 0 => 0,
        None => len, // No newline in the window and the file is large: unknown.
    };
    if cut == len {
        return Ok(0);
    }
    file.set_len(cut)?;
    file.sync_all()?;
    Ok(len - cut)
}

/// Scan typed records, skipping the header-free event envelope when the caller's
/// records were written raw. Used by session logs in M1.
pub fn scan_raw<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<(Vec<T>, u64)> {
    let path = path.as_ref();
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
        Err(e) => return Err(e.into()),
    };
    let total = file.metadata()?.len();
    let mut reader = BufReader::new(file.try_clone()?);
    let mut out = Vec::new();
    let mut buf = Vec::new();
    let mut complete_upto = 0u64;
    loop {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        if buf.last() != Some(&b'\n') {
            return Ok((out, complete_upto));
        }
        buf.pop();
        let v: T = serde_json::from_slice(&buf).map_err(|e| {
            ZeroError::new(ErrorCode::Corrupt, format!("unparseable record: {e}"))
        })?;
        out.push(v);
        complete_upto += n as u64;
    }
    let _ = total;
    Ok((out, complete_upto))
}

/// Read the raw bytes of a byte range; used by attach streaming (SES-07).
pub fn read_range(path: impl AsRef<Path>, start: u64, len: usize) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(start))?;
    let mut buf = vec![0u8; len];
    let mut read = 0;
    while read < len {
        let n = file.read(&mut buf[read..])?;
        if n == 0 {
            break;
        }
        read += n;
    }
    buf.truncate(read);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(seq: u64) -> Event {
        Event { seq, ts: 1000 + seq as i64, kind: "test".into(), payload: serde_json::json!({"n": seq}) }
    }

    #[test]
    fn append_and_scan_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut w = JsonlWriter::open(&path).unwrap();
        for i in 0..10 {
            w.append(&event(i)).unwrap();
        }
        let report = scan(&path).unwrap();
        assert_eq!(report.records.len(), 10);
        assert_eq!(report.torn_tail_bytes, 0);
        assert_eq!(report.records[3], event(3));
    }

    #[test]
    fn torn_tail_is_dropped_then_repaired() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut w = JsonlWriter::open(&path).unwrap();
        w.append(&event(0)).unwrap();
        w.append(&event(1)).unwrap();
        drop(w);
        // Simulate a crash mid-write of record 2.
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"seq\":2,\"ts\":10").unwrap();
        f.sync_all().unwrap();

        let report = scan(&path).unwrap();
        assert_eq!(report.records.len(), 2);
        assert!(report.torn_tail_bytes > 0);

        let cut = repair(&path).unwrap();
        assert!(cut > 0);
        let after = scan(&path).unwrap();
        assert_eq!(after.records.len(), 2);
        assert_eq!(after.torn_tail_bytes, 0);

        // Appending after repair produces a clean record at the right boundary.
        let mut w = JsonlWriter::open(&path).unwrap();
        w.append(&event(2)).unwrap();
        assert_eq!(scan(&path).unwrap().records.len(), 3);
    }

    #[test]
    fn complete_but_corrupt_line_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        std::fs::write(&path, b"{\"seq\":0,\"ts\":1,\"kind\":\"x\",\"payload\":{}}\nnot json\n").unwrap();
        let err = scan(&path).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Corrupt);
    }
}


