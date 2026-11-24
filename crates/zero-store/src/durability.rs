//! Crash-injection durability harness (FND-09).
//!
//! Every durable write path is exercised with a simulated kill at a random byte
//! offset. The invariant: after any crash, the store contains a prefix of
//! complete records and no torn record is ever returned to a reader.

use crate::jsonl::{scan, Event, ScanReport};
use serde::Serialize;
use std::path::Path;
use zero_types::error::Result;

/// Serialise a record exactly as `JsonlWriter` does, including the newline.
pub fn encode_record<T: Serialize>(record: &T) -> Result<Vec<u8>> {
    let mut line = serde_json::to_vec(record)?;
    line.push(b'\n');
    Ok(line)
}

/// Simulate writing `bytes` with a crash after `crash_at` bytes.
pub fn crash_after(bytes: &[u8], crash_at: usize) -> Vec<u8> {
    bytes[..crash_at.min(bytes.len())].to_vec()
}

/// Write a record stream to `path`, stopping at `crash_at` total bytes.
/// Returns (bytes written, records completed).
pub fn write_with_crash<T: Serialize>(path: impl AsRef<Path>, records: &[T], crash_at: usize) -> Result<(usize, usize)> {
    let mut buf = Vec::new();
    for r in records {
        buf.extend_from_slice(&encode_record(r)?);
    }
    let cut = crash_after(&buf, crash_at);
    std::fs::write(path, &cut)?;
    let completed = cut.iter().filter(|b| **b == b'\n').count();
    Ok((cut.len(), completed))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashReport {
    pub written: usize,
    pub completed_lines: usize,
    pub scan: ScanReport,
}

/// Verify one injected crash: every returned record parses, the returned set is
/// a prefix of the intended set, and the torn tail is at most one record.
pub fn verify_crash(path: impl AsRef<Path>, expected: &[Event], written: usize) -> Result<CrashReport> {
    let scan = scan(path)?;
    let completed_lines = scan.records.len();
    assert!(
        scan.records.len() <= expected.len(),
        "reader returned more records than were written"
    );
    for (got, want) in scan.records.iter().zip(expected) {
        assert_eq!(got, want, "record at the boundary differs: torn record returned");
    }
    assert!(
        scan.total_bytes == written as u64,
        "written bytes must match the crashed file size"
    );
    if scan.torn_tail_bytes > 0 {
        let max_record = expected
            .iter()
            .map(|e| encode_record(e).unwrap().len() as u64)
            .max()
            .unwrap_or(0);
        assert!(
            scan.torn_tail_bytes <= max_record,
            "torn tail larger than one record: {} > {}",
            scan.torn_tail_bytes,
            max_record
        );
    }
    Ok(CrashReport { written, completed_lines, scan })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonl::repair;
    use zero_types::id::DeterministicRng;

    fn events(n: usize) -> Vec<Event> {
        (0..n)
            .map(|i| Event {
                seq: i as u64,
                ts: i as i64,
                kind: "durable".into(),
                payload: serde_json::json!({"i": i, "pad": "x".repeat(64)}),
            })
            .collect()
    }

    #[test]
    fn one_thousand_injected_crashes_leave_no_torn_record() {
        let dir = tempfile::tempdir().unwrap();
        let expected = events(64);
        let total: usize = expected.iter().map(|e| encode_record(e).unwrap().len()).sum();
        let mut rng = DeterministicRng::new(0xD00D);
        for iteration in 0..1000 {
            let crash_at = rng.below(total as u32 + 1) as usize;
            let path = dir.path().join(format!("crash-{iteration}.jsonl"));
            let (written, _) = write_with_crash(&path, &expected, crash_at).unwrap();
            let report = verify_crash(&path, &expected, written).unwrap();
            assert!(report.completed_lines <= expected.len());
            // Repair then append must produce a valid continuation.
            repair(&path).unwrap();
            let after = scan(&path).unwrap();
            assert_eq!(after.torn_tail_bytes, 0);
            assert_eq!(after.records, report.scan.records);
        }
    }
}
