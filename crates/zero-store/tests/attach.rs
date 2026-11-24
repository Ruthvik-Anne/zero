//! SES-07 evidence: a 500 MiB session attaches without loading history.
//!
//! The proof is structural and measured: the index is built by a streaming scan
//! and written to disk (no in-memory offset list), and attach reads only the last
//! `max_entries` records. `tail_bytes_read` stays under a megabyte for a 500 MiB
//! file.

use std::io::Write;
use zero_store::session::{attach, SessionMeta, ENTRY_SCHEMA_VERSION};

#[test]
fn five_hundred_mib_attaches_without_loading_history() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("huge.jsonl");
    let index = dir.path().join("huge.idx");
    let pad = "x".repeat(60);

    let target: u64 = 500 * 1024 * 1024;
    let mut written: u64 = 0;
    let mut seq: u64 = 0;
    {
        let file = std::fs::File::create(&log).unwrap();
        let mut w = std::io::BufWriter::with_capacity(1024 * 1024, file);
        while written < target {
            writeln!(
                w,
                "{{\"seq\":{seq},\"ts\":0,\"kind\":\"message\",\"role\":\"user\",\"text\":\"{pad}\"}}"
            )
            .unwrap();
            written += 100;
            seq += 1;
        }
        w.flush().unwrap();
        w.get_ref().sync_all().unwrap();
    }
    let file_len = std::fs::metadata(&log).unwrap().len();
    assert!(file_len >= target, "fixture must exceed 500 MiB, got {file_len}");
    let total = seq;

    zero_store::session::write_meta(
        &log,
        &SessionMeta {
            schema: ENTRY_SCHEMA_VERSION,
            generation: 7,
            created_ts: 0,
            name: "huge".into(),
            project: None,
            parent: None,
        },
    )
    .unwrap();

    let started = std::time::Instant::now();
    let snapshot = attach(&log, &index, 50).unwrap();
    let first_elapsed = started.elapsed();
    println!(
        "attach: {} MiB, {} records, tail {} bytes, index {} bytes, elapsed {:?}",
        file_len / 1024 / 1024,
        total,
        snapshot.stats.tail_bytes_read,
        snapshot.stats.index_bytes_read,
        first_elapsed
    );

    assert_eq!(snapshot.entries.len(), 50);
    assert_eq!(snapshot.stats.records_returned, 50);
    assert_eq!(snapshot.stats.total_records, total);
    assert_eq!(snapshot.stats.bytes_scanned_for_index, file_len);
    assert!(snapshot.stats.index_rebuilt);
    assert!(
        snapshot.stats.tail_bytes_read < 1024 * 1024,
        "tail read must stay bounded, was {}",
        snapshot.stats.tail_bytes_read
    );
    assert_eq!(snapshot.cursor.generation, 7);
    assert_eq!(snapshot.cursor.sequence, total);
    assert_eq!(snapshot.entries.last().unwrap().seq, total - 1);
    assert!(snapshot.history_bytes > target / 2, "history is streamable by offset");

    // A second attach reuses the index and reads only the tail again.
    let started = std::time::Instant::now();
    let again = attach(&log, &index, 50).unwrap();
    let second_elapsed = started.elapsed();
    assert!(!again.stats.index_rebuilt, "the index must be reused");
    assert_eq!(again.stats.bytes_scanned_for_index, 0);
    assert_eq!(again.entries, snapshot.entries);
    assert!(
        second_elapsed < std::time::Duration::from_secs(5),
        "tail attach must not scan history, took {second_elapsed:?}"
    );
}
