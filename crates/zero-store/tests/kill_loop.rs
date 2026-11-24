//! FND-09 evidence: kill the writer process repeatedly and prove the log stays
//! parseable and replayable, with a torn tail at most.

use std::process::{Command, Stdio};
use std::time::Duration;
use zero_store::jsonl::{repair, scan, Event, JsonlWriter};

#[test]
fn kill_loop_leaves_logs_parseable_and_replayable() {
    let bin = env!("CARGO_BIN_EXE_append-loop");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kill-loop.jsonl");

    let mut torn_runs = 0;
    for run in 0..4 {
        let mut child = Command::new(bin)
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn writer");
        std::thread::sleep(Duration::from_millis(250));
        child.kill().expect("hard kill");
        let _ = child.wait();

        let report = scan(&path).unwrap();
        assert!(!report.records.is_empty(), "run {run}: no complete records survived");
        // Every surviving record parses and the sequence is dense from zero.
        for (i, event) in report.records.iter().enumerate() {
            assert_eq!(event.seq, i as u64, "run {run}: replay order broke at {i}");
            assert_eq!(event.kind, "kill-loop");
        }
        if report.torn_tail_bytes > 0 {
            torn_runs += 1;
        }
        // Repair and prove the next writer continues cleanly.
        repair(&path).unwrap();
        let repaired = scan(&path).unwrap();
        assert_eq!(repaired.torn_tail_bytes, 0, "run {run}: repair failed");
        let mut w = JsonlWriter::open(&path).unwrap();
        let next = repaired.records.len() as u64;
        w.append(&Event {
            seq: next,
            ts: 0,
            kind: "kill-loop".into(),
            payload: serde_json::json!({"resumed": true}),
        })
        .unwrap();
    }

    let final_report = scan(&path).unwrap();
    assert!(final_report.records.len() >= 4, "expected records across four runs");
    eprintln!(
        "kill loop: {} complete records, {} runs ended with a torn tail",
        final_report.records.len(),
        torn_runs
    );
}
