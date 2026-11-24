//! SES-06 evidence: two concurrent creates converge on one worker.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;

fn read_json_line(child: &mut std::process::Child) -> serde_json::Value {
    let mut out = String::new();
    child.stdout.as_mut().unwrap().read_to_string(&mut out).unwrap();
    serde_json::from_str(out.trim()).unwrap_or_else(|e| panic!("bad child output {out:?}: {e}"))
}

#[test]
fn concurrent_creates_converge_on_one_worker() {
    let bin = env!("CARGO_BIN_EXE_lease-session");
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("tree").join("s.jsonl");
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();

    let mut first = Command::new(bin)
        .arg(&log)
        .args(["1500", "10000"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    // Give the first process time to create the lease, then race a second.
    std::thread::sleep(Duration::from_millis(120));
    let mut second = Command::new(bin)
        .arg(&log)
        .args(["100", "10000"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    let second_out = read_json_line(&mut second);
    let first_out = read_json_line(&mut first);
    let _ = first.wait();
    let _ = second.wait();

    assert_eq!(first_out["outcome"], "created", "{first_out}");
    assert_eq!(second_out["outcome"], "existing", "{second_out}");
    assert_eq!(
        second_out["owner_pid"].as_u64().unwrap(),
        first_out["pid"].as_u64().unwrap(),
        "the loser must name the winning worker"
    );
    // One session file, with the winner's record.
    assert!(log.exists());
    let records = zero_store::session::SessionLog::open(&log).unwrap().records().unwrap();
    assert_eq!(records.len(), 1);
}
