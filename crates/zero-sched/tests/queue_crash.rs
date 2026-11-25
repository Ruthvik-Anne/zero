//! SCH-06 evidence: kill a worker mid-queue and prove the call is dispatched
//! exactly once across the restart.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use zero_sched::{CallState, DurableQueue};

#[test]
fn killing_a_worker_mid_queue_yields_one_dispatch_per_call() {
    let dir = tempfile::tempdir().unwrap();
    let queue_path = dir.path().join("queue.jsonl");
    let id = {
        let mut queue = DurableQueue::open(&queue_path).unwrap();
        queue.enqueue("call-key", "openai", "gpt", serde_json::json!({"prompt": "hi"})).unwrap()
    };

    let marker = dir.path().join("claimed.marker");
    let mut child = Command::new(env!("CARGO_BIN_EXE_queue-claim"))
        .arg(&queue_path)
        .arg(&marker)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn worker");

    let deadline = Instant::now() + Duration::from_secs(10);
    while !marker.exists() {
        assert!(Instant::now() < deadline, "worker never claimed the call");
        std::thread::sleep(Duration::from_millis(25));
    }
    let claimed = std::fs::read_to_string(&marker).unwrap();
    assert!(claimed.starts_with(&id), "unexpected marker: {claimed}");
    child.kill().expect("kill worker");
    let _ = child.wait();

    // Restart: the claim is durable, and the call is never re-dispatched.
    let mut queue = DurableQueue::open(&queue_path).unwrap();
    assert!(matches!(queue.state(&id), Some(CallState::InFlight { .. })));
    assert_eq!(queue.dispatch_count(&id), 1);
    assert!(queue.claim_next("new-worker", 1).unwrap().is_none());
    let uncertain = queue.recover(2).unwrap();
    assert_eq!(uncertain, vec![id.clone()]);
    assert_eq!(queue.state(&id), Some(&CallState::Uncertain));
    assert!(queue.claim_next("new-worker", 3).unwrap().is_none());
    assert_eq!(queue.dispatch_count(&id), 1);
}
