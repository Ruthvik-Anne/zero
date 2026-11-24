//! SES-08 evidence: a killed worker recovers, failures are bounded, adoption and
//! coordinated shutdown work.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zero_daemon::{Supervisor, SupervisorConfig, WorkerStatus};

fn worker_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_zero-worker"))
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn fast_config() -> SupervisorConfig {
    let mut config = SupervisorConfig::for_binary(worker_bin());
    config.backoff_ms = vec![10, 10, 10];
    config.stale_heartbeat_ms = 3_000;
    config
}

fn wait_for_heartbeat(path: &Path) -> bool {
    for _ in 0..100 {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn killing_a_worker_recovers_the_tree_with_bounded_retries() {
    let dir = tempfile::tempdir().unwrap();
    let session = dir.path().join("s.jsonl");
    let mut supervisor = Supervisor::new(fast_config());

    supervisor.start(&session, now_ms()).unwrap();
    let heartbeat = session.with_extension("heartbeat");
    assert!(wait_for_heartbeat(&heartbeat), "worker did not start");

    let first_pid = supervisor.route(&session).expect("routed worker");
    assert!(supervisor.healthy(&session, now_ms()));

    // Simulate an external kill.
    supervisor.kill_worker(&session).unwrap();
    let now = now_ms();
    supervisor.poll(now);
    supervisor.poll(now + 50);
    for _ in 0..50 {
        if supervisor.route(&session).is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
        supervisor.poll(now_ms());
    }
    let second_pid = supervisor.route(&session).expect("worker restarted");
    assert_ne!(first_pid, second_pid);
    let key = supervisor.workers().next().unwrap().session.clone();
    let record = supervisor
        .workers()
        .find(|r| r.session == key)
        .expect("record");
    assert_eq!(record.restarts, 1, "one failure, one restart");
    assert_eq!(record.status, WorkerStatus::Running);
    assert!(supervisor.healthy(&session, now_ms()));

    supervisor.shutdown().unwrap();
}

#[test]
fn repeated_failures_stop_at_the_retry_budget() {
    let dir = tempfile::tempdir().unwrap();
    let session = dir.path().join("failing.jsonl");
    let mut config = fast_config();
    config.worker_args = vec!["--fail-after-ms".into(), "60".into()];
    let mut supervisor = Supervisor::new(config);
    supervisor.start(&session, now_ms()).unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        supervisor.poll(now_ms());
        let failed = supervisor
            .workers()
            .any(|r| matches!(r.status, WorkerStatus::Failed { .. }));
        if failed {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "worker never reached the retry budget");
        std::thread::sleep(Duration::from_millis(30));
    }
    let record = supervisor.workers().next().unwrap();
    assert_eq!(record.restarts, 4, "three allowed restarts plus the failure that exhausts the budget");
    match &record.status {
        WorkerStatus::Failed { reason } => assert!(reason.contains("failed 4 times"), "{reason}"),
        other => panic!("expected Failed, got {other:?}"),
    }
    assert_eq!(supervisor.route(&session), None);
    supervisor.shutdown().unwrap();
}

#[test]
fn a_new_supervisor_adopts_a_running_worker() {
    let dir = tempfile::tempdir().unwrap();
    let session = dir.path().join("adopt.jsonl");
    let heartbeat = session.with_extension("heartbeat");

    // Start the worker outside the supervisor, as a previous supervisor would.
    std::fs::create_dir_all(dir.path()).unwrap();
    let mut child = Command::new(worker_bin())
        .arg("--session")
        .arg(&session)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(wait_for_heartbeat(&heartbeat));

    let mut supervisor = Supervisor::new(fast_config());
    supervisor.adopt(&session, child.id());
    assert!(supervisor.healthy(&session, now_ms()));
    assert_eq!(supervisor.route(&session), Some(child.id()));

    // Coordinated shutdown asks the adopted worker to stop.
    supervisor.shutdown().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "adopted worker did not stop");
        std::thread::sleep(Duration::from_millis(30));
    }
}
