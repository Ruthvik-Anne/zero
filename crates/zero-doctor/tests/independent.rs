//! Independence evidence (T-DOC-01, DOC-09): the binary works with no daemon.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Build a doctor command whose daemon addresses all point at paths that do not
/// exist, so any attempt to contact the daemon fails instead of reaching a
/// live instance.
fn doctor(dir: &Path) -> (Command, PathBuf) {
    let socket = dir.join("no-such-daemon.sock");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_zero-doctor"));
    cmd.env("ZERO_DAEMON_SOCKET", &socket)
        .env("ZERO_DAEMON", dir.join("no-such-daemon"))
        .env("ZERO_DATA_DIR", dir.join("data"))
        .current_dir(dir);
    (cmd, socket)
}

#[test]
fn runs_with_the_daemon_dead_and_says_it_was_not_contacted() {
    let dir = tempfile::tempdir().unwrap();
    let (mut cmd, socket) = doctor(dir.path());
    let out = cmd.output().expect("run zero-doctor");
    assert!(
        out.status.success(),
        "status {:?}, stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("daemon: not contacted"), "stdout: {stdout}");
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")), "stdout: {stdout}");
    assert!(!socket.exists(), "the doctor must not create a daemon socket");
}

#[test]
fn json_report_is_independent_and_never_contacted_the_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let (mut cmd, _socket) = doctor(dir.path());
    let out = cmd.arg("--json").output().expect("run zero-doctor --json");
    assert!(out.status.success());
    assert_eq!(out.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON report");
    assert_eq!(report["independent"], true);
    assert_eq!(report["daemon"], "not_contacted");
    assert_eq!(report["version"], env!("CARGO_PKG_VERSION"));
    assert!(report["checks"].as_array().unwrap().is_empty());
}

#[test]
fn version_flag_prints_the_version_without_a_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let (mut cmd, _socket) = doctor(dir.path());
    let out = cmd.arg("--version").output().expect("run zero-doctor --version");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")), "stdout: {stdout}");
}
