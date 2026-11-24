//! SES-12 evidence: the line-mode client drives the loop in CI without a
//! terminal, and a second run resumes the same session.

use std::io::Write;
use std::process::{Command, Stdio};

fn zero() -> Command {
    Command::new(env!("CARGO_BIN_EXE_zero"))
}

fn script_one() -> &'static str {
    r#"{
      "turns": [
        {"text": "", "tool_calls": [{"id": "c1", "name": "echo", "arguments": {"text": "hello from tool"}}]},
        {"text": "final answer", "usage": {"input_tokens": 5, "output_tokens": 3}}
      ]
    }"#
}

#[test]
fn line_client_drives_the_loop_without_a_terminal() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("script.json");
    std::fs::write(&script, script_one()).unwrap();

    let mut child = zero()
        .args(["resume", "--line", "--session", "demo", "--script"])
        .arg(&script)
        .arg("--data-dir")
        .arg(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"please echo\n/quit\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("line: created"), "{stdout}");
    assert!(stdout.contains("tool: hello from tool"), "{stdout}");
    assert!(stdout.contains("assistant: final answer"), "{stdout}");
    assert!(stdout.contains("final: final answer"), "{stdout}");
    assert!(stdout.contains("usage: in=5 out=3"), "{stdout}");
    assert!(stdout.contains("bye"), "{stdout}");

    let log = dir.path().join("sessions").join("demo.jsonl");
    assert!(log.exists());
    let records = zero_store::session::SessionLog::open(&log).unwrap().records().unwrap();
    assert!(records.iter().any(|r| r.entry.message_text() == Some("please echo")));
    assert!(records.iter().any(|r| r.entry.message_text() == Some("final answer")));

    // A second run resumes the same session and appends.
    let script2 = dir.path().join("script2.json");
    std::fs::write(&script2, r#"{"turns":[{"text":"second answer"}]}"#).unwrap();
    let mut child = zero()
        .args(["resume", "--line", "--session", "demo", "--script"])
        .arg(&script2)
        .arg("--data-dir")
        .arg(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"again\n/quit\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("line: resumed"), "{stdout}");
    assert!(stdout.contains("assistant: second answer"), "{stdout}");
    let records = zero_store::session::SessionLog::open(&log).unwrap().records().unwrap();
    assert!(records.iter().any(|r| r.entry.message_text() == Some("second answer")));
}

#[test]
fn line_mode_requires_a_script() {
    let dir = tempfile::tempdir().unwrap();
    let out = zero()
        .args(["resume", "--line", "--data-dir"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--script is required"));
}
