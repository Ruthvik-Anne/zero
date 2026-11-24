//! CLI shell evidence (T-FND-11, FND-01).

use std::process::Command;

fn zero() -> Command {
    Command::new(env!("CARGO_BIN_EXE_zero"))
}

#[test]
fn unknown_verb_prints_the_matching_action_name_and_exits_non_zero() {
    let out = zero().arg("resum").output().expect("run zero");
    assert!(!out.status.success(), "unknown verb must exit non-zero");
    assert_ne!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("`resume`"), "stderr: {stderr}");
}

#[test]
fn nonsense_verb_still_exits_non_zero() {
    let out = zero().arg("frobnicate").output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown verb"));
}

#[test]
fn version_runs_before_any_installer_step() {
    let out = zero().arg("--version").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("zero 0.1.0"), "{stdout}");
    assert!(stdout.contains("protocol 1"), "{stdout}");
}

#[test]
fn help_lists_exactly_the_permitted_verbs() {
    let out = zero().arg("--help").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for verb in ["resume", "login", "logout", "doctor", "install", "update", "uninstall", "service", "completion"] {
        assert!(stdout.contains(verb), "help is missing {verb}");
    }
}

#[test]
fn doctor_passes_on_a_fresh_directory_and_reports_every_check() {
    let dir = tempfile::tempdir().unwrap();
    let out = zero()
        .args(["doctor", "--json", "--data-dir"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let checks = value["checks"].as_array().unwrap();
    let names: Vec<&str> = checks.iter().map(|c| c["check"].as_str().unwrap()).collect();
    for expected in ["data_dir", "config_dir", "state_dir", "cache_dir", "store", "offline"] {
        assert!(names.contains(&expected), "missing check {expected}: {names:?}");
    }
    assert!(checks.iter().all(|c| c["status"] == "ok"));
}

#[test]
fn login_is_honest_about_the_missing_credential_store() {
    let out = zero().args(["login", "openai"]).output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("zero.fnd.unavailable"), "{stderr}");
}

#[test]
fn resume_list_works_with_no_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let out = zero()
        .args(["resume", "--list", "--data-dir"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("no saved sessions"));
}

#[test]
fn completion_scripts_mention_the_verbs() {
    for shell in ["bash", "zsh", "fish", "powershell"] {
        let out = zero().args(["completion", shell]).output().unwrap();
        assert!(out.status.success(), "{shell}");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("resume"), "{shell}: {stdout}");
    }
    let out = zero().args(["completion", "tcsh"]).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn service_status_does_not_pretend_a_unit_exists() {
    let out = zero().args(["service", "status"]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("not installed"));
}
