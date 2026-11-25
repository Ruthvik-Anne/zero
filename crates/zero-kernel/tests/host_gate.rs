//! KRN-02 evidence: kernel effects go through the policy host gate. Plan mode
//! denies a file write even when the request bypasses the edit tool.

use zero_kernel::KernelHost;
use zero_policy::{Mode, Policy, PolicyEngine};
use zero_types::protected::ProtectedPaths;

fn gate(mode: Mode) -> KernelHost {
    KernelHost::new(PolicyEngine::new(Policy::new(mode, ProtectedPaths::for_current())))
}

#[test]
fn a_kernel_file_write_is_denied_in_plan_mode() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("generated.py");
    let mut host = gate(Mode::Plan);
    let err = host.write_file(&target, b"print('nope')", 0).unwrap_err();
    assert_eq!(err.code(), zero_types::ErrorCode::PolicyDenied);
    assert!(!target.exists(), "the effect never ran");

    let mut host = gate(Mode::Auto);
    host.write_file(&target, b"print('ok')", 1).unwrap();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "print('ok')");
}

#[test]
fn reads_and_shell_obey_the_live_mode() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("data.txt");
    std::fs::write(&file, b"readable").unwrap();
    let mut host = gate(Mode::Plan);
    assert_eq!(host.read_file(&file, 0).unwrap(), b"readable");
    let err = host.shell("echo hi", 1).unwrap_err();
    assert_eq!(err.code(), zero_types::ErrorCode::PolicyDenied);
    let err = host.delete_file(&file, 2).unwrap_err();
    assert_eq!(err.code(), zero_types::ErrorCode::PolicyDenied);
    assert!(file.exists());
}
