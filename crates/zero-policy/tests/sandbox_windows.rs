//! TRU-03 evidence: the Windows Job Object prototype confines a child process.

#![cfg(windows)]

#[test]
fn windows_job_object_prototype_confines_a_child() {
    let probe = zero_policy::sandbox::windows::prototype().expect("job object prototype");
    assert_eq!(probe.mechanism, "windows-job-object");
    assert!(probe.enforced);
    assert!(probe.detail.contains("memory cap"));
    assert!(probe.detail.contains("exit"));
}
