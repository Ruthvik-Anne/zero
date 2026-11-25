//! DEL-03 evidence on Windows: the PowerShell function shim blocks Remove-Item
//! and leaves the file in place.

#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;
use zero_policy::shims::install_powershell;

#[test]
fn powershell_function_shim_blocks_remove_item() {
    let dir = tempfile::tempdir().unwrap();
    let victim = dir.path().join("victim.txt");
    std::fs::write(&victim, b"keep me").unwrap();
    let guard = PathBuf::from(env!("CARGO_BIN_EXE_zero-guard"));
    let shim = install_powershell(dir.path(), &guard).unwrap();

    let command = format!(
        ". '{}'; Remove-Item -LiteralPath '{}' -Force",
        shim.display(),
        victim.display()
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"])
        .arg(&command)
        .output()
        .expect("run powershell");
    assert!(!out.status.success(), "the shim should have blocked the delete");
    assert!(victim.exists(), "the file must survive a blocked delete");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.to_lowercase().contains("blocked") || stderr.contains("zero-guard"), "{stderr}");
}

#[test]
fn the_guard_binary_blocks_and_allows_directly() {
    let guard = env!("CARGO_BIN_EXE_zero-guard");
    let blocked = Command::new(guard).args(["posix", "rm", "-rf", "build"]).output().unwrap();
    assert_eq!(blocked.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("blocked"));

    let allowed = Command::new(guard).args(["posix", "ls", "-la"]).output().unwrap();
    assert!(allowed.status.success());
}
