//! DEL-03 evidence on Unix: a Makefile deletion is blocked by the PATH shim.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;
use zero_policy::shims::install_posix;

#[test]
fn a_makefile_deletion_is_blocked_by_the_path_shim() {
    let dir = tempfile::tempdir().unwrap();
    let victim = dir.path().join("victim");
    std::fs::create_dir_all(&victim).unwrap();
    std::fs::write(victim.join("keep.txt"), b"keep").unwrap();

    let guard = PathBuf::from(env!("CARGO_BIN_EXE_zero-guard"));
    let shim_dir = dir.path().join("shims");
    install_posix(&shim_dir, &guard).unwrap();

    std::fs::write(dir.path().join("Makefile"), "clean:\n\trm -rf victim\n").unwrap();

    let path = format!(
        "{}:{}",
        shim_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = Command::new("make")
        .arg("-f")
        .arg(dir.path().join("Makefile"))
        .arg("clean")
        .current_dir(dir.path())
        .env("PATH", path)
        .output()
        .expect("run make");
    assert!(!out.status.success(), "make must fail when the guard blocks rm");
    assert!(victim.exists(), "the directory must survive");
    assert!(victim.join("keep.txt").exists());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("zero-guard") || stderr.to_lowercase().contains("blocked"), "{stderr}");
}
