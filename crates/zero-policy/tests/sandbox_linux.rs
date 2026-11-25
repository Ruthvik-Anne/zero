//! TRU-03 evidence: the Linux Landlock prototype denies writes in a child
//! process. Skipped with a message when the kernel lacks Landlock.

#![cfg(target_os = "linux")]

use std::process::Command;

#[test]
fn linux_landlock_prototype_denies_writes() {
    let out = Command::new(env!("CARGO_BIN_EXE_zero-sandbox-probe"))
        .output()
        .expect("run probe");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    match out.status.code() {
        Some(0) => {
            assert!(stdout.contains("ENFORCED"), "{stdout}");
            assert!(stdout.contains("landlock") || stdout.contains("ABI"), "{stdout}");
        }
        Some(4) => println!("skipped: {stdout}{stderr}"),
        code => panic!("probe failed with {code:?}: {stdout}\n{stderr}"),
    }
}
