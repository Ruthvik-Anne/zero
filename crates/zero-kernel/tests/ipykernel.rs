//! KRN-01, KRN-03, KRN-04, KRN-05 evidence against a real ipykernel.
//! Skips with a reason when ipykernel/pyzmq are not installed.

use std::time::Duration;
use zero_kernel::jupyter::{default_python, kernel_available, KernelClient};

fn start(dir: &std::path::Path) -> Option<KernelClient> {
    if !kernel_available() {
        println!("skipped: ipykernel/pyzmq are not installed");
        return None;
    }
    Some(KernelClient::start(&default_python(), dir).expect("start ipykernel"))
}

#[test]
fn real_ipykernel_execute_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let Some(mut client) = start(dir.path()) else { return };
    let out = client.execute("print('hello'); 2+2", Duration::from_secs(20)).unwrap();
    assert!(out.stdout.contains("hello"), "{out:?}");
    assert_eq!(out.result.as_deref(), Some("4"), "{out:?}");
    assert!(out.error.is_none());
    assert!(!out.timed_out);
    client.stop();
}

#[test]
fn state_survives_a_kill_and_rehydrate_reports_the_lost_cell() {
    let dir = tempfile::tempdir().unwrap();
    let Some(mut client) = start(dir.path()) else { return };
    client.execute("x = 41", Duration::from_secs(10)).unwrap();
    let out = client.execute("print(x)", Duration::from_secs(10)).unwrap();
    assert!(out.stdout.contains("41"));

    // Kill mid-cell: the call times out and is recorded as lost.
    let lost = client
        .execute("import time; time.sleep(30)", Duration::from_millis(500))
        .unwrap();
    assert!(lost.timed_out, "{lost:?}");
    assert!(client.last_lost.as_deref().unwrap_or("").contains("sleep(30)"));

    // The next call restarts and replays the successful history.
    let out = client.execute_after_restart("print(x)", Duration::from_secs(30)).unwrap();
    assert!(out.stdout.contains("41"), "{out:?}");
    assert!(out.replayed >= 1, "replayed {}", out.replayed);
    client.stop();
}

#[test]
fn an_output_flood_is_capped_and_the_kernel_stays_usable() {
    let dir = tempfile::tempdir().unwrap();
    let Some(mut client) = start(dir.path()) else { return };
    client.max_output_bytes = 2000;
    let out = client
        .execute("for i in range(10000): print('x' * 100)", Duration::from_secs(30))
        .unwrap();
    assert!(!out.timed_out);
    assert!(out.stdout.len() <= 2200, "output {} bytes", out.stdout.len());
    assert!(out.stdout.contains("[output truncated]"));
    let out = client.execute("6*7", Duration::from_secs(10)).unwrap();
    assert_eq!(out.result.as_deref(), Some("42"));
    client.stop();
}

#[test]
fn percent_cd_persists_and_the_preloaded_namespace_exists() {
    let dir = tempfile::tempdir().unwrap();
    let Some(mut client) = start(dir.path()) else { return };
    let sub = dir.path().join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    client
        .execute(&format!("%cd {}", sub.display()), Duration::from_secs(10))
        .unwrap();
    let out = client.execute("import os; print(os.getcwd())", Duration::from_secs(10)).unwrap();
    assert!(out.stdout.contains("sub"), "{out:?}");
    let out = client
        .execute(
            "print(hasattr(zero,'trash'), hasattr(zero,'web_search'), hasattr(zero,'tool_search'))",
            Duration::from_secs(10),
        )
        .unwrap();
    assert!(out.stdout.contains("True True True"), "{out:?}");
    client.stop();
}

#[test]
fn a_process_spawn_flood_is_bounded_and_the_kernel_stays_usable() {
    let dir = tempfile::tempdir().unwrap();
    let Some(mut client) = start(dir.path()) else { return };
    let code = r#"
import subprocess, sys
spawned = []
for _ in range(100):
    try:
        spawned.append(subprocess.Popen([sys.executable, "-c", "pass"]))
    except PermissionError:
        break
for p in spawned:
    p.wait()
print("SPAWNED", len(spawned))
"#;
    let out = client.execute(code, Duration::from_secs(30)).unwrap();
    assert!(out.stdout.contains("SPAWNED"), "{out:?}");
    let count: u32 = out
        .stdout
        .split("SPAWNED")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(999);
    assert!(count <= 8, "process limit not enforced: {count}");
    let out = client.execute("1+1", Duration::from_secs(10)).unwrap();
    assert_eq!(out.result.as_deref(), Some("2"));
    client.stop();
}

#[cfg(unix)]
#[test]
fn bash_cell_state_does_not_leak_into_python() {
    let dir = tempfile::tempdir().unwrap();
    let Some(mut client) = start(dir.path()) else { return };
    let out = client
        .execute("%%bash\nexport ZERO_LEAK_TEST=1", Duration::from_secs(10))
        .unwrap();
    if out.error.is_some() {
        println!("skipped: %%bash is unavailable: {:?}", out.error);
        return;
    }
    let out = client
        .execute("import os; print(os.environ.get('ZERO_LEAK_TEST'))", Duration::from_secs(10))
        .unwrap();
    assert!(out.stdout.trim().is_empty() || out.stdout.contains("None"), "{out:?}");
    client.stop();
}
