//! Linux Landlock probe. Applies the sandbox and proves writes are denied while
//! reads still work. Exit codes: 0 enforced, 2 setup error, 4 unsupported,
//! 5 not enforced.

fn main() {
    #[cfg(target_os = "linux")]
    {
        match zero_policy::sandbox::linux::confine_writes() {
            Err(zero_policy::sandbox::SandboxError::Unsupported(reason)) => {
                println!("SKIP {reason}");
                std::process::exit(4);
            }
            Err(e) => {
                eprintln!("SETUP {e}");
                std::process::exit(2);
            }
            Ok(probe) => {
                let path = std::env::temp_dir().join(format!("zero-landlock-probe-{}", std::process::id()));
                match std::fs::write(&path, b"x") {
                    Ok(()) => {
                        let _ = std::fs::remove_file(&path);
                        eprintln!("NOT ENFORCED: write succeeded");
                        std::process::exit(5);
                    }
                    Err(e) => {
                        println!("ENFORCED {}: write denied ({e})", probe.detail);
                        // Reads must still work.
                        if std::fs::read("/etc/hosts").is_err() && std::fs::read("/etc/hostname").is_err() {
                            eprintln!("read check failed");
                            std::process::exit(5);
                        }
                        std::process::exit(0);
                    }
                }
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        println!("SKIP: the Landlock probe is Linux-only");
        std::process::exit(4);
    }
}
