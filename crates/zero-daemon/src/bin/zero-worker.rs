//! Worker process: owns a session tree's loop. A supervisor starts, monitors,
//! adopts, and restarts it. It writes a heartbeat file so an adopting supervisor
//! can judge liveness without owning the child handle.

use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zero_store::session::{Entry, SessionLog, SessionMeta, ENTRY_SCHEMA_VERSION};

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn heartbeat(path: &PathBuf, state: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    write!(f, "{{\"pid\":{},\"ts\":{},\"state\":\"{state}\"}}", std::process::id(), now_ms())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut session: Option<PathBuf> = None;
    let mut heartbeat_path: Option<PathBuf> = None;
    let mut stop_file: Option<PathBuf> = None;
    let mut fail_after_ms: Option<u64> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--session" => session = args.next().map(PathBuf::from),
            "--heartbeat" => heartbeat_path = args.next().map(PathBuf::from),
            "--stop-file" => stop_file = args.next().map(PathBuf::from),
            "--fail-after-ms" => fail_after_ms = args.next().and_then(|v| v.parse().ok()),
            other => {
                eprintln!("zero-worker: unknown argument `{other}`");
                std::process::exit(2);
            }
        }
    }
    let Some(session_path) = session else {
        eprintln!("zero-worker: --session is required");
        std::process::exit(2);
    };
    let heartbeat_path = heartbeat_path.unwrap_or_else(|| session_path.with_extension("heartbeat"));
    let stop_file = stop_file.unwrap_or_else(|| session_path.with_extension("stop"));

    let mut log = match SessionLog::open(&session_path) {
        Ok(log) => log,
        Err(_) => SessionLog::create(
            &session_path,
            SessionMeta {
                schema: ENTRY_SCHEMA_VERSION,
                generation: 1,
                created_ts: now_ms(),
                name: session_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("worker")
                    .to_string(),
                project: None,
                parent: None,
            },
        )
        .expect("create session"),
    };
    log.append(now_ms(), Entry::Info { text: format!("worker {} started", std::process::id()) })
        .expect("append start");

    let started = Instant::now();
    loop {
        let _ = heartbeat(&heartbeat_path, "running");
        if stop_file.exists() {
            let _ = heartbeat(&heartbeat_path, "stopped");
            let _ = std::fs::remove_file(&stop_file);
            std::process::exit(0);
        }
        if let Some(limit) = fail_after_ms {
            if started.elapsed().as_millis() as u64 >= limit {
                let _ = heartbeat(&heartbeat_path, "failed");
                std::process::exit(3);
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}
