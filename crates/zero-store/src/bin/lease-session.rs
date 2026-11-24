//! Helper for the concurrent-create test: try to lease a session log and create
//! it only when this process wins. Prints one JSON line, then holds the lease.

use std::io::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zero_store::lease::{acquire, LeaseOutcome};
use zero_store::session::{Entry, SessionLog, SessionMeta, ENTRY_SCHEMA_VERSION};

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let log_path = args.next().expect("usage: lease-session <log> [hold_ms] [ttl_ms]");
    let hold_ms: u64 = args.next().and_then(|v| v.parse().ok()).unwrap_or(1200);
    let ttl_ms: i64 = args.next().and_then(|v| v.parse().ok()).unwrap_or(10_000);

    match acquire(std::path::Path::new(&log_path), now_ms(), ttl_ms).expect("lease") {
        LeaseOutcome::Acquired(mut lease) => {
            let log = SessionLog::create(
                &log_path,
                SessionMeta {
                    schema: ENTRY_SCHEMA_VERSION,
                    generation: 1,
                    created_ts: now_ms(),
                    name: "concurrent".into(),
                    project: None,
                    parent: None,
                },
            )
            .expect("create session");
            let mut log = log;
            log.append(now_ms(), Entry::Info { text: "created by one worker".into() }).expect("append");
            println!("{{\"outcome\":\"created\",\"pid\":{}}}", std::process::id());
            std::io::stdout().flush().ok();
            std::thread::sleep(Duration::from_millis(hold_ms));
            let _ = lease.release();
        }
        LeaseOutcome::Held { owner_pid, .. } => {
            println!("{{\"outcome\":\"existing\",\"pid\":{},\"owner_pid\":{owner_pid}}}", std::process::id());
            std::io::stdout().flush().ok();
            std::thread::sleep(Duration::from_millis(hold_ms.min(300)));
        }
    }
}
