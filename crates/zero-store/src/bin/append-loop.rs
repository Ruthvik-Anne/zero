//! Child process for the kill -9 durability loop. Appends large, fsynced records
//! until killed. Every record is a complete line before the fsync returns.

use zero_store::jsonl::{Event, JsonlWriter};

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: append-loop <path>");
    let pad = "x".repeat(64 * 1024);
    // Continue the sequence from any durable records already on disk.
    let start = zero_store::jsonl::scan(&path).map(|r| r.records.len() as u64).unwrap_or(0);
    let mut writer = JsonlWriter::open(&path).expect("open log");
    let mut seq = start;
    loop {
        let event = Event {
            seq,
            ts: seq as i64,
            kind: "kill-loop".into(),
            payload: serde_json::json!({ "seq": seq, "pad": pad }),
        };
        if writer.append(&event).is_err() {
            std::process::exit(2);
        }
        seq += 1;
    }
}
