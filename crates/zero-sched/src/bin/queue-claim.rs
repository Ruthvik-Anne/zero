//! Claim one durable-queue call, write a marker, then sleep. Used by the
//! crash test: killing this process must not lead to a second dispatch.

use zero_sched::DurableQueue;

fn main() {
    let mut args = std::env::args().skip(1);
    let queue_path = args.next().expect("usage: queue-claim <queue> <marker>");
    let marker = args.next().expect("usage: queue-claim <queue> <marker>");
    let mut queue = DurableQueue::open(&queue_path).expect("open queue");
    match queue.claim_next("crashing-worker", 0).expect("claim") {
        Some((call, generation)) => {
            std::fs::write(&marker, format!("{} {generation}", call.id)).expect("marker");
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
        None => {
            std::fs::write(&marker, "none").expect("marker");
        }
    }
}
