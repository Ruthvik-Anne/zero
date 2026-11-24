//! `zero-daemon` — supervisor, protocol server, leases, adoption, and updates.
//!
//! Contract (`architecture.md` §5): must not render anything.

pub mod supervisor;

pub use supervisor::{Supervisor, SupervisorConfig, WorkerRecord, WorkerStatus};
