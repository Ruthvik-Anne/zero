//! `zero-store` — append-only logs, SQLite, blobs, migrations, sessions,
//! leases, the command journal, and durability.
//!
//! Contract (`architecture.md` §5): must not contain policy decisions.

pub mod audit;
pub mod blob;
pub mod durability;
pub mod journal;
pub mod jsonl;
pub mod lease;
pub mod migrate;
pub mod session;
pub mod sqlite;

pub use audit::{AuditLog, AuditReport};
pub use blob::{BlobId, BlobStore};
pub use journal::{ApplyOutcome, CommandJournal, CommandState};
pub use jsonl::{Event, JsonlWriter, ScanReport};
pub use lease::{Lease, LeaseOutcome};
pub use session::{AttachSnapshot, Cursor, Entry, Record, SessionLog, SessionMeta};
pub use sqlite::SqliteStore;
