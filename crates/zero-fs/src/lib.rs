//! `zero-fs` — see `architecture.md` section 5 for the module contract.
pub mod batch;
pub mod edit;
pub mod identity;
pub mod large_file;
pub mod locks;
pub mod manager;
pub mod overlay;
pub mod overwrite_journal;
pub mod purge;
pub mod retention;
pub mod trash;

pub use batch::{BatchError, BatchFile, BatchOp, BatchReceipt, BatchRunner};
pub use edit::{apply_to_text, Anchor, EditOp, EditReceipt, EditSession, FileSummary, ReceiptError};
pub use large_file::{LargeFile, RangeEdit, RangeEditor};
pub use identity::{identity, identity_or_path, FileIdentity};
pub use locks::{Lease, LockManager, Resource};
pub use overlay::{Conflict, MergeReport, Overlay};
pub use manager::{atomic_write, current_version, Change, ChangeKind, Encoding, FileManager, Handle, Newline, Version, Watcher};
pub use overwrite_journal::{OverwriteJournal, Snapshot};
pub use purge::{confirm_from_ui, HumanConfirmation, PurgePlan, PurgeReport, PurgeService};
pub use retention::{Retention, RetentionPolicy, RetentionReport};
pub use trash::{TrashOutcome, TrashService};