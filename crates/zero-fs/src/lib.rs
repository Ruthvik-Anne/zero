//! `zero-fs` — see `architecture.md` section 5 for the module contract.
pub mod overwrite_journal;
pub mod purge;
pub mod retention;
pub mod trash;

pub use overwrite_journal::{OverwriteJournal, Snapshot};
pub use purge::{confirm_from_ui, HumanConfirmation, PurgePlan, PurgeReport, PurgeService};
pub use retention::{Retention, RetentionPolicy, RetentionReport};
pub use trash::{TrashOutcome, TrashService};