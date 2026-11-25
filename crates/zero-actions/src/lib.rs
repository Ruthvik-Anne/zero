//! `zero-actions` — the one action registry, schema, palette, keybindings,
//! policy-gated execution, idempotency, and audit.
//!
//! Contract (`architecture.md` §5): must not hold UI rendering.

pub mod core;
pub mod executor;
pub mod keys;
pub mod palette;
pub mod record;
pub mod registry;

pub use core::core_registry;
pub use executor::{
    parse_input, shell_prefix, ActionContext, ActionEvent, ActionOutcome, Executor, Form,
    Invocation, Surface,
};
pub use keys::Keymap;
pub use palette::{palette, search, PaletteItem};
pub use record::{ActionRecord, ApprovalRule, AuditMeta, Idempotency};
pub use registry::{ActionRegistry, Source};
