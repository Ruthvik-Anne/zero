//! `zero-tui` — cell grid, diff renderer, Unicode layout, themes, transcript,
//! input, selection, modals, status, and the virtual terminal harness.
//!
//! Contract (`architecture.md` §5): must not make policy decisions. Host-owned
//! chrome (approvals, secrets) is rendered here from host state only.

pub mod a11y;
pub mod buffer;
pub mod image;
pub mod input;
pub mod markdown;
pub mod modal;
pub mod nonblocking;
pub mod screen;
pub mod selection;
pub mod slow;
pub mod status;
pub mod style;
pub mod theme;
pub mod transcript;
pub mod unicode;
pub mod vterm;

pub use buffer::{Buffer, Cell, InvariantError};
pub use screen::{Run, Screen, SYNC_OFF, SYNC_ON};
pub use style::{Color, Style};
pub use theme::{Theme, Token};
pub use vterm::Terminal;
