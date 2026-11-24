//! `zero-tui` — renderer, widgets, virtual terminal harness, themes.
//!
//! Contract (`architecture.md` §5): must not make policy decisions.

pub mod vterm;

pub use vterm::Terminal;
