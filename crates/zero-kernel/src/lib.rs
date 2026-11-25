//! `zero-kernel` — kernel lifecycle, Jupyter messaging, host requests, output
//! capture, restart/rehydrate, and limits.
//!
//! Contract (`architecture.md` §5): must not hold secrets or credentials.

pub mod host;
pub mod jupyter;

pub use host::KernelHost;
pub use jupyter::{kernel_available, ConnectionInfo, Execution, Header, KernelClient, Message};
