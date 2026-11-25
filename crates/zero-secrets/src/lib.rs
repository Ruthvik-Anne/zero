//! `zero-secrets` — credential store, encrypted fallback, project vault, tags,
//! transport substitution, and `.env` rules.
//!
//! Contract (`architecture.md` §5): must not expose values to callers outside
//! the substitution chokepoint.

pub mod credentials;

pub use credentials::{
    import_plaintext, scrubbed_env, Credential, EncryptedStore, Keychain, MemoryKeychain,
    RefreshLock,
};
