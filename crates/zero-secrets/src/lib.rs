//! `zero-secrets` — credential store, encrypted fallback, project vault, tags,
//! transport substitution, and `.env` rules.
//!
//! Contract (`architecture.md` §5): must not expose values to callers outside
//! the substitution chokepoint.

pub mod credentials;
pub mod vault;

pub use vault::{
    assert_no_leak, audit_use, ensure_env_rules, parse_placeholders, precommit_denies_env, substitute,
    Binding, Destination, Scope, SecretHandle, Vault,
};
pub use credentials::{
    import_plaintext, scrubbed_env, Credential, EncryptedStore, Keychain, MemoryKeychain,
    RefreshLock,
};
