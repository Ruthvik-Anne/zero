//! `zero-secrets` — credential store, OS keychain adapter, encrypted fallback,
//! project vault, tags, transport substitution, prompts, scans, and `.env`
//! rules.
//!
//! Contract (`architecture.md` §5): must not expose values to callers outside
//! the substitution chokepoint.

pub mod credentials;
pub mod flows;
pub mod keychain;
pub mod vault;

pub use credentials::{
    import_plaintext, scrubbed_env, Credential, EncryptedStore, Keychain, MemoryKeychain,
    RefreshLock,
};
pub use flows::{
    request_secret, request_secret_headless, rotation_offer, scan_file, scan_git_history, scan_text,
    AuthMethod, Finding, PromptSurface, SecretPrompt, SignInFlow,
};
pub use keychain::{
    native_backend_name, EncryptedKeychain, KeychainChoice, OsKeychain,
};
pub use vault::{
    assert_no_leak, audit_use, ensure_env_rules, parse_placeholders, precommit_denies_env,
    substitute, Binding, Destination, Scope, SecretHandle, Vault,
};
