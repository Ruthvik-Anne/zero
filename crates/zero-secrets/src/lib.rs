//! `zero-secrets` — credential store, OS keychain adapter, encrypted fallback,
//! project vault, tags, transport substitution, prompts, scans, and `.env`
//! rules.
//!
//! Contract (`architecture.md` §5): must not expose values to callers outside
//! the substitution chokepoint.

pub mod credentials;
pub mod flows;
pub mod keychain;
pub mod signin;
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
pub use signin::{
    load_tokens, new_agent_host_id, open_system_browser, pkce, poll_device_token,
    request_device_code, store_tokens, Authorization, Callback, ChatGptSignIn, DeviceCode,
    DeviceSignIn, HttpResponse, LoopbackListener, OAuthClient, Pkce, ReqwestTransport, TermsEntry,
    TermsRegistry, TokenSet, Transport, CHATGPT_CALLBACK_PATH, CHATGPT_DYNAMIC_CLIENT,
    CHATGPT_RESOURCE, CHATGPT_SCOPES, OPENCODE_CLIENT_ID, OPENCODE_CONSOLE, TERMS_CHECKED_ON,
};
pub use vault::{
    assert_no_leak, audit_use, ensure_env_rules, parse_placeholders, precommit_denies_env,
    substitute, Binding, Destination, Scope, SecretHandle, Vault,
};
