//! OS credential-store adapter (CRT-01).
//!
//! The platform store is:
//!
//! - Windows Credential Manager on Windows,
//! - Keychain Services on macOS,
//! - Secret Service over D-Bus on Linux and other non-Apple Unix (`keyring`'s
//!   `v1` backend, which uses pure-Rust `zbus`).
//!
//! Availability is probed at runtime. Headless hosts (CI containers, servers)
//! have no Secret Service, so the caller selects [`KeychainChoice`], which falls
//! back to the AES-256-GCM encrypted file store from [`crate::credentials`].
//!
//! Platform coverage:
//!
//! | OS | Store | Test |
//! |---|---|---|
//! | Windows | Credential Manager | runs natively, required in the `keychain (windows)` CI job |
//! | Linux | Secret Service | runs under `dbus-run-session` + `gnome-keyring`, required in the `keychain (linux)` CI job |
//! | macOS | Keychain Services | compiled; the native test is skipped because hosted runners can show a keychain prompt |
//!
//! The native test asserts a real round trip when the store is usable. Set
//! `ZERO_REQUIRE_KEYCHAIN=1` to turn an unavailable store into a failure; the
//! dedicated CI jobs set it so the native path can never silently skip.

use crate::credentials::{Credential, EncryptedStore, Keychain};
use std::path::{Path, PathBuf};
use zero_types::error::{ErrorCode, Result, ZeroError};

const SERVICE: &str = "zero.credentials";

/// The platform-native credential store.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsKeychain;

impl OsKeychain {
    /// Initialization status of the platform store. Touching this initializes it.
    pub fn status() -> &'static std::result::Result<(), keyring::Error> {
        keyring::Entry::store_status()
    }

    /// Name of the native backend used on this platform.
    pub fn backend_name(&self) -> &'static str {
        native_backend_name()
    }

    /// True when a credential can actually be written and read back.
    ///
    /// A store can initialize but still be unusable (locked keyring, no D-Bus
    /// session), so this performs a real probe under a unique account name.
    pub fn available() -> bool {
        let account = probe_account();
        let entry = match keyring::Entry::new(SERVICE, &account) {
            Ok(entry) => entry,
            Err(_) => return false,
        };
        if entry.set_password("probe").is_err() {
            return false;
        }
        let readable = entry.get_password().map(|v| v == "probe").unwrap_or(false);
        let _ = entry.delete_credential();
        readable
    }

    fn entry(provider: &str, account: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(SERVICE, &format!("{provider}/{account}"))
            .map_err(|e| ZeroError::new(ErrorCode::Unavailable, format!("keychain: {e}")))
    }

    fn map_error(e: keyring::Error) -> ZeroError {
        match e {
            keyring::Error::NoEntry => ZeroError::new(ErrorCode::NotFound, "keychain entry"),
            other => ZeroError::new(ErrorCode::Unavailable, format!("keychain: {other}")),
        }
    }
}

impl Keychain for OsKeychain {
    fn get(&self, provider: &str, account: &str) -> Result<Option<String>> {
        match Self::entry(provider, account)?.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(Self::map_error(e)),
        }
    }

    fn set(&mut self, provider: &str, account: &str, secret: &str) -> Result<()> {
        Self::entry(provider, account)?
            .set_password(secret)
            .map_err(Self::map_error)
    }

    fn delete(&mut self, provider: &str, account: &str) -> Result<()> {
        match Self::entry(provider, account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(Self::map_error(e)),
        }
    }
}

/// The encrypted file store exposed through the [`Keychain`] trait, so callers
/// do not need to know whether a native store exists.
#[derive(Debug)]
pub struct EncryptedKeychain {
    store: EncryptedStore,
    path: PathBuf,
}

impl EncryptedKeychain {
    pub fn open(path: impl AsRef<Path>, passphrase: Option<&str>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let store = EncryptedStore::open(&path, passphrase)?;
        Ok(Self { store, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn store(&self) -> &EncryptedStore {
        &self.store
    }
}

impl Keychain for EncryptedKeychain {
    fn get(&self, provider: &str, account: &str) -> Result<Option<String>> {
        // Reads are served from the in-memory view; a write is required to
        // reload the file. Callers that need a fresh read reopen the store.
        let _ = self.store.accounts(provider);
        self.store.get_immutable(provider, account)
    }

    fn set(&mut self, provider: &str, account: &str, secret: &str) -> Result<()> {
        self.store.set(provider, account, secret)
    }

    fn delete(&mut self, provider: &str, account: &str) -> Result<()> {
        self.store.delete(provider, account)
    }
}

/// Which credential backend this host uses.
#[derive(Debug)]
pub enum KeychainChoice {
    Native(OsKeychain),
    Encrypted(EncryptedKeychain),
}

impl KeychainChoice {
    /// Prefer the OS store; fall back to the encrypted file when the OS store is
    /// unavailable. `data_dir` holds `credentials.enc` and, in unattended mode,
    /// the machine key file.
    pub fn select(data_dir: impl AsRef<Path>) -> Result<Self> {
        Self::select_with(OsKeychain::available(), data_dir)
    }

    /// Deterministic variant used by tests and by probes that already know the
    /// native store is unusable.
    pub fn select_with(native_available: bool, data_dir: impl AsRef<Path>) -> Result<Self> {
        if native_available {
            Ok(Self::Native(OsKeychain))
        } else {
            let path = data_dir.as_ref().join("credentials.enc");
            Ok(Self::Encrypted(EncryptedKeychain::open(path, None)?))
        }
    }

    pub fn is_native(&self) -> bool {
        matches!(self, Self::Native(_))
    }

    pub fn backend_name(&self) -> &'static str {
        match self {
            Self::Native(_) => native_backend_name(),
            Self::Encrypted(_) => "encrypted-file",
        }
    }
}

impl Keychain for KeychainChoice {
    fn get(&self, provider: &str, account: &str) -> Result<Option<String>> {
        match self {
            Self::Native(kc) => kc.get(provider, account),
            Self::Encrypted(kc) => kc.get(provider, account),
        }
    }

    fn set(&mut self, provider: &str, account: &str, secret: &str) -> Result<()> {
        match self {
            Self::Native(kc) => kc.set(provider, account, secret),
            Self::Encrypted(kc) => kc.set(provider, account, secret),
        }
    }

    fn delete(&mut self, provider: &str, account: &str) -> Result<()> {
        match self {
            Self::Native(kc) => kc.delete(provider, account),
            Self::Encrypted(kc) => kc.delete(provider, account),
        }
    }
}

/// Name of the native backend used on this platform.
pub const fn native_backend_name() -> &'static str {
    #[cfg(windows)]
    {
        "windows-credential-manager"
    }
    #[cfg(target_os = "macos")]
    {
        "macos-keychain"
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        "linux-secret-service"
    }
    #[cfg(not(any(windows, unix)))]
    {
        "unsupported"
    }
}

/// Kept so callers can talk about credentials uniformly.
pub fn probe_credential(provider: &str, account: &str) -> Credential {
    Credential { provider: provider.into(), account: account.into() }
}

fn probe_account() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("probe-{}-{nanos}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn require_native() -> bool {
        std::env::var("ZERO_REQUIRE_KEYCHAIN").as_deref() == Ok("1")
    }

    #[test]
    fn native_store_round_trips_on_windows_and_linux() {
        // macOS hosted runners can raise a Keychain prompt; the platform store
        // there is covered by compilation and by the fallback tests below.
        if cfg!(target_os = "macos") {
            eprintln!("skipped: macOS keychain prompts are not driven in tests");
            return;
        }
        let required = require_native();
        if !OsKeychain::available() {
            assert!(
                !required,
                "ZERO_REQUIRE_KEYCHAIN=1 but the {} store is unavailable: {:?}",
                native_backend_name(),
                OsKeychain::status()
            );
            eprintln!("skipped: the native store is unavailable in this environment");
            return;
        }
        let account = probe_account();
        let provider = "zero-test";
        let mut keychain = OsKeychain;
        keychain.set(provider, &account, "native-secret-value").unwrap();
        assert_eq!(
            keychain.get(provider, &account).unwrap().as_deref(),
            Some("native-secret-value")
        );
        assert_eq!(keychain.backend_name(), native_backend_name());
        keychain.delete(provider, &account).unwrap();
        assert!(keychain.get(provider, &account).unwrap().is_none());
        let _ = probe_credential(provider, &account);
    }

    #[test]
    fn selection_falls_back_to_the_encrypted_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut choice = KeychainChoice::select_with(false, dir.path()).unwrap();
        assert!(!choice.is_native());
        assert_eq!(choice.backend_name(), "encrypted-file");
        choice.set("openai", "default", "sk-fallback-secret").unwrap();
        assert_eq!(choice.get("openai", "default").unwrap().as_deref(), Some("sk-fallback-secret"));
        let path = dir.path().join("credentials.enc");
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("sk-fallback-secret"), "the fallback never writes plaintext");
        assert!(raw.contains("\"machine\""), "the fallback is machine-bound for unattended start");
    }

    #[test]
    fn encrypted_keychain_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut kc = EncryptedKeychain::open(dir.path().join("c.enc"), Some("pass phrase")).unwrap();
            kc.set("anthropic", "work", "sk-ant-persisted").unwrap();
        }
        let mut reopened = EncryptedKeychain::open(dir.path().join("c.enc"), Some("pass phrase")).unwrap();
        assert_eq!(reopened.get("anthropic", "work").unwrap().as_deref(), Some("sk-ant-persisted"));
        reopened.delete("anthropic", "work").unwrap();
        assert!(reopened.get("anthropic", "work").unwrap().is_none());
    }

    #[test]
    fn the_choice_routes_each_operation_to_its_backend() {
        let dir = tempfile::tempdir().unwrap();
        let mut native = KeychainChoice::select_with(true, dir.path()).unwrap();
        assert!(native.is_native());
        assert_eq!(native.backend_name(), native_backend_name());
        // Only exercise the native backend when it is genuinely usable.
        if OsKeychain::available() {
            native.set("zero-test", "routing", "value").unwrap();
            assert_eq!(native.get("zero-test", "routing").unwrap().as_deref(), Some("value"));
            native.delete("zero-test", "routing").unwrap();
        }
        let _ = EncryptedKeychain::open(dir.path().join("unused.enc"), None);
    }
}
