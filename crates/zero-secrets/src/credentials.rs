//! Credential store (CRT-01..CRT-06): encrypted file fallback, named accounts,
//! scrubbed child environments, a single refresher lock, plaintext import with
//! redaction, and machine-bound unattended unlock.
//!
//! The OS keychain integration is expressed as a [`Keychain`] trait; the tested
//! implementation here is the AES-256-GCM encrypted fallback required when no
//! keychain is available.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub provider: String,
    pub account: String,
}

pub trait Keychain {
    fn get(&self, provider: &str, account: &str) -> Result<Option<String>>;
    fn set(&mut self, provider: &str, account: &str, secret: &str) -> Result<()>;
    fn delete(&mut self, provider: &str, account: &str) -> Result<()>;
}

#[derive(Debug, Default, Clone)]
pub struct MemoryKeychain {
    entries: BTreeMap<(String, String), String>,
}

impl Keychain for MemoryKeychain {
    fn get(&self, provider: &str, account: &str) -> Result<Option<String>> {
        Ok(self.entries.get(&(provider.into(), account.into())).cloned())
    }
    fn set(&mut self, provider: &str, account: &str, secret: &str) -> Result<()> {
        self.entries.insert((provider.into(), account.into()), secret.into());
        Ok(())
    }
    fn delete(&mut self, provider: &str, account: &str) -> Result<()> {
        self.entries.remove(&(provider.into(), account.into()));
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    version: u32,
    kdf: String,
    salt_b64: String,
    wrapped_key_b64: String,
    data_nonce_b64: String,
    data_b64: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Contents {
    active: BTreeMap<String, String>,
    secrets: BTreeMap<String, BTreeMap<String, String>>,
}

impl std::fmt::Debug for EncryptedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedStore")
            .field("path", &self.path)
            .field("providers", &self.contents.secrets.len())
            .finish()
    }
}

pub struct EncryptedStore {
    path: PathBuf,
    key: [u8; 32],
    contents: Contents,
}

impl EncryptedStore {
    /// Open or create the encrypted fallback. `passphrase=None` uses a
    /// machine-bound key file (mode 0600) for unattended unlock.
    pub fn open(path: impl AsRef<Path>, passphrase: Option<&str>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            let envelope: Envelope = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
            let key = unwrap_key(&path, &envelope, passphrase)?;
            let contents = decrypt_contents(&key, &envelope)?;
            Ok(Self { path, key, contents })
        } else {
            let mut key = [0u8; 32];
            getrandom::getrandom(&mut key).map_err(|e| ZeroError::new(ErrorCode::Internal, e.to_string()))?;
            let salt = random_bytes(16);
            let kek = derive_kek(passphrase, &salt, &path)?;
            let wrapped = encrypt(&kek, &key, b"zero-credential-key")?;
            let contents = Contents::default();
            let (nonce, data) = encrypt_parts(&key, &serde_json::to_vec(&contents)?, b"zero-credentials")?;
            let envelope = Envelope {
                version: 1,
                kdf: if passphrase.is_some() { "argon2id".into() } else { "machine".into() },
                salt_b64: B64.encode(&salt),
                wrapped_key_b64: B64.encode(&wrapped),
                data_nonce_b64: B64.encode(&nonce),
                data_b64: B64.encode(&data),
            };
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, serde_json::to_vec_pretty(&envelope)?)?;
            std::fs::rename(&tmp, &path)?;
            Ok(Self { path, key, contents })
        }
    }

    pub fn set(&mut self, provider: &str, account: &str, secret: &str) -> Result<()> {
        self.contents
            .secrets
            .entry(provider.into())
            .or_default()
            .insert(account.into(), secret.into());
        self.contents.active.entry(provider.into()).or_insert_with(|| account.into());
        self.save()
    }

    pub fn get(&mut self, provider: &str, account: &str) -> Result<Option<String>> {
        Ok(self.contents.secrets.get(provider).and_then(|a| a.get(account)).cloned())
    }

    /// Read without a mutable borrow, for `&self` trait implementations.
    pub fn get_immutable(&self, provider: &str, account: &str) -> Result<Option<String>> {
        Ok(self.contents.secrets.get(provider).and_then(|a| a.get(account)).cloned())
    }

    pub fn accounts(&self, provider: &str) -> Vec<String> {
        self.contents.secrets.get(provider).map(|a| a.keys().cloned().collect()).unwrap_or_default()
    }

    pub fn active(&self, provider: &str) -> Option<String> {
        self.contents.active.get(provider).cloned()
    }

    pub fn switch(&mut self, provider: &str, account: &str) -> Result<()> {
        if !self.contents.secrets.get(provider).map(|a| a.contains_key(account)).unwrap_or(false) {
            return Err(ZeroError::new(ErrorCode::NotFound, format!("account `{account}`")));
        }
        self.contents.active.insert(provider.into(), account.into());
        self.save()
    }

    pub fn rename(&mut self, provider: &str, from: &str, to: &str) -> Result<()> {
        let accounts = self.contents.secrets.get_mut(provider).ok_or_else(|| ZeroError::new(ErrorCode::NotFound, "provider"))?;
        let secret = accounts.remove(from).ok_or_else(|| ZeroError::new(ErrorCode::NotFound, "account"))?;
        accounts.insert(to.into(), secret);
        if self.contents.active.get(provider).map(String::as_str) == Some(from) {
            self.contents.active.insert(provider.into(), to.into());
        }
        self.save()
    }

    pub fn delete(&mut self, provider: &str, account: &str) -> Result<()> {
        if let Some(accounts) = self.contents.secrets.get_mut(provider) {
            accounts.remove(account);
        }
        if self.contents.active.get(provider).map(String::as_str) == Some(account) {
            self.contents.active.remove(provider);
        }
        self.save()
    }

    pub fn sign_out(&mut self, provider: &str, account: &str) -> Result<()> {
        self.delete(provider, account)
    }

    pub fn set_active_secret(&mut self, provider: &str, secret: &str) -> Result<()> {
        let account = self.active(provider).ok_or_else(|| ZeroError::new(ErrorCode::NotFound, "no active account"))?;
        self.set(provider, &account, secret)
    }

    fn save(&self) -> Result<()> {
        let envelope_text = std::fs::read_to_string(&self.path)?;
        let mut envelope: Envelope = serde_json::from_str(&envelope_text)?;
        let (nonce, data) = encrypt_parts(&self.key, &serde_json::to_vec(&self.contents)?, b"zero-credentials")?;
        envelope.data_nonce_b64 = B64.encode(&nonce);
        envelope.data_b64 = B64.encode(&data);
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&envelope)?)?;
        std::fs::rename(&tmp, &self.path)?;
        restrict(&self.path)?;
        restrict(&self.path.with_extension("machine"))?;
        Ok(())
    }
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    let _ = getrandom::getrandom(&mut buf);
    buf
}

fn derive_kek(passphrase: Option<&str>, salt: &[u8], path: &Path) -> Result<[u8; 32]> {
    match passphrase {
        Some(passphrase) => {
            let mut out = [0u8; 32];
            Argon2::default()
                .hash_password_into(passphrase.as_bytes(), salt, &mut out)
                .map_err(|e| ZeroError::new(ErrorCode::Internal, format!("argon2: {e}")))?;
            Ok(out)
        }
        None => {
            let machine = path.with_extension("machine");
            let bytes = if machine.exists() {
                std::fs::read(&machine)?
            } else {
                let bytes = random_bytes(32);
                std::fs::write(&machine, &bytes)?;
                restrict(&machine)?;
                bytes
            };
            let mut out = [0u8; 32];
            out.copy_from_slice(blake3::hash(&bytes).as_bytes());
            Ok(out)
        }
    }
}

fn unwrap_key(path: &Path, envelope: &Envelope, passphrase: Option<&str>) -> Result<[u8; 32]> {
    if envelope.kdf == "machine" && passphrase.is_some() {
        return Err(ZeroError::new(ErrorCode::InvalidInput, "this store unlocks with a machine key"));
    }
    if envelope.kdf == "argon2id" && passphrase.is_none() {
        return Err(ZeroError::new(ErrorCode::Unavailable, "a passphrase is required to unlock"));
    }
    let salt = B64.decode(&envelope.salt_b64).map_err(|e| ZeroError::new(ErrorCode::Corrupt, e.to_string()))?;
    let kek = derive_kek(passphrase, &salt, path)?;
    let wrapped = B64.decode(&envelope.wrapped_key_b64).map_err(|e| ZeroError::new(ErrorCode::Corrupt, e.to_string()))?;
    let key = decrypt(&kek, &wrapped, b"zero-credential-key")?;
    let mut out = [0u8; 32];
    if key.len() != 32 {
        return Err(ZeroError::new(ErrorCode::Corrupt, "wrapped key has the wrong length"));
    }
    out.copy_from_slice(&key);
    Ok(out)
}

fn encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let (nonce, data) = encrypt_parts(key, plaintext, aad)?;
    let mut out = nonce;
    out.extend_from_slice(&data);
    Ok(out)
}

fn encrypt_parts(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ZeroError::new(ErrorCode::Internal, "bad key"))?;
    let nonce_bytes = random_bytes(12);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let data = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| ZeroError::new(ErrorCode::Corrupt, "encryption failed"))?;
    Ok((nonce_bytes, data))
}

fn decrypt(key: &[u8], nonce_and_data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if nonce_and_data.len() < 12 {
        return Err(ZeroError::new(ErrorCode::Corrupt, "ciphertext is too short"));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ZeroError::new(ErrorCode::Internal, "bad key"))?;
    let nonce = Nonce::from_slice(&nonce_and_data[..12]);
    cipher
        .decrypt(nonce, Payload { msg: &nonce_and_data[12..], aad })
        .map_err(|_| ZeroError::new(ErrorCode::TamperDetected, "decryption failed: wrong key or tampered file"))
}

fn decrypt_contents(key: &[u8; 32], envelope: &Envelope) -> Result<Contents> {
    let nonce = B64.decode(&envelope.data_nonce_b64).map_err(|e| ZeroError::new(ErrorCode::Corrupt, e.to_string()))?;
    let data = B64.decode(&envelope.data_b64).map_err(|e| ZeroError::new(ErrorCode::Corrupt, e.to_string()))?;
    let mut combined = nonce;
    combined.extend_from_slice(&data);
    let plaintext = decrypt(key, &combined, b"zero-credentials")?;
    Ok(serde_json::from_slice(&plaintext)?)
}

fn restrict(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    let _ = path;
    Ok(())
}

/// Remove credential-bearing variables from a child environment.
pub fn scrubbed_env(base: impl IntoIterator<Item = (String, String)>) -> BTreeMap<String, String> {
    const SECRET_MARKERS: &[&str] = &["KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"];
    base.into_iter()
        .filter(|(key, _)| {
            let upper = key.to_ascii_uppercase();
            !SECRET_MARKERS.iter().any(|m| upper.contains(m))
                || matches!(upper.as_str(), "SSH_AUTH_SOCK" | "GPG_AGENT_INFO")
        })
        .collect()
}

/// One refresher per credential across processes.
pub struct RefreshLock {
    path: PathBuf,
    held: bool,
}

impl RefreshLock {
    pub fn acquire(path: impl AsRef<Path>) -> Result<Option<Self>> {
        let path = path.as_ref().to_path_buf();
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                use std::io::Write;
                writeln!(file, "{}", std::process::id())?;
                file.sync_all()?;
                Ok(Some(Self { path, held: true }))
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn release(&mut self) {
        if self.held {
            let _ = std::fs::remove_file(&self.path);
            self.held = false;
        }
    }
}

impl Drop for RefreshLock {
    fn drop(&mut self) {
        self.release();
    }
}

/// Import a plaintext JSON credential map, then trash the old file.
pub fn import_plaintext(
    path: impl AsRef<Path>,
    store: &mut EncryptedStore,
    trash: &zero_fs::TrashService,
) -> Result<usize> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path)?;
    let map: BTreeMap<String, String> = serde_json::from_str(&text)?;
    let mut count = 0;
    for (key, value) in map {
        let (provider, account) = key.split_once('/').unwrap_or((&key, "default"));
        store.set(provider, account, &value)?;
        count += 1;
    }
    let _ = trash.trash(path)?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_fs::trash::TrashService;
    use zero_types::paths::Platform;
    use zero_types::protected::ProtectedPaths;

    #[test]
    fn the_no_keychain_store_never_writes_a_plaintext_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds.enc");
        let mut store = EncryptedStore::open(&path, None).unwrap();
        store.set("openai", "default", "sk-super-secret-value").unwrap();
        let bytes = std::fs::read_to_string(&path).unwrap();
        assert!(!bytes.contains("sk-super-secret-value"));
        assert!(bytes.contains("\"kdf\": \"machine\""));
        // A second open with the machine key sees the value.
        let mut reopened = EncryptedStore::open(&path, None).unwrap();
        assert_eq!(reopened.get("openai", "default").unwrap().as_deref(), Some("sk-super-secret-value"));
    }

    #[test]
    fn a_passphrase_store_requires_the_right_passphrase_and_rejects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds.enc");
        let mut store = EncryptedStore::open(&path, Some("correct horse")).unwrap();
        store.set("anthropic", "work", "sk-ant-secret").unwrap();
        assert_eq!(EncryptedStore::open(&path, Some("wrong")).unwrap_err().code(), ErrorCode::TamperDetected);
        assert_eq!(EncryptedStore::open(&path, None).unwrap_err().code(), ErrorCode::Unavailable);
        let mut ok = EncryptedStore::open(&path, Some("correct horse")).unwrap();
        assert_eq!(ok.get("anthropic", "work").unwrap().as_deref(), Some("sk-ant-secret"));

        let mut envelope: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let data = envelope["data_b64"].as_str().unwrap().to_string();
        let mut raw = B64.decode(data).unwrap();
        raw[0] ^= 0xff;
        envelope["data_b64"] = serde_json::Value::String(B64.encode(raw));
        std::fs::write(&path, serde_json::to_string(&envelope).unwrap()).unwrap();
        assert_eq!(EncryptedStore::open(&path, Some("correct horse")).unwrap_err().code(), ErrorCode::TamperDetected);
    }

    #[test]
    fn accounts_are_independent_and_switchable() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = EncryptedStore::open(dir.path().join("c.enc"), None).unwrap();
        store.set("openai", "personal", "sk-personal").unwrap();
        store.set("openai", "work", "sk-work").unwrap();
        assert_eq!(store.accounts("openai"), vec!["personal", "work"]);
        assert_eq!(store.active("openai").as_deref(), Some("personal"));
        store.switch("openai", "work").unwrap();
        assert_eq!(store.active("openai").as_deref(), Some("work"));
        assert_eq!(store.get("openai", "personal").unwrap().as_deref(), Some("sk-personal"), "switching keeps both tokens");
        store.rename("openai", "work", "office").unwrap();
        assert_eq!(store.active("openai").as_deref(), Some("office"));
        store.sign_out("openai", "personal").unwrap();
        assert_eq!(store.accounts("openai"), vec!["office"]);
    }

    #[test]
    fn child_env_is_scrubbed_and_one_refresher_wins() {
        let env = scrubbed_env([
            ("PATH".to_string(), "/bin".to_string()),
            ("OPENAI_API_KEY".to_string(), "sk-x".to_string()),
            ("GITHUB_TOKEN".to_string(), "ghp_x".to_string()),
            ("AWS_SECRET_ACCESS_KEY".to_string(), "aws".to_string()),
            ("SSH_AUTH_SOCK".to_string(), "/tmp/agent".to_string()),
        ]);
        assert_eq!(env.get("PATH"), Some(&"/bin".to_string()));
        assert_eq!(env.get("SSH_AUTH_SOCK"), Some(&"/tmp/agent".to_string()));
        assert!(!env.contains_key("OPENAI_API_KEY"));
        assert!(!env.contains_key("GITHUB_TOKEN"));
        assert!(!env.contains_key("AWS_SECRET_ACCESS_KEY"));

        let dir = tempfile::tempdir().unwrap();
        let mut first = RefreshLock::acquire(dir.path().join("refresh.lock")).unwrap().expect("first lock");
        assert!(RefreshLock::acquire(dir.path().join("refresh.lock")).unwrap().is_none(), "one refresher");
        first.release();
        assert!(RefreshLock::acquire(dir.path().join("refresh.lock")).unwrap().is_some());
    }

    #[test]
    fn plaintext_import_stores_values_and_trashes_the_old_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = EncryptedStore::open(dir.path().join("c.enc"), None).unwrap();
        let old = dir.path().join("old-creds.json");
        std::fs::write(&old, r#"{"openai/work":"sk-imported"}"#).unwrap();
        let trash = TrashService::new(ProtectedPaths::new(
            dir.path(),
            dir.path().join(".zero"),
            dir.path().join(".zero-config"),
            if cfg!(windows) { Platform::Windows } else { Platform::Linux },
        ));
        assert_eq!(import_plaintext(&old, &mut store, &trash).unwrap(), 1);
        assert_eq!(store.get("openai", "work").unwrap().as_deref(), Some("sk-imported"));
        assert!(!old.exists(), "the old plaintext file is trashed");
    }
}
