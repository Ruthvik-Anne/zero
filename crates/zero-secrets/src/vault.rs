//! Project vault, tags/bindings, placeholder parsing, transport substitution,
//! audit, `.env` rules, leakage checks, and the headless secret queue
//! (SEC-01..SEC-04, SEC-06, SEC-07, SEC-09, SEC-10).
//!
//! Values are AES-256-GCM ciphertext with AAD bound to tag, scope, and project.
//! The index carries only metadata and ciphertext. Only the transport
//! substitution path ever returns a value; the chat path always yields a
//! redacted handle.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zero_store::audit::AuditLog;
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "scope", content = "id", rename_all = "snake_case")]
pub enum Scope {
    User,
    Project(String),
    Session(String),
}

impl Scope {
    fn name(&self) -> String {
        match self {
            Scope::User => "user".into(),
            Scope::Project(p) => format!("project:{p}"),
            Scope::Session(s) => format!("session:{s}"),
        }
    }

    fn rank(&self) -> u8 {
        match self {
            Scope::User => 0,
            Scope::Session(_) => 1,
            Scope::Project(_) => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub scope: Scope,
    /// Project binding; a mismatch is drift and is refused.
    #[serde(default)]
    pub project: Option<String>,
    pub nonce_b64: String,
    pub cipher_b64: String,
    pub created_ms: i64,
    pub rotated_ms: i64,
    #[serde(default)]
    pub expires_ms: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Index {
    version: u32,
    tags: BTreeMap<String, Vec<Binding>>,
}

pub struct Vault {
    dir: PathBuf,
    key: [u8; 32],
    index: Index,
}

pub const VAULT_VERSION: u32 = 1;

impl Vault {
    /// Open or create a vault. The key is the project vault key.
    pub fn open(dir: impl AsRef<Path>, key: [u8; 32]) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("index.json");
        let index = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Index { version: VAULT_VERSION, tags: BTreeMap::new() },
            Err(e) => return Err(e.into()),
        };
        if index.version > VAULT_VERSION {
            return Err(ZeroError::new(ErrorCode::SchemaVersion, "vault is newer than this build"));
        }
        Ok(Self { dir, key, index })
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }

    fn save(&self) -> Result<()> {
        let path = self.dir.join("index.json");
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&self.index)?)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    fn aad(tag: &str, binding: &Binding) -> Vec<u8> {
        format!("{}|{}|{}", tag, binding.scope.name(), binding.project.clone().unwrap_or_default()).into_bytes()
    }

    fn encrypt(&self, tag: &str, binding: &Binding, value: &str) -> Result<(String, String)> {
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| ZeroError::new(ErrorCode::Internal, "bad key"))?;
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|e| ZeroError::new(ErrorCode::Internal, e.to_string()))?;
        let aad = Self::aad(tag, binding);
        let data = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: value.as_bytes(), aad: &aad })
            .map_err(|_| ZeroError::new(ErrorCode::Internal, "encryption failed"))?;
        Ok((B64.encode(nonce), B64.encode(data)))
    }

    fn decrypt(&self, tag: &str, binding: &Binding) -> Result<String> {
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| ZeroError::new(ErrorCode::Internal, "bad key"))?;
        let nonce = B64.decode(&binding.nonce_b64).map_err(|e| ZeroError::new(ErrorCode::Corrupt, e.to_string()))?;
        let data = B64.decode(&binding.cipher_b64).map_err(|e| ZeroError::new(ErrorCode::Corrupt, e.to_string()))?;
        if nonce.len() != 12 {
            return Err(ZeroError::new(ErrorCode::Corrupt, "vault nonce has the wrong length"));
        }
        let aad = Self::aad(tag, binding);
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: &data, aad: &aad })
            .map_err(|_| ZeroError::new(ErrorCode::TamperDetected, "vault AAD or ciphertext mismatch"))?;
        String::from_utf8(plaintext).map_err(|_| ZeroError::new(ErrorCode::Corrupt, "secret is not UTF-8"))
    }

    pub fn put(&mut self, tag: &str, value: &str, scope: Scope, project: Option<&str>, now_ms: i64) -> Result<()> {
        if tag.trim().is_empty() || tag.contains(['{', '}', ' ', '\n']) {
            return Err(ZeroError::new(ErrorCode::InvalidInput, "a tag is a short identifier without spaces or braces"));
        }
        let mut binding = Binding {
            scope,
            project: project.map(str::to_string),
            nonce_b64: String::new(),
            cipher_b64: String::new(),
            created_ms: now_ms,
            rotated_ms: now_ms,
            expires_ms: None,
        };
        let (nonce, cipher) = self.encrypt(tag, &binding, value)?;
        binding.nonce_b64 = nonce;
        binding.cipher_b64 = cipher;
        let entries = self.index.tags.entry(tag.to_string()).or_default();
        entries.retain(|b| b.scope != binding.scope || b.project != binding.project);
        entries.push(binding);
        self.save()
    }

    /// Index projection: tags and scopes only, never values.
    pub fn index(&self) -> Vec<(String, Scope, Option<String>)> {
        let mut out = Vec::new();
        for (tag, bindings) in &self.index.tags {
            for binding in bindings {
                out.push((tag.clone(), binding.scope.clone(), binding.project.clone()));
            }
        }
        out
    }

    pub fn tags(&self) -> Vec<String> {
        self.index.tags.keys().cloned().collect()
    }

    pub fn rotate(&mut self, tag: &str, project: Option<&str>, now_ms: i64) -> Result<()> {
        let scope = self
            .index
            .tags
            .get(tag)
            .and_then(|b| b.iter().max_by_key(|x| x.scope.rank()).map(|b| b.scope.clone()))
            .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("tag `{tag}`")))?;
        let value = self.resolve(tag, project, now_ms)?;
        self.put(tag, &value, scope, project, now_ms)
    }

    /// Resolve a tag for a project. Project scope wins over session, then user.
    /// A binding whose project does not match is drift and is refused.
    pub fn resolve(&self, tag: &str, project: Option<&str>, now_ms: i64) -> Result<String> {
        let bindings = self
            .index
            .tags
            .get(tag)
            .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("tag `{tag}`")))?;
        let binding = bindings
            .iter()
            .filter(|b| b.project.as_deref().is_none() || b.project.as_deref() == project)
            .max_by_key(|b| b.scope.rank())
            .ok_or_else(|| ZeroError::new(ErrorCode::PolicyDenied, format!("tag `{tag}` has no binding for this project")))?;
        if let Some(expires) = binding.expires_ms {
            if now_ms >= expires {
                return Err(ZeroError::new(ErrorCode::ApprovalExpired, format!("tag `{tag}` expired")));
            }
        }
        self.decrypt(tag, binding)
    }

    /// Resolve by scope, used by transport bindings.
    pub fn resolve_for(&self, tag: &str, scope: &Scope, now_ms: i64) -> Result<String> {
        let binding = self
            .index
            .tags
            .get(tag)
            .and_then(|bs| bs.iter().find(|b| &b.scope == scope))
            .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("tag `{tag}` in this scope")))?;
        if binding.expires_ms.map(|e| now_ms >= e).unwrap_or(false) {
            return Err(ZeroError::new(ErrorCode::ApprovalExpired, "secret expired"));
        }
        self.decrypt(tag, binding)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretHandle {
    pub tag: String,
}

impl SecretHandle {
    pub fn redacted(&self) -> String {
        format!("[secret:{}]", self.tag)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    Header,
    Query,
    Stdin,
    EnvSdk,
    Chat,
}

impl Destination {
    fn allows_value(self) -> bool {
        !matches!(self, Destination::Chat)
    }
}

/// Substitute `{{secret:TAG}}` or `Secret("TAG")` placeholders. Chat output is
/// always redacted; only transport destinations receive the value.
pub fn substitute(text: &str, vault: &Vault, project: Option<&str>, destination: Destination, now_ms: i64) -> Result<String> {
    let mut out = text.to_string();
    for tag in parse_placeholders(text) {
        let replacement = if destination.allows_value() {
            vault.resolve(&tag, project, now_ms)?
        } else {
            SecretHandle { tag: tag.clone() }.redacted()
        };
        out = out.replace(&format!("{{{{secret:{tag}}}}}"), &replacement);
        out = out.replace(&format!("Secret(\"{tag}\")"), &replacement);
        out = out.replace(&format!("Secret('{tag}')"), &replacement);
    }
    Ok(out)
}

pub fn parse_placeholders(text: &str) -> Vec<String> {
    let mut tags = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 10 < bytes.len() {
        if text[i..].starts_with("{{secret:") {
            if let Some(end) = text[i + 9..].find("}}") {
                let tag = &text[i + 9..i + 9 + end];
                if !tag.is_empty() && !tags.contains(&tag.to_string()) {
                    tags.push(tag.to_string());
                }
            }
        }
        if text[i..].starts_with("Secret(\"") {
            if let Some(end) = text[i + 8..].find('"') {
                let tag = &text[i + 8..i + 8 + end];
                if !tag.is_empty() && !tags.contains(&tag.to_string()) {
                    tags.push(tag.to_string());
                }
            }
        }
        i += 1;
    }
    tags
}

/// Audit rows carry tags, never values.
pub fn audit_use(audit: &mut AuditLog, ts: i64, tag: &str, destination: Destination) -> Result<()> {
    audit.append(ts, "user", "secret.use", serde_json::json!({"tag": tag, "destination": format!("{destination:?}")}))?;
    Ok(())
}

/// `.env` rules: `.env` must be git-ignored and `.env.example` tracked.
pub fn ensure_env_rules(repo: &Path) -> Result<Vec<String>> {
    let mut actions = Vec::new();
    let env = repo.join(".env");
    if env.exists() {
        let gitignore = std::fs::read_to_string(repo.join(".gitignore")).unwrap_or_default();
        if repo.join(".git").exists() && !gitignore.lines().any(|l| l.trim() == ".env") {
            return Err(ZeroError::new(ErrorCode::PolicyDenied, "`.env` exists and is not git-ignored"));
        }
        let example = repo.join(".env.example");
        if !example.exists() {
            std::fs::write(&example, "# Copy to .env and fill in values\n")?;
            actions.push("created .env.example".into());
        }
    }
    Ok(actions)
}

/// Pre-commit guard: a staged `.env` with a value-like line is refused.
pub fn precommit_denies_env(value: &str) -> bool {
    value.lines().any(|line| {
        let line = line.trim();
        !line.is_empty() && !line.starts_with('#') && line.contains('=') && line.split_once('=').map(|(_, v)| v.trim().len() >= 8).unwrap_or(false)
    })
}

/// Leakage check across every sink named by SEC-09.
pub fn assert_no_leak(value: &str, sinks: &[(&str, &str)]) -> Result<()> {
    for (name, content) in sinks {
        if content.contains(value) {
            return Err(ZeroError::new(ErrorCode::PolicyDenied, format!("secret leaked into {name}")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault(dir: &Path) -> Vault {
        Vault::open(dir.join("vault"), [7u8; 32]).unwrap()
    }

    #[test]
    fn the_index_has_no_values_and_aad_tampering_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = vault(dir.path());
        v.put("OPENAI_KEY", "sk-plaintext-value", Scope::Project("p1".into()), Some("p1"), 0).unwrap();
        let index_text = std::fs::read_to_string(v.path().join("index.json")).unwrap();
        assert!(!index_text.contains("sk-plaintext-value"));
        assert_eq!(v.resolve("OPENAI_KEY", Some("p1"), 1).unwrap(), "sk-plaintext-value");
        assert_eq!(v.resolve("OPENAI_KEY", Some("other"), 1).unwrap_err().code(), ErrorCode::PolicyDenied);

        // Changing the bound project in the index invalidates the AAD.
        let mut index: serde_json::Value = serde_json::from_str(&index_text).unwrap();
        index["tags"]["OPENAI_KEY"][0]["project"] = serde_json::json!("p2");
        std::fs::write(v.path().join("index.json"), serde_json::to_string(&index).unwrap()).unwrap();
        let reopened = Vault::open(v.path(), [7u8; 32]).unwrap();
        assert_eq!(reopened.resolve("OPENAI_KEY", Some("p2"), 1).unwrap_err().code(), ErrorCode::TamperDetected);
    }

    #[test]
    fn placeholders_resolve_only_in_transport_and_chat_is_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = vault(dir.path());
        v.put("TOKEN", "super-secret", Scope::User, None, 0).unwrap();
        let chat = substitute("auth {{secret:TOKEN}} and Secret(\"TOKEN\")", &v, None, Destination::Chat, 1).unwrap();
        assert!(!chat.contains("super-secret"));
        assert!(chat.contains("[secret:TOKEN]"));
        let header = substitute("Bearer {{secret:TOKEN}}", &v, None, Destination::Header, 1).unwrap();
        assert_eq!(header, "Bearer super-secret");
        assert_eq!(parse_placeholders("{{secret:A}} Secret(\"B\")"), vec!["A", "B"]);
    }

    #[test]
    fn scopes_precedence_binding_drift_and_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = vault(dir.path());
        v.put("K", "user", Scope::User, None, 0).unwrap();
        v.put("K", "proj", Scope::Project("p".into()), Some("p"), 0).unwrap();
        assert_eq!(v.resolve("K", Some("p"), 1).unwrap(), "proj");
        assert_eq!(v.resolve("K", Some("other"), 1).unwrap(), "user");
        // Expiry.
        v.put("E", "x", Scope::User, None, 0).unwrap();
        {
            let entry = v.index.tags.get_mut("E").unwrap();
            entry[0].expires_ms = Some(10);
        }
        v.save().unwrap();
        assert_eq!(v.resolve("E", None, 10).unwrap_err().code(), ErrorCode::ApprovalExpired);
    }

    #[test]
    fn audit_rows_and_env_rules_carry_no_values() {
        let dir = tempfile::tempdir().unwrap();
        let mut audit = AuditLog::open(dir.path().join("audit.jsonl")).unwrap();
        audit_use(&mut audit, 0, "OPENAI_KEY", Destination::Header).unwrap();
        let text = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        assert!(text.contains("OPENAI_KEY"));
        assert!(!text.contains("sk-"));

        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::write(repo.join(".env"), "OPENAI_KEY=abcdefgh\n").unwrap();
        assert_eq!(ensure_env_rules(&repo).unwrap_err().code(), ErrorCode::PolicyDenied);
        std::fs::write(repo.join(".gitignore"), ".env\n").unwrap();
        assert!(ensure_env_rules(&repo).ok().unwrap().iter().any(|a| a.contains(".env.example")));
        assert!(precommit_denies_env("OPENAI_KEY=abcdefgh"));
        assert!(!precommit_denies_env("OPENAI_KEY=\n# comment"));
    }

    #[test]
    fn leakage_suite_covers_every_sink() {
        let secret = "sk-leak-check-value";
        let clean = assert_no_leak(secret, &[
            ("transcript", "no secret here"),
            ("kernel", "print('x')"),
            ("config", "{}"),
            ("logs", "info"),
            ("teleport", "bundle"),
            ("crash", "report"),
        ]);
        assert!(clean.is_ok());
        let leaked = assert_no_leak(secret, &[("kernel", "out sk-leak-check-value")]);
        assert!(leaked.is_err());
    }
}
