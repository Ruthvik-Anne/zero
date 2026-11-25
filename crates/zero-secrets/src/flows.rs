//! Host prompt model (SEC-05), secret scanning and rotation (SEC-08), headless
//! secret queue (SEC-10), and sign-in/terms gating (SEC-11).

use serde::{Deserialize, Serialize};
use std::path::Path;
use zero_policy::headless::{QueueKind, UserQueue};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptSurface {
    Tui,
    Desktop,
    Web,
    Android,
}

impl PromptSurface {
    pub const ALL: [PromptSurface; 4] = [
        PromptSurface::Tui,
        PromptSurface::Desktop,
        PromptSurface::Web,
        PromptSurface::Android,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            PromptSurface::Tui => "tui",
            PromptSurface::Desktop => "desktop",
            PromptSurface::Web => "web",
            PromptSurface::Android => "android",
        }
    }
}

/// The host-owned view every surface renders. It carries no value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretPromptView {
    pub prompt_id: String,
    pub surface: PromptSurface,
    pub tag: String,
    pub reason: String,
    pub masked: bool,
    /// What the entry field shows; bullets only.
    pub field: String,
    pub submit: String,
    pub cancel: String,
}

impl SecretPromptView {
    pub fn is_masked(&self) -> bool {
        self.masked && self.field.chars().all(|c| c == '•')
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretPrompt {
    pub id: String,
    pub tag: String,
    pub reason: String,
    pub masked: bool,
    /// Only the host creates prompts; there is no agent constructor.
    #[serde(skip)]
    host_issued: bool,
}

/// Host-side request model. The agent has no route to this constructor.
pub fn request_secret(id: &str, tag: &str, reason: &str, now_ms: i64) -> SecretPrompt {
    let _ = now_ms;
    SecretPrompt { id: id.into(), tag: tag.into(), reason: reason.into(), masked: true, host_issued: true }
}

impl SecretPrompt {
    pub fn is_host_issued(&self) -> bool {
        self.host_issued
    }

    /// One model rendered on every surface. A prompt that was deserialized or
    /// otherwise not created by the host is refused.
    pub fn view(&self, surface: PromptSurface, typed_len: usize) -> Result<SecretPromptView> {
        if !self.host_issued {
            return Err(ZeroError::new(
                ErrorCode::PolicyDenied,
                "secret prompts are host-issued only",
            ));
        }
        Ok(SecretPromptView {
            prompt_id: self.id.clone(),
            surface,
            tag: self.tag.clone(),
            reason: self.reason.clone(),
            masked: true,
            field: "•".repeat(typed_len.max(1)),
            submit: "store".into(),
            cancel: "cancel".into(),
        })
    }

    pub fn render_masked(&self, surface: PromptSurface, typed_len: usize) -> String {
        format!(
            "[{}] {}: {} {}",
            surface.as_str(),
            self.tag,
            "•".repeat(typed_len.max(1)),
            self.reason
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub path: String,
    pub line: usize,
    pub kind: String,
}

/// Scan text for common credential patterns. Matches are reported, never echoed.
pub fn scan_text(path: &str, text: &str) -> Vec<Finding> {
    let patterns = [
        ("opencode_key", "oc_sk_"),
        ("openai_key", "sk-"),
        ("github_token", "ghp_"),
        ("aws_access_key", "AKIA"),
        ("private_key", "-----BEGIN"),
    ];
    let mut out = Vec::new();
    for (index, line) in text.lines().enumerate() {
        for (kind, needle) in patterns {
            if line.contains(needle) {
                out.push(Finding { path: path.into(), line: index + 1, kind: kind.into() });
            }
        }
    }
    out
}

pub fn scan_file(path: impl AsRef<Path>) -> Result<Vec<Finding>> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path)?;
    Ok(scan_text(&path.display().to_string(), &text))
}

/// Scan a git history (`git log -p`) for credential patterns. Returns an empty
/// list when the path is not a repository.
pub fn scan_git_history(repo: impl AsRef<Path>) -> Result<Vec<Finding>> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo.as_ref())
        .args(["log", "-p", "--all", "-n", "500", "--no-color"])
        .output();
    match output {
        Ok(output) if output.status.success() => {
            Ok(scan_text("<git-history>", &String::from_utf8_lossy(&output.stdout)))
        }
        _ => Ok(Vec::new()),
    }
}

/// Rotation offer derived from findings, one entry per affected file.
pub fn rotation_offer(findings: &[Finding]) -> Vec<String> {
    let mut files: Vec<String> = findings.iter().map(|f| f.path.clone()).collect();
    files.sort();
    files.dedup();
    files.into_iter().map(|f| format!("rotate secrets found in {f}")).collect()
}

/// Headless: queue a credential request and keep independent work moving.
pub fn request_secret_headless(
    queue: &mut UserQueue,
    tag: &str,
    reason: &str,
    now_ms: i64,
) -> Result<String> {
    let item = queue.push(QueueKind::Credential, format!("secret `{tag}` required: {reason}"), now_ms)?;
    Ok(item.id)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    ApiKey,
    OAuth,
    DeviceCode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignInFlow {
    pub provider: String,
    pub method: AuthMethod,
    pub documented_for_third_party: bool,
    pub checked_on: String,
}

impl SignInFlow {
    pub fn new(provider: &str, method: AuthMethod, documented: bool, checked_on: &str) -> Self {
        Self { provider: provider.into(), method, documented_for_third_party: documented, checked_on: checked_on.into() }
    }

    /// A flow not documented for third-party clients is disabled with the reason.
    pub fn enabled(&self) -> Result<()> {
        if self.documented_for_third_party {
            Ok(())
        } else {
            Err(ZeroError::new(
                ErrorCode::Unavailable,
                format!("{} {} flow is not documented for third-party clients (checked {})", self.provider, format!("{:?}", self.method).to_lowercase(), self.checked_on),
            ))
        }
    }

    /// Complete a flow: tokens land in the credential store, never in config.
    pub fn complete(&self, store: &mut crate::credentials::EncryptedStore, account: &str, token: &str) -> Result<()> {
        self.enabled()?;
        store.set(&self.provider, account, token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_prompts_are_host_issued_and_masked() {
        let prompt = request_secret("p1", "OPENAI_KEY", "provider login", 0);
        assert!(prompt.is_host_issued());
        let rendered = prompt.render_masked(PromptSurface::Tui, 6);
        assert!(rendered.contains("OPENAI_KEY"));
        assert!(rendered.contains("••••••"));
        assert!(!rendered.contains("sk-"));
    }

    #[test]
    fn scanning_finds_keys_in_files_and_git_history_with_a_rotation_offer() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.txt"), "api=sk-abcdefghijklmnopqrst\nsafe=1\n").unwrap();
        let findings = scan_file(dir.path().join("config.txt")).unwrap();
        assert!(findings.iter().any(|f| f.kind == "openai_key"));
        assert!(!rotation_offer(&findings).is_empty());
        assert!(!findings[0].kind.contains("abcdef"));

        let status = std::process::Command::new("git").arg("--version").output();
        if status.map(|o| !o.status.success()).unwrap_or(true) {
            println!("skipped: git is unavailable");
            return;
        }
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let git = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(&repo)
                .args(["-c", "user.email=test@example.com", "-c", "user.name=test"])
                .args(args)
                .output()
                .unwrap()
        };
        assert!(git(&["init", "-q"]).status.success());
        std::fs::write(repo.join("creds.txt"), "token=ghp_abcdefghijklmnopqrstuvwx\n").unwrap();
        assert!(git(&["add", "."]).status.success());
        assert!(git(&["commit", "-q", "-m", "plant"]).status.success());
        std::fs::remove_file(repo.join("creds.txt")).unwrap();
        assert!(git(&["commit", "-q", "-am", "remove"]).status.success());
        let history = scan_git_history(&repo).unwrap();
        assert!(history.iter().any(|f| f.kind == "github_token"));
    }

    #[test]
    fn the_headless_queue_queues_a_secret_and_work_continues() {
        let dir = tempfile::tempdir().unwrap();
        let mut queue = UserQueue::open(dir.path().join("q.json")).unwrap();
        let id = request_secret_headless(&mut queue, "API_KEY", "needed for deploy", 0).unwrap();
        assert_eq!(queue.open_items().len(), 1);
        assert_eq!(queue.open_items()[0].id, id);
        assert_eq!(queue.open_items()[0].kind, QueueKind::Credential);
    }

    #[test]
    fn an_undocumented_sign_in_flow_is_disabled_with_the_reason() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = crate::credentials::EncryptedStore::open(dir.path().join("c.enc"), None).unwrap();
        let oauth = SignInFlow::new("chatgpt", AuthMethod::OAuth, false, "2026-11-25");
        let err = oauth.enabled().unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unavailable);
        assert!(err.message().contains("not documented"));
        assert!(oauth.complete(&mut store, "default", "token").is_err());
        assert!(store.active("chatgpt").is_none());

        let api = SignInFlow::new("openai", AuthMethod::ApiKey, true, "2026-11-25");
        api.complete(&mut store, "default", "sk-documented").unwrap();
        assert_eq!(store.get("openai", "default").unwrap().as_deref(), Some("sk-documented"));
    }
}
