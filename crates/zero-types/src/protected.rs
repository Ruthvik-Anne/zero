//! Protected-path classification (DEL-07, TRU-05).
//!
//! Pure path policy, shared by `zero-fs` (trash) and `zero-policy` (agent
//! writes). It performs no IO and is platform-parameterized, so a Windows path
//! classifies identically on every host (and the table is testable for all
//! platforms from one machine).

use crate::paths::Platform;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedKind {
    Home,
    DriveRoot,
    SystemDirectory,
    GitDirectory,
    ZeroDirectory,
    AuditLog,
    Journal,
    CredentialStore,
    PolicyFile,
}

impl ProtectedKind {
    pub fn reason(self) -> &'static str {
        match self {
            ProtectedKind::Home => "the home directory itself",
            ProtectedKind::DriveRoot => "a filesystem root",
            ProtectedKind::SystemDirectory => "a system directory",
            ProtectedKind::GitDirectory => "a `.git` directory",
            ProtectedKind::ZeroDirectory => "Zero's own `.zero` data",
            ProtectedKind::AuditLog => "the audit log",
            ProtectedKind::Journal => "a Zero journal",
            ProtectedKind::CredentialStore => "the credential store",
            ProtectedKind::PolicyFile => "a policy or trust file",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub path: String,
    pub kind: ProtectedKind,
    pub reason: String,
}

/// The protected set, built from the real data/config roots and a platform.
#[derive(Debug, Clone)]
pub struct ProtectedPaths {
    pub home: PathBuf,
    pub data_root: PathBuf,
    pub config_root: PathBuf,
    pub platform: Platform,
}

/// A path split with the rules of a specific platform, independent of the host.
#[derive(Debug, Clone)]
struct Normalised {
    text: String,
    parts: Vec<String>,
}

impl Normalised {
    fn separator(&self, platform: Platform) -> char {
        if platform == Platform::Windows {
            '\\'
        } else {
            '/'
        }
    }

    fn under(&self, base: &Normalised, platform: Platform) -> bool {
        self.text == base.text
            || (self.text.starts_with(&base.text)
                && self.text.len() > base.text.len()
                && self.text.as_bytes()[base.text.len()] == self.separator(platform) as u8)
    }
}

fn normalise(path: &Path, platform: Platform) -> Normalised {
    match platform {
        Platform::Windows => {
            let raw = path.to_string_lossy().replace('/', "\\");
            let mut parts: Vec<String> = Vec::new();
            for part in raw.split('\\') {
                match part {
                    "" | "." => {}
                    ".." => {
                        parts.pop();
                    }
                    other => parts.push(other.to_ascii_lowercase()),
                }
            }
            Normalised { text: parts.join("\\"), parts }
        }
        Platform::MacOs | Platform::Linux => {
            let mut parts: Vec<String> = Vec::new();
            let mut absolute = false;
            for component in path.components() {
                use std::path::Component;
                match component {
                    // Host-independent: a leading `/` is absolute even when the
                    // host is Windows, where `Path::is_absolute("/")` is false.
                    Component::RootDir => {
                        absolute = true;
                        parts.clear();
                    }
                    Component::CurDir => {}
                    Component::ParentDir => {
                        parts.pop();
                    }
                    Component::Normal(part) => parts.push(part.to_string_lossy().to_string()),
                    Component::Prefix(prefix) => parts.push(prefix.as_os_str().to_string_lossy().to_string()),
                }
            }
            let text = if absolute {
                format!("/{}", parts.join("/"))
            } else {
                parts.join("/")
            };
            Normalised { text, parts }
        }
    }
}

fn is_root(path: &Path, platform: Platform) -> bool {
    let norm = normalise(path, platform);
    match platform {
        Platform::Windows => {
            norm.parts.len() == 1 && norm.parts[0].ends_with(':')
        }
        Platform::MacOs | Platform::Linux => norm.text == "/",
    }
}

impl ProtectedPaths {
    /// The protected set for this process, from the resolved data/config roots.
    pub fn for_current() -> Self {
        use crate::paths::{current, current_platform, Env, PathKind};
        let env = Env::from_process();
        let home = env.home.clone().unwrap_or_else(|| ".".into());
        Self::new(home, current(PathKind::Data), current(PathKind::Config), current_platform())
    }

    pub fn new(home: impl Into<PathBuf>, data_root: impl Into<PathBuf>, config_root: impl Into<PathBuf>, platform: Platform) -> Self {
        Self { home: home.into(), data_root: data_root.into(), config_root: config_root.into(), platform }
    }

    fn starts_with_path(&self, path: &Normalised, base: &Path) -> bool {
        path.under(&normalise(base, self.platform), self.platform)
    }

    /// Classify a path. `None` means it is not protected.
    pub fn classify(&self, path: &Path) -> Option<Refusal> {
        let norm = normalise(path, self.platform);
        let refusal = |kind: ProtectedKind| {
            Some(Refusal {
                path: path.display().to_string(),
                kind,
                reason: kind.reason().to_string(),
            })
        };

        // The home directory itself (not its children).
        if norm.text == normalise(&self.home, self.platform).text {
            return refusal(ProtectedKind::Home);
        }
        if is_root(path, self.platform) {
            return refusal(ProtectedKind::DriveRoot);
        }
        for system in system_dirs(self.platform) {
            if self.starts_with_path(&norm, Path::new(system)) {
                return refusal(ProtectedKind::SystemDirectory);
            }
        }

        // Policy/trust and credential file names win over their parent directory,
        // so a denial names the more specific reason.
        if let Some(name) = norm.parts.last() {
            let lower = name.to_ascii_lowercase();
            if lower == "policy.toml" || lower == "trust.json" || lower == ".halcyon-mode" {
                return refusal(ProtectedKind::PolicyFile);
            }
            if lower.contains("credentials") || lower == "auth.json" {
                return refusal(ProtectedKind::CredentialStore);
            }
            if lower.ends_with(".journal") {
                return refusal(ProtectedKind::Journal);
            }
        }
        if norm.parts.iter().any(|p| p == ".git") {
            return refusal(ProtectedKind::GitDirectory);
        }
        if norm.parts.iter().any(|p| p == ".zero") {
            return refusal(ProtectedKind::ZeroDirectory);
        }
        if self.starts_with_path(&norm, &self.data_root) {
            let lower = norm.text.to_ascii_lowercase();
            if lower.contains("audit") {
                return refusal(ProtectedKind::AuditLog);
            }
            if lower.contains("journal") {
                return refusal(ProtectedKind::Journal);
            }
            return refusal(ProtectedKind::ZeroDirectory);
        }
        if self.starts_with_path(&norm, &self.config_root) {
            let lower = norm.text.to_ascii_lowercase();
            if lower.contains("credential") {
                return refusal(ProtectedKind::CredentialStore);
            }
            if lower.contains("policy") || lower.contains("trust") {
                return refusal(ProtectedKind::PolicyFile);
            }
            return refusal(ProtectedKind::ZeroDirectory);
        }
        None
    }

    pub fn is_protected(&self, path: &Path) -> bool {
        self.classify(path).is_some()
    }
}

fn system_dirs(platform: Platform) -> Vec<&'static str> {
    match platform {
        Platform::Windows => vec![
            r"C:\Windows",
            r"C:\Program Files",
            r"C:\Program Files (x86)",
            r"C:\ProgramData",
        ],
        Platform::MacOs => vec!["/System", "/Library", "/usr", "/bin", "/sbin", "/private/etc"],
        Platform::Linux => vec!["/etc", "/usr", "/bin", "/sbin", "/boot", "/sys", "/proc", "/dev"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classifier() -> ProtectedPaths {
        ProtectedPaths::new(
            r"C:\Users\example",
            r"C:\Users\example\AppData\Local\Zero",
            r"C:\Users\example\AppData\Roaming\Zero",
            Platform::Windows,
        )
    }

    #[test]
    fn each_listed_path_returns_a_refusal_with_the_reason() {
        let p = classifier();
        let cases = [
            (r"C:\Users\example", ProtectedKind::Home),
            (r"C:\", ProtectedKind::DriveRoot),
            (r"C:\Windows\System32", ProtectedKind::SystemDirectory),
            (r"C:\work\proj\.git\config", ProtectedKind::GitDirectory),
            (r"C:\work\proj\.zero\project.json", ProtectedKind::ZeroDirectory),
            (r"C:\Users\example\AppData\Local\Zero\audit\audit.jsonl", ProtectedKind::AuditLog),
            (r"C:\Users\example\AppData\Local\Zero\journals\turn.journal", ProtectedKind::Journal),
            (r"C:\Users\example\AppData\Roaming\Zero\credentials\openai.json", ProtectedKind::CredentialStore),
            (r"C:\work\proj\.zero\policy.toml", ProtectedKind::PolicyFile),
        ];
        for (path, kind) in cases {
            let refusal = p.classify(Path::new(path)).unwrap_or_else(|| panic!("{path} must be protected"));
            assert_eq!(refusal.kind, kind, "{path}");
            assert!(!refusal.reason.is_empty());
        }
    }

    #[test]
    fn ordinary_project_files_are_not_protected() {
        let p = classifier();
        for path in [r"C:\work\proj\src\main.rs", r"C:\work\proj\README.md", r"C:\Users\example\notes.txt"] {
            assert!(p.classify(Path::new(path)).is_none(), "{path}");
        }
    }

    #[test]
    fn traversal_cannot_escape_the_classification() {
        let p = classifier();
        let refused = p
            .classify(Path::new(r"C:\work\proj\src\..\..\.git\config"))
            .expect("normalised path still contains .git");
        assert_eq!(refused.kind, ProtectedKind::GitDirectory);
        assert!(p.is_protected(Path::new(r"C:\work\..\Users\example")));
    }

    #[test]
    fn classification_is_platform_parameterized_not_host_dependent() {
        // This test itself runs on every host; the Windows fixture must classify
        // identically on Linux and macOS.
        let win = classifier();
        assert_eq!(win.classify(Path::new(r"C:\work\proj\.git\config")).unwrap().kind, ProtectedKind::GitDirectory);
        assert!(win.classify(Path::new(r"C:\work\proj\src\main.rs")).is_none());

        let unix = ProtectedPaths::new("/home/example", "/home/example/.local/share/zero", "/home/example/.config/zero", Platform::Linux);
        assert_eq!(unix.classify(Path::new("/")).unwrap().kind, ProtectedKind::DriveRoot);
        assert_eq!(unix.classify(Path::new("/etc/passwd")).unwrap().kind, ProtectedKind::SystemDirectory);
        assert_eq!(unix.classify(Path::new("/home/example/.zero/x")).unwrap().kind, ProtectedKind::ZeroDirectory);
        assert_eq!(unix.classify(Path::new("/home/example/.config/zero/policy.toml")).unwrap().kind, ProtectedKind::PolicyFile);
        assert!(unix.classify(Path::new("/home/example/proj/a.rs")).is_none());
    }

    #[test]
    fn a_sibling_prefix_is_not_under_the_root() {
        let p = ProtectedPaths::new("/home/example", "/home/example/zero-data", "/home/example/zero-config", Platform::Linux);
        assert!(p.classify(Path::new("/home/example/zero-data-old/file")).is_none());
        assert!(p.classify(Path::new("/home/example/zero-data/file")).is_some());
    }
}
