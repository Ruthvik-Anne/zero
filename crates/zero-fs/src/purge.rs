//! Purge flow (DEL-08): permanent deletion is human-only, dry-run, confirmed,
//! plan-bound, and audited. There is no action class for purge, so the agent
//! cannot reach it by any dispatch route.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zero_store::audit::AuditLog;
use zero_types::error::{ErrorCode, Result, ZeroError};
use zero_types::protected::ProtectedPaths;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurgeEntry {
    pub path: PathBuf,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurgePlan {
    pub root: PathBuf,
    pub files: Vec<PurgeEntry>,
    pub bytes: u64,
    /// Bound to this exact plan; a changed plan cannot be confirmed.
    pub digest: String,
}

#[derive(Debug, Clone)]
pub struct HumanConfirmation {
    digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeReport {
    pub removed: usize,
    pub bytes: u64,
    pub digest: String,
}

pub struct PurgeService {
    protected: ProtectedPaths,
}

impl PurgeService {
    pub fn new(protected: ProtectedPaths) -> Self {
        Self { protected }
    }

    pub fn dry_run(&self, path: impl AsRef<Path>) -> Result<PurgePlan> {
        let root = path.as_ref().to_path_buf();
        if let Some(refusal) = self.protected.classify(&root) {
            return Err(ZeroError::new(ErrorCode::ProtectedPath, format!("cannot purge {}: {}", root.display(), refusal.reason)));
        }
        let mut files = Vec::new();
        let mut bytes = 0u64;
        if root.is_file() {
            let size = std::fs::metadata(&root)?.len();
            files.push(PurgeEntry { path: root.clone(), size });
            bytes += size;
        } else if root.is_dir() {
            collect(&root, &mut files, &mut bytes)?;
        } else {
            return Err(ZeroError::new(ErrorCode::NotFound, format!("{} does not exist", root.display())));
        }
        let digest = plan_digest(&root, &files);
        Ok(PurgePlan { root, files, bytes, digest })
    }

    pub fn purge(&self, plan: &PurgePlan, confirmation: HumanConfirmation, audit: &mut AuditLog, ts: i64) -> Result<PurgeReport> {
        if confirmation.digest != plan.digest {
            return Err(ZeroError::new(ErrorCode::PurgeDenied, "the confirmation is for a different plan"));
        }
        if plan.digest != plan_digest(&plan.root, &plan.files) {
            return Err(ZeroError::new(ErrorCode::PurgeDenied, "the plan changed after it was confirmed"));
        }
        let mut removed = 0usize;
        for entry in &plan.files {
            std::fs::remove_file(&entry.path).map_err(|e| {
                ZeroError::new(ErrorCode::PurgeDenied, format!("could not purge {}: {e}", entry.path.display()))
            })?;
            removed += 1;
        }
        if plan.root.is_dir() {
            remove_empty_dirs(&plan.root)?;
            let _ = std::fs::remove_dir(&plan.root);
        }
        audit.append(
            ts,
            "user",
            "purge",
            serde_json::json!({"root": plan.root.display().to_string(), "files": removed, "bytes": plan.bytes, "digest": plan.digest}),
        )?;
        Ok(PurgeReport { removed, bytes: plan.bytes, digest: plan.digest.clone() })
    }
}

/// The UI calls this after the user types the exact phrase. The agent has no
/// route to this function and no way to construct a confirmation token.
pub fn confirm_from_ui(plan: &PurgePlan, phrase: &str) -> Option<HumanConfirmation> {
    if phrase == "PURGE" {
        Some(HumanConfirmation { digest: plan.digest.clone() })
    } else {
        None
    }
}

fn collect(dir: &Path, files: &mut Vec<PurgeEntry>, bytes: &mut u64) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            // Remove the link itself, never its target.
            files.push(PurgeEntry { path, size: 0 });
            continue;
        }
        if metadata.is_dir() {
            collect(&path, files, bytes)?;
        } else {
            *bytes += metadata.len();
            files.push(PurgeEntry { path, size: metadata.len() });
        }
    }
    Ok(())
}

fn remove_empty_dirs(dir: &Path) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() && !entry.file_type()?.is_symlink() {
            remove_empty_dirs(&path)?;
            let _ = std::fs::remove_dir(&path);
        }
    }
    Ok(())
}

fn plan_digest(root: &Path, files: &[PurgeEntry]) -> String {
    let mut lines: Vec<String> = files
        .iter()
        .map(|f| format!("{}:{}", f.path.display(), f.size))
        .collect();
    lines.sort();
    let canonical = format!("root={}\n{}", root.display(), lines.join("\n"));
    blake3::hash(canonical.as_bytes()).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_types::paths::Platform;

    fn service(home: &Path) -> PurgeService {
        PurgeService::new(ProtectedPaths::new(
            home,
            home.join(".zero-data"),
            home.join(".zero-config"),
            if cfg!(windows) { Platform::Windows } else { Platform::Linux },
        ))
    }

    #[test]
    fn purge_is_dry_run_confirmed_and_audited() {
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        let target = dir.path().join("obsolete");
        std::fs::create_dir_all(target.join("sub")).unwrap();
        std::fs::write(target.join("a.txt"), b"aaaa").unwrap();
        std::fs::write(target.join("sub").join("b.txt"), b"bb").unwrap();

        let plan = service.dry_run(&target).unwrap();
        assert_eq!(plan.files.len(), 2);
        assert_eq!(plan.bytes, 6);
        assert!(target.exists(), "dry-run removes nothing");

        // A wrong phrase and a changed plan are refused.
        assert!(confirm_from_ui(&plan, "yes").is_none());
        let mut tampered = plan.clone();
        tampered.files.push(PurgeEntry { path: dir.path().join("injected.txt"), size: 0 });
        let confirmation = confirm_from_ui(&plan, "PURGE").unwrap();
        let audit = AuditLog::open(dir.path().join("audit.jsonl")).unwrap();
        let mut audit = audit;
        let err = service.purge(&tampered, confirmation, &mut audit, 1).unwrap_err();
        assert_eq!(err.code(), ErrorCode::PurgeDenied);
        assert!(target.exists());

        // The exact plan purges and is recorded.
        let confirmation = confirm_from_ui(&plan, "PURGE").unwrap();
        let report = service.purge(&plan, confirmation, &mut audit, 2).unwrap();
        assert_eq!(report.removed, 2);
        assert!(!target.exists());
        let (events, _) = zero_store::jsonl::scan_raw::<zero_store::audit::AuditEvent>(dir.path().join("audit.jsonl")).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "purge");
    }

    #[test]
    fn protected_roots_cannot_be_purged() {
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        let err = service.dry_run(dir.path()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtectedPath);
    }

    #[test]
    fn the_agent_cannot_produce_a_confirmation_token() {
        // A purge is not a policy action class, and only the human phrase mints a
        // token; the agent has no route to either.
        let plan = PurgePlan {
            root: "x".into(),
            files: vec![],
            bytes: 0,
            digest: "d".into(),
        };
        // Agent-supplied phrases do not produce a token.
        for phrase in ["yes", "PURGE!", "purge", ""] {
            assert!(confirm_from_ui(&plan, phrase).is_none(), "{phrase}");
        }
    }
}
