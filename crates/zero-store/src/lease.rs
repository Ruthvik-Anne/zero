//! Process-safe lease per canonical log path (SES-06).
//!
//! Acquisition is an atomic `create_new` of a sidecar file. A live lease is
//! reported as `Held` with its owner, so two concurrent creates converge on one
//! worker instead of racing. An expired lease may be stolen exactly once.

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use zero_types::error::{ErrorCode, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseInfo {
    pub pid: u32,
    pub nonce: String,
    pub acquired_ms: i64,
    pub expires_ms: i64,
    pub log_path: String,
}

#[derive(Debug)]
pub enum LeaseOutcome {
    Acquired(Lease),
    Held { owner_pid: u32, owner_nonce: String },
}

#[derive(Debug)]
pub struct Lease {
    path: PathBuf,
    info: LeaseInfo,
    released: bool,
}

impl Lease {
    pub fn info(&self) -> &LeaseInfo {
        &self.info
    }

    pub fn renew(&mut self, now_ms: i64, ttl_ms: i64) -> Result<()> {
        self.info.expires_ms = now_ms + ttl_ms;
        write_lease(&self.path, &self.info)
    }

    pub fn release(&mut self) -> Result<()> {
        if self.released {
            return Ok(());
        }
        // Only remove the file if it still describes this lease.
        if let Ok(current) = read_lease(&self.path) {
            if current.nonce == self.info.nonce {
                let _ = std::fs::remove_file(&self.path);
            }
        }
        self.released = true;
        Ok(())
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

fn canonical_key(log_path: &Path) -> PathBuf {
    let parent = log_path.parent().unwrap_or_else(|| Path::new("."));
    let parent = std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
    let name = log_path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    parent.join(name)
}

pub fn lease_path(log_path: &Path) -> PathBuf {
    let canonical = canonical_key(log_path);
    let mut name = canonical.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".lease");
    canonical.with_file_name(name)
}

fn write_lease(path: &Path, info: &LeaseInfo) -> Result<()> {
    let tmp = path.with_extension("lease.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&serde_json::to_vec(info)?)?;
        f.sync_all()?;
    }
    // A rename replaces atomically; used only for renewal of our own lease.
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn read_lease(path: &Path) -> Result<LeaseInfo> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn nonce() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}-{:x}", std::process::id(), nanos)
}

/// Acquire the lease for `log_path`, or report its live owner.
pub fn acquire(log_path: &Path, now_ms: i64, ttl_ms: i64) -> Result<LeaseOutcome> {
    let path = lease_path(log_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let info = LeaseInfo {
        pid: std::process::id(),
        nonce: nonce(),
        acquired_ms: now_ms,
        expires_ms: now_ms + ttl_ms,
        log_path: log_path.display().to_string(),
    };
    match try_create(&path, &info) {
        Ok(()) => Ok(LeaseOutcome::Acquired(Lease { path, info, released: false })),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_lease(&path)?;
            if existing.expires_ms <= now_ms {
                // Expired: remove and retry once. A concurrent stealer may win;
                // then we report it as held rather than racing further.
                let _ = std::fs::remove_file(&path);
                match try_create(&path, &info) {
                    Ok(()) => Ok(LeaseOutcome::Acquired(Lease { path, info, released: false })),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        let current = read_lease(&path)?;
                        Ok(LeaseOutcome::Held { owner_pid: current.pid, owner_nonce: current.nonce })
                    }
                    Err(e) => Err(e.into()),
                }
            } else {
                Ok(LeaseOutcome::Held { owner_pid: existing.pid, owner_nonce: existing.nonce })
            }
        }
        Err(e) => Err(e.into()),
    }
}

fn try_create(path: &Path, info: &LeaseInfo) -> std::io::Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(&serde_json::to_vec(info)?)?;
    f.sync_all()?;
    Ok(())
}

/// Read the current owner without acquiring.
pub fn owner(log_path: &Path) -> Result<Option<LeaseInfo>> {
    let path = lease_path(log_path);
    match read_lease(&path) {
        Ok(info) => Ok(Some(info)),
        Err(e) if e.code() == ErrorCode::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_owner_and_expiry_steal() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("s.jsonl");
        std::fs::write(&log, b"").unwrap();

        let LeaseOutcome::Acquired(mut lease) = acquire(&log, 1000, 5000).unwrap() else {
            panic!("first acquire must win");
        };
        match acquire(&log, 1001, 5000).unwrap() {
            LeaseOutcome::Held { owner_pid, owner_nonce } => {
                assert_eq!(owner_pid, std::process::id());
                assert_eq!(owner_nonce, lease.info().nonce);
            }
            _ => panic!("second acquire must report the owner"),
        }

        lease.release().unwrap();
        assert!(matches!(acquire(&log, 1002, 5000).unwrap(), LeaseOutcome::Acquired(_)));

        // Expired leases may be stolen.
        let LeaseOutcome::Acquired(mut short) = acquire(&log, 2000, 10).unwrap() else {
            panic!()
        };
        let stolen = acquire(&log, 3000, 5000).unwrap();
        assert!(matches!(stolen, LeaseOutcome::Acquired(_)));
        assert!(short.release().is_ok());
    }

    #[test]
    fn lease_path_is_canonical() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("s.jsonl");
        let a = lease_path(&log);
        let b = lease_path(&dir.path().join(".").join("s.jsonl"));
        assert_eq!(a, b);
        assert!(a.to_string_lossy().ends_with("s.jsonl.lease"));
    }
}
