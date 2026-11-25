//! File and subtree leases with fencing (FS-03, FS-08).
//!
//! A lease records the resource identity, owner, generation, expiry, and a
//! monotonic fence. A stale holder's write is rejected: the generation no longer
//! matches. Overlap is identity-based (hardlinks/symlinks agree) and tree leases
//! cover their descendants.

use crate::identity::{identity_or_path, normalise, FileIdentity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Resource {
    File { id: String, canonical: PathBuf },
    Tree { canonical: PathBuf },
}

impl Resource {
    fn overlaps(&self, other: &Resource) -> bool {
        match (self, other) {
            (Resource::File { id: a, .. }, Resource::File { id: b, .. }) => a == b,
            (Resource::File { canonical, .. }, Resource::Tree { canonical: dir })
            | (Resource::Tree { canonical: dir }, Resource::File { canonical, .. }) => canonical.starts_with(dir),
            (Resource::Tree { canonical: a }, Resource::Tree { canonical: b }) => a.starts_with(b) || b.starts_with(a),
        }
    }

    fn key(&self) -> String {
        match self {
            Resource::File { id, .. } => format!("file:{id}"),
            Resource::Tree { canonical } => format!("tree:{}", canonical.display()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub resource: Resource,
    pub owner: String,
    pub generation: u64,
    pub expires_ms: i64,
    pub fence: u64,
}

#[derive(Debug, Default)]
pub struct LockManager {
    leases: Vec<Lease>,
    generations: BTreeMap<String, u64>,
    next_fence: u64,
}

impl LockManager {
    pub fn new() -> Self {
        Self { leases: Vec::new(), generations: BTreeMap::new(), next_fence: 1 }
    }

    fn next_lease(&mut self, resource: Resource, owner: &str, now_ms: i64, ttl_ms: i64) -> Lease {
        let key = resource.key();
        let generation = self.generations.entry(key).or_insert(0);
        *generation += 1;
        let fence = self.next_fence;
        self.next_fence += 1;
        Lease {
            resource,
            owner: owner.to_string(),
            generation: *generation,
            expires_ms: now_ms + ttl_ms,
            fence,
        }
    }

    fn conflicting(&self, resource: &Resource) -> Option<&Lease> {
        self.leases.iter().find(|lease| lease.resource.overlaps(resource))
    }

    pub fn acquire_file(&mut self, path: impl AsRef<Path>, owner: &str, now_ms: i64, ttl_ms: i64) -> Result<Lease> {
        let identity: FileIdentity = identity_or_path(path.as_ref());
        let resource = Resource::File { id: identity.id.clone(), canonical: identity.canonical.clone() };
        if let Some(existing) = self.conflicting(&resource) {
            return Err(ZeroError::new(
                ErrorCode::Locked,
                format!(
                    "{} is locked by {} until {} (fence {})",
                    path.as_ref().display(),
                    existing.owner,
                    existing.expires_ms,
                    existing.fence
                ),
            ));
        }
        let lease = self.next_lease(resource, owner, now_ms, ttl_ms);
        self.leases.push(lease.clone());
        Ok(lease)
    }

    pub fn acquire_tree(&mut self, dir: impl AsRef<Path>, owner: &str, now_ms: i64, ttl_ms: i64) -> Result<Lease> {
        let canonical = std::fs::canonicalize(dir.as_ref()).unwrap_or_else(|_| normalise(dir.as_ref()));
        let resource = Resource::Tree { canonical: normalise(&canonical) };
        if let Some(existing) = self.conflicting(&resource) {
            return Err(ZeroError::new(
                ErrorCode::Locked,
                format!("{} is covered by {} (fence {})", dir.as_ref().display(), existing.owner, existing.fence),
            ));
        }
        let lease = self.next_lease(resource, owner, now_ms, ttl_ms);
        self.leases.push(lease.clone());
        Ok(lease)
    }

    pub fn renew(&mut self, lease: &Lease, now_ms: i64, ttl_ms: i64) -> Result<Lease> {
        self.validate(lease, now_ms)?;
        let mut updated = lease.clone();
        updated.expires_ms = now_ms + ttl_ms;
        for existing in &mut self.leases {
            if existing.resource == lease.resource && existing.generation == lease.generation {
                *existing = updated.clone();
            }
        }
        Ok(updated)
    }

    pub fn validate(&self, lease: &Lease, now_ms: i64) -> Result<()> {
        let current = self
            .leases
            .iter()
            .find(|l| l.resource == lease.resource)
            .ok_or_else(|| ZeroError::new(ErrorCode::Stale, "the lease was released or superseded"))?;
        if current.generation != lease.generation || current.owner != lease.owner {
            return Err(ZeroError::new(
                ErrorCode::Stale,
                format!("lease fence {} is stale; current generation is {}", lease.fence, current.generation),
            ));
        }
        if now_ms >= current.expires_ms {
            return Err(ZeroError::new(ErrorCode::Stale, format!("lease fence {} expired", lease.fence)));
        }
        Ok(())
    }

    pub fn release(&mut self, lease: &Lease) {
        self.leases.retain(|l| !(l.resource == lease.resource && l.generation == lease.generation));
    }

    /// Remove expired leases and return them.
    pub fn expire(&mut self, now_ms: i64) -> Vec<Lease> {
        let (expired, live): (Vec<_>, Vec<_>) = self.leases.drain(..).partition(|l| now_ms >= l.expires_ms);
        self.leases = live;
        expired
    }

    /// Take an expired lease for a new owner. A live lease is a conflict.
    pub fn steal_expired(&mut self, path: impl AsRef<Path>, owner: &str, now_ms: i64, ttl_ms: i64) -> Result<Lease> {
        let identity = identity_or_path(path.as_ref());
        let resource = Resource::File { id: identity.id, canonical: identity.canonical };
        match self.conflicting(&resource) {
            Some(existing) if now_ms < existing.expires_ms => Err(ZeroError::new(
                ErrorCode::Locked,
                format!("lease held by {} until {}", existing.owner, existing.expires_ms),
            )),
            Some(_) => {
                self.leases.retain(|l| !l.resource.overlaps(&resource));
                let lease = self.next_lease(resource, owner, now_ms, ttl_ms);
                self.leases.push(lease.clone());
                Ok(lease)
            }
            None => self.acquire_file(path, owner, now_ms, ttl_ms),
        }
    }

    pub fn active(&self) -> &[Lease] {
        &self.leases
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_claimants_cannot_hold_one_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, b"x").unwrap();
        let mut locks = LockManager::new();
        let first = locks.acquire_file(&file, "worker-1", 0, 1000).unwrap();
        let err = locks.acquire_file(&file, "worker-2", 1, 1000).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Locked);
        assert_eq!(locks.active().len(), 1);
        locks.release(&first);
        let second = locks.acquire_file(&file, "worker-2", 2, 1000).unwrap();
        assert!(second.generation > first.generation, "release bumps the fence");
    }

    #[test]
    fn a_tree_lease_covers_descendants_but_not_siblings() {
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().join("src");
        std::fs::create_dir_all(tree.join("nested")).unwrap();
        let inside = tree.join("nested").join("a.rs");
        std::fs::write(&inside, b"x").unwrap();
        let outside = dir.path().join("other.rs");
        std::fs::write(&outside, b"y").unwrap();

        let mut locks = LockManager::new();
        locks.acquire_tree(&tree, "agent-a", 0, 1000).unwrap();
        assert_eq!(locks.acquire_file(&inside, "agent-b", 1, 1000).unwrap_err().code(), ErrorCode::Locked);
        assert!(locks.acquire_file(&outside, "agent-b", 1, 1000).is_ok());
    }

    #[test]
    fn a_stale_holder_is_fenced_out() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, b"x").unwrap();
        let mut locks = LockManager::new();
        let old = locks.acquire_file(&file, "crashed-worker", 0, 100).unwrap();
        assert!(locks.validate(&old, 50).is_ok());
        assert_eq!(locks.validate(&old, 100).unwrap_err().code(), ErrorCode::Stale);

        let new = locks.steal_expired(&file, "new-worker", 100, 1000).unwrap();
        assert!(new.fence > old.fence);
        assert_eq!(locks.validate(&old, 150).unwrap_err().code(), ErrorCode::Stale);
        assert!(locks.validate(&new, 150).is_ok());
    }

    #[test]
    fn a_hardlink_is_the_same_lock_resource() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, b"x").unwrap();
        let hard = dir.path().join("hard.txt");
        std::fs::hard_link(&file, &hard).unwrap();
        let mut locks = LockManager::new();
        locks.acquire_file(&file, "owner", 0, 1000).unwrap();
        assert_eq!(locks.acquire_file(&hard, "other", 1, 1000).unwrap_err().code(), ErrorCode::Locked);
    }
}
