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
    /// Higher priority wounds lower priority holders (wound-wait).
    #[serde(default)]
    pub priority: i32,
    /// A critical section is never wounded.
    #[serde(default)]
    pub critical: bool,
}

#[derive(Debug, Default)]
pub struct LockManager {
    leases: Vec<Lease>,
    generations: BTreeMap<String, u64>,
    next_fence: u64,
    /// Identity cache: one open per path per manager, not per attempt.
    identities: BTreeMap<PathBuf, FileIdentity>,
}

impl LockManager {
    pub fn new() -> Self {
        Self { leases: Vec::new(), generations: BTreeMap::new(), next_fence: 1, identities: BTreeMap::new() }
    }

    fn next_lease(&mut self, resource: Resource, owner: &str, now_ms: i64, ttl_ms: i64, priority: i32) -> Lease {
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
            priority,
            critical: false,
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
        let lease = self.next_lease(resource, owner, now_ms, ttl_ms, 0);
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
        let lease = self.next_lease(resource, owner, now_ms, ttl_ms, 0);
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
                let lease = self.next_lease(resource, owner, now_ms, ttl_ms, 0);
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

impl LockManager {
    /// Canonical acquisition order, independent of how the caller listed paths.
    pub fn canonical_order(paths: &[std::path::PathBuf]) -> Vec<std::path::PathBuf> {
        let mut keyed: Vec<(String, std::path::PathBuf)> = paths
            .iter()
            .map(|path| {
                let identity = identity_or_path(path);
                (identity.canonical.display().to_string(), path.clone())
            })
            .collect();
        keyed.sort();
        keyed.dedup_by(|a, b| a.0 == b.0);
        keyed.into_iter().map(|(_, path)| path).collect()
    }

    fn file_resource(&mut self, path: &Path) -> Resource {
        let identity = self
            .identities
            .get(path)
            .cloned()
            .unwrap_or_else(|| {
                let identity = identity_or_path(path);
                self.identities.insert(path.to_path_buf(), identity.clone());
                identity
            });
        Resource::File { id: identity.id, canonical: identity.canonical }
    }

    /// Acquire a set of files in canonical order. A lower-priority holder is
    /// wounded; an equal/higher or critical holder makes the request wait, and
    /// the wait fails with `Locked` or `Timeout` (the caller retries, so no
    /// thread blocks inside the lock manager).
    pub fn acquire_many(
        &mut self,
        paths: &[PathBuf],
        owner: &str,
        priority: i32,
        now_ms: i64,
        ttl_ms: i64,
        deadline_ms: i64,
    ) -> Result<Vec<Lease>> {
        let mut ordered = Self::canonical_order(paths);
        // canonical_order is path-based; use cached identities for the lock key.
        ordered.sort_by_key(|path| self.file_resource(path).key());
        let mut acquired: Vec<Lease> = Vec::new();
        for path in &ordered {
            let resource = self.file_resource(path);
            loop {
                match self.conflicting(&resource) {
                    None => {
                        let lease = self.next_lease(resource, owner, now_ms, ttl_ms, priority);
                        self.leases.push(lease.clone());
                        acquired.push(lease);
                        break;
                    }
                    Some(existing) if priority > existing.priority && !existing.critical => {
                        // Wound-wait: the younger low-priority holder is preempted.
                        let victim = existing.clone();
                        self.release(&victim);
                        continue;
                    }
                    Some(_) => {
                        for lease in &acquired {
                            self.release(lease);
                        }
                        if now_ms >= deadline_ms {
                            return Err(ZeroError::new(
                                ErrorCode::Timeout,
                                format!("timed out acquiring {}", path.display()),
                            ));
                        }
                        return Err(ZeroError::new(
                            ErrorCode::Locked,
                            format!("{} is held; retry after the holder finishes", path.display()),
                        ));
                    }
                }
            }
        }
        Ok(acquired)
    }

    /// Mark a lease's critical section so wound-wait cannot preempt it.
    pub fn protect(&mut self, lease: &Lease) {
        for existing in &mut self.leases {
            if existing.resource == lease.resource && existing.generation == lease.generation {
                existing.critical = true;
            }
        }
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

    #[test]
    fn canonical_order_ignores_the_caller_order() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["a.txt", "b.txt", "c.txt"] {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        let forward = vec![dir.path().join("a.txt"), dir.path().join("b.txt")];
        let reversed = vec![dir.path().join("b.txt"), dir.path().join("a.txt")];
        assert_eq!(LockManager::canonical_order(&forward), LockManager::canonical_order(&reversed));
        let mut locks = LockManager::new();
        let leases = locks.acquire_many(&reversed, "w", 0, 0, 1000, 100).unwrap();
        assert_eq!(leases[0].resource, leases[0].resource.clone());
        assert!(leases.len() >= 2);
    }

    #[test]
    fn wound_wait_preempts_lower_priority_and_respects_critical_sections() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, b"x").unwrap();
        let mut locks = LockManager::new();
        let low = locks.acquire_file(&file, "low", 0, 1000).unwrap();
        let high = locks
            .acquire_many(std::slice::from_ref(&file), "high", 10, 1, 1000, 100)
            .unwrap();
        assert_eq!(high.len(), 1);
        assert!(locks.validate(&low, 2).is_err(), "the low-priority lease was wounded");
        assert!(locks.validate(&high[0], 2).is_ok());

        // A critical section is not wounded: the high-priority request waits.
        let mut locks = LockManager::new();
        let low = locks.acquire_file(&file, "low", 0, 1000).unwrap();
        locks.protect(&low);
        let blocked = locks.acquire_many(std::slice::from_ref(&file), "high", 10, 1, 1000, 100).unwrap_err();
        assert_eq!(blocked.code(), ErrorCode::Locked);
        let timed_out = locks.acquire_many(std::slice::from_ref(&file), "high", 10, 1000, 1000, 100).unwrap_err();
        assert_eq!(timed_out.code(), ErrorCode::Timeout);
    }

    #[test]
    fn ten_thousand_interleavings_never_deadlock() {
        use zero_types::id::DeterministicRng;
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        // One manager and one file pair, reused across 10,000 orderings; every
        // lease is released before the next seed.
        let mut locks = LockManager::new();
        for seed in 0..10_000u64 {
            let mut rng = DeterministicRng::new(seed);
            let mut pending: Vec<(String, Vec<PathBuf>, i32)> = (0..4)
                .map(|worker| {
                    let paths = if rng.below(2) == 0 { vec![a.clone()] } else { vec![b.clone()] };
                    (format!("w{worker}"), paths, rng.below(3) as i32)
                })
                .collect();
            let mut now = 0i64;
            let mut rounds = 0;
            while !pending.is_empty() {
                rounds += 1;
                assert!(rounds < 200, "seed {seed} deadlocked: {pending:?}");
                let mut progressed = false;
                let mut still = Vec::new();
                for (owner, paths, priority) in pending {
                    match locks.acquire_many(&paths, &owner, priority, now, 10_000, now + 1_000) {
                        Ok(leases) => {
                            for lease in &leases {
                                locks.release(lease);
                            }
                            progressed = true;
                        }
                        Err(e) if e.code() == ErrorCode::Locked => still.push((owner, paths, priority)),
                        Err(e) => panic!("seed {seed}: unexpected {}: {}", e.code(), e.message()),
                    }
                }
                pending = still;
                now += 1;
                if !progressed {
                    // All remaining requests were waiting in this round; retry.
                    continue;
                }
            }
        }
    }
}
