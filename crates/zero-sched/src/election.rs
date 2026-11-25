//! Deterministic resource ownership and fenced handoff (LCK-07, LCK-10).
//!
//! Every resource has one owner chosen by a stable hash over the membership.
//! Ownership moves by a fenced handoff (a new generation), and a minority
//! partition denies new leases.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerLease {
    pub resource: String,
    pub owner: String,
    pub generation: u64,
    pub fence: u64,
}

#[derive(Debug, Clone)]
pub struct Election {
    members: BTreeSet<String>,
    available: BTreeSet<String>,
    generations: BTreeMap<String, u64>,
    fences: BTreeMap<String, u64>,
    /// Owners moved by an explicit handoff; the hash is the initial election.
    owners: BTreeMap<String, String>,
    next_fence: u64,
}

impl Election {
    pub fn new(members: impl IntoIterator<Item = String>) -> Self {
        let members: BTreeSet<String> = members.into_iter().collect();
        let available = members.clone();
        Self {
            members,
            available,
            generations: BTreeMap::new(),
            fences: BTreeMap::new(),
            owners: BTreeMap::new(),
            next_fence: 1,
        }
    }

    pub fn members(&self) -> &BTreeSet<String> {
        &self.members
    }

    /// Simulate a partition: only these nodes are reachable.
    pub fn set_available(&mut self, nodes: impl IntoIterator<Item = String>) {
        self.available = nodes.into_iter().filter(|n| self.members.contains(n)).collect();
    }

    /// True when the reachable set is not a strict majority.
    pub fn partitioned(&self) -> bool {
        self.available.len() * 2 <= self.members.len()
    }

    /// Deterministic owner: stable hash of the resource modulo the sorted
    /// membership. Availability does not change the owner, only whether it can
    /// act.
    pub fn owner(&self, resource: &str) -> Option<String> {
        if let Some(owner) = self.owners.get(resource) {
            return Some(owner.clone());
        }
        if self.members.is_empty() {
            return None;
        }
        let members: Vec<&String> = self.members.iter().collect();
        let hash = blake3::hash(resource.as_bytes());
        let first = u64::from_be_bytes(hash.as_bytes()[..8].try_into().expect("8 bytes"));
        Some(members[(first % members.len() as u64) as usize].clone())
    }

    pub fn acquire(&mut self, resource: &str, node: &str) -> Result<OwnerLease> {
        if self.partitioned() {
            return Err(ZeroError::new(
                ErrorCode::NoQuorum,
                format!("{} reachable of {} members; new leases are denied", self.available.len(), self.members.len()),
            ));
        }
        let owner = self
            .owner(resource)
            .ok_or_else(|| ZeroError::new(ErrorCode::Unavailable, "no mesh members"))?;
        if owner != node {
            return Err(ZeroError::new(ErrorCode::PolicyDenied, format!("`{node}` is not the owner of `{resource}`")));
        }
        let generation = self.generations.entry(resource.to_string()).or_insert(0);
        *generation += 1;
        let fence = self.next_fence;
        self.next_fence += 1;
        self.fences.insert(resource.to_string(), fence);
        Ok(OwnerLease { resource: resource.into(), owner: owner.clone(), generation: *generation, fence })
    }

    /// Move ownership with a new generation. Only a member can receive it.
    pub fn handoff(&mut self, resource: &str, from: &str, to: &str) -> Result<OwnerLease> {
        if self.partitioned() {
            return Err(ZeroError::new(ErrorCode::NoQuorum, "ownership cannot move without quorum"));
        }
        if !self.members.contains(to) {
            return Err(ZeroError::new(ErrorCode::NotFound, format!("`{to}` is not a member")));
        }
        if self.owner(resource).as_deref() != Some(from) {
            return Err(ZeroError::new(ErrorCode::PolicyDenied, format!("`{from}` does not own `{resource}`")));
        }
        self.owners.insert(resource.to_string(), to.to_string());
        let generation = self.generations.entry(resource.to_string()).or_insert(0);
        *generation += 1;
        let fence = self.next_fence;
        self.next_fence += 1;
        self.fences.insert(resource.to_string(), fence);
        Ok(OwnerLease { resource: resource.into(), owner: to.into(), generation: *generation, fence })
    }

    pub fn validate(&self, lease: &OwnerLease) -> Result<()> {
        if self.owner(&lease.resource).as_deref() != Some(lease.owner.as_str()) {
            return Err(ZeroError::new(ErrorCode::Stale, "ownership changed"));
        }
        if self.generations.get(&lease.resource).copied().unwrap_or(0) != lease.generation {
            return Err(ZeroError::new(ErrorCode::Stale, "lease generation is stale"));
        }
        if self.fences.get(&lease.resource).copied() != Some(lease.fence) {
            return Err(ZeroError::new(ErrorCode::Stale, "lease fence is stale"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nodes(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("node-{i}")).collect()
    }

    #[test]
    fn ownership_is_deterministic_and_stable() {
        let election = Election::new(nodes(5));
        let first = election.owner("task/1").unwrap();
        assert_eq!(election.owner("task/1").unwrap(), first);
        // Every resource has exactly one of the members as owner.
        for i in 0..50 {
            let owner = election.owner(&format!("resource/{i}")).unwrap();
            assert!(election.members().contains(&owner));
        }
    }

    #[test]
    fn a_minority_partition_denies_new_leases() {
        let members = nodes(5);
        let mut election = Election::new(members.clone());
        let resource = "task/1";
        let owner = election.owner(resource).unwrap();
        election.set_available(vec![owner.clone()]);
        assert!(election.partitioned());
        assert_eq!(election.acquire(resource, &owner).unwrap_err().code(), ErrorCode::NoQuorum);

        election.set_available(members[..3].to_vec());
        assert!(!election.partitioned(), "three of five is a majority");
        assert!(election.acquire(resource, &owner).is_ok());
    }

    #[test]
    fn a_fenced_handoff_invalidates_the_old_lease() {
        let mut election = Election::new(nodes(3));
        let resource = "resource/x";
        let owner = election.owner(resource).unwrap();
        let old = election.acquire(resource, &owner).unwrap();
        let new_owner = election.members().iter().find(|n| **n != owner).unwrap().clone();
        let new = election.handoff(resource, &owner, &new_owner).unwrap();
        assert!(new.generation > old.generation);
        assert!(election.validate(&old).is_err());
        assert!(election.validate(&new).is_ok(), "the handoff owner is valid");
    }
}
