//! Quorum writes, revocation propagation, and partition refusal (T-MESH-08,
//! MESH-08, MESH-09, LCK-10).
//!
//! [`state`](crate::state) is the single-owner slice: one owner root key signs
//! every membership snapshot. This module adds the two things a replicated mesh
//! needs before an overlay can carry traffic:
//!
//! 1. **A quorum.** [`DelegateSet`] names the delegates and a threshold.
//!    [`check_quorum`] accepts a [`StateUpdate`] only when the owner root signed
//!    it, or when at least `threshold` distinct delegates voted for exactly that
//!    update. A minority partition — fewer than `threshold` votes — is refused,
//!    even when it holds a delegate signing key.
//! 2. **Revocation propagation.** [`RevocationSet`] is an owner-signed,
//!    monotonic list of revoked device ids. [`propagate`] verifies it, ignores
//!    an older version, and unions the ids into a [`Revoked`] table.
//!    [`Revoked::is_revoked`] is the single check relay, discovery, and state
//!    acceptance use to drop a revoked device.
//!
//! There is no privileged node and no network here: every function is a pure
//! operation over signed values a caller moves between peers. A node that has
//! not yet seen a revocation may still accept a stale peer; once it applies the
//! signed revocation it must drop the peer from discovery and presence, refuse
//! its relay traffic, and refuse its updates (MESH-08's "revocation
//! propagates").
//!
//! ## Owner-root rule
//!
//! MESH-09 allows either an owner root key or a threshold of delegates.
//! [`DelegateSet::owner_public_key_b64`] carries the root key, when the mesh has
//! one. The rule is:
//!
//! - A valid **owner-root signature on the update envelope** satisfies the
//!   quorum by itself, whatever the threshold. This is the single-owner path.
//! - Otherwise the update needs `threshold` **distinct delegate votes**. The
//!   owner root may be listed in [`DelegateSet::delegates`]; its vote then
//!   counts as one delegate like any other. It cannot both sign the envelope and
//!   have that signature counted as a vote — the envelope signature is either
//!   full root authority or nothing.
//!
//! A delegate that holds a signing key but sits in a minority partition has one
//! vote, not a quorum; [`can_write`] refuses the write rather than letting it
//! happen silently.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, ZeroError};

use crate::discovery::{self, Discovery};
use crate::identity::{device_id_for, verify, KeyPair};
use crate::presence::PresenceTable;
use crate::state::{apply, ApplyOutcome, MembershipState, StateUpdate};

/// Domain separator for a delegate vote.
pub const VOTE_DOMAIN: &[u8] = b"zero.mesh.delegate-vote.v1\0";

/// Domain separator for a signed revocation set.
pub const REVOCATION_SET_DOMAIN: &[u8] = b"zero.mesh.revocation-set.v1\0";

/// Most delegates a [`DelegateSet`] may carry.
pub const MAX_DELEGATES: usize = 128;

/// Most revoked ids a [`RevocationSet`] may carry.
pub const MAX_REVOCATION_IDS: usize = 8192;

/// The owner designates this many of these delegates to authorise a write.
///
/// `delegates` maps a delegate device id to its standard padded base64 Ed25519
/// public key. The id must be the blake3 hash of the key, so ids and keys are
/// unique together and a caller cannot invent an id for a key it does not hold.
/// `owner_public_key_b64` is optional: a mesh may run purely on a delegate
/// threshold (MESH-09's "or a threshold of delegates").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegateSet {
    /// Votes required to accept one update; 1..=delegates.len().
    pub threshold: u8,
    /// Delegate device id -> base64 Ed25519 public key.
    pub delegates: BTreeMap<String, String>,
    /// The owner root key, when the mesh has one. A valid signature by this key
    /// on the update envelope satisfies the quorum alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_public_key_b64: Option<String>,
}

impl DelegateSet {
    /// Build a delegate-only quorum.
    pub fn new(threshold: u8, delegates: BTreeMap<String, String>) -> Result<Self, ZeroError> {
        let set = Self {
            threshold,
            delegates,
            owner_public_key_b64: None,
        };
        set.validate()?;
        Ok(set)
    }

    /// Attach an owner root key to the quorum.
    pub fn with_owner(mut self, owner_public_key_b64: impl Into<String>) -> Result<Self, ZeroError> {
        self.owner_public_key_b64 = Some(owner_public_key_b64.into());
        self.validate()?;
        Ok(self)
    }

    /// Check the threshold, the count bound, and that every id is the blake3
    /// hash of its recorded key. A malformed key or a mismatched id is
    /// `zero.fnd.invalid_input`.
    pub fn validate(&self) -> Result<(), ZeroError> {
        if self.delegates.is_empty() {
            return Err(invalid("a delegate set must name at least one delegate"));
        }
        if self.delegates.len() > MAX_DELEGATES {
            return Err(limit(format!(
                "delegate set has {} delegates; the limit is {MAX_DELEGATES}",
                self.delegates.len()
            )));
        }
        if self.threshold == 0 {
            return Err(invalid("a delegate threshold must be at least one"));
        }
        if usize::from(self.threshold) > self.delegates.len() {
            return Err(invalid(format!(
                "delegate threshold {} exceeds the {} delegates",
                self.threshold,
                self.delegates.len()
            )));
        }
        for (delegate_id, public_key_b64) in &self.delegates {
            validate_device_id(delegate_id)?;
            if device_id_for(public_key_b64)? != *delegate_id {
                return Err(invalid(format!(
                    "delegate id `{delegate_id}` does not match its public key"
                )));
            }
        }
        if let Some(owner_public_key_b64) = &self.owner_public_key_b64 {
            device_id_for(owner_public_key_b64)?;
        }
        Ok(())
    }

    /// The public key recorded for `delegate_id`, when it is a delegate.
    pub fn public_key(&self, delegate_id: &str) -> Option<&str> {
        self.delegates.get(delegate_id).map(String::as_str)
    }

    /// True when `device_id` is a named delegate.
    pub fn is_delegate(&self, device_id: &str) -> bool {
        self.delegates.contains_key(device_id)
    }
}

/// One delegate's signature over `(state_version, state_hash)`.
///
/// `state_hash` is the lower-case hex blake3 hash of
/// [`StateUpdate::canonical_bytes`] — the same bytes the owner signs. A vote
/// therefore binds one exact update: changing a device, a name, a revoked id, or
/// the base version changes the hash and the vote no longer counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegateVote {
    /// The delegate device id that cast the vote.
    pub delegate_id: String,
    /// The update's state version the voter observed.
    pub state_version: u64,
    /// Lower-case hex blake3 of the update envelope bytes.
    pub state_hash: String,
    /// Standard padded base64 Ed25519 signature by the delegate key.
    #[serde(default)]
    pub signature_b64: String,
}

impl DelegateVote {
    /// Canonical vote bytes: the domain, the delegate id, the version, and the
    /// update hash, each length-prefixed. The signature is excluded because it
    /// is produced over these bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        framed(
            VOTE_DOMAIN,
            &[
                self.delegate_id.as_bytes(),
                &self.state_version.to_be_bytes(),
                self.state_hash.as_bytes(),
            ],
        )
    }
}

/// Sign a vote for `update` with a delegate key.
pub fn sign_vote(delegate_key: &KeyPair, update: &StateUpdate) -> Result<DelegateVote, ZeroError> {
    let state_hash = update_hash(update)?;
    let mut vote = DelegateVote {
        delegate_id: delegate_key.device_id().to_string(),
        state_version: update.state.version,
        state_hash,
        signature_b64: String::new(),
    };
    vote.signature_b64 = delegate_key.sign(&vote.canonical_bytes());
    Ok(vote)
}

/// The hex blake3 hash of [`StateUpdate::canonical_bytes`].
///
/// Canonicalisation validates the snapshot's structure; an invalid snapshot is
/// the same typed error [`crate::state::canonical_bytes`] returns.
pub fn update_hash(update: &StateUpdate) -> Result<String, ZeroError> {
    Ok(blake3::hash(&update.canonical_bytes()?).to_hex().to_string())
}

/// Result of [`check_quorum`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumDecision {
    /// The owner root signed the update, or enough distinct delegates voted.
    Accepted,
    /// The update is not authorised. The reason is for logs and tests; the
    /// update must not be written.
    Refused {
        /// Why the update was refused.
        reason: String,
    },
}

impl QuorumDecision {
    /// True for [`QuorumDecision::Accepted`].
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted)
    }

    /// The refusal reason, when refused.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Accepted => None,
            Self::Refused { reason } => Some(reason),
        }
    }
}

/// Decide whether `update` is authorised by `delegates` and `votes`.
///
/// Checks, in order:
///
/// 1. the delegate set is valid and the update snapshot canonicalises;
/// 2. `state.version == base_version + 1` and the update is not signed in the
///    future (`state.updated_ms <= now_ms`);
/// 3. an owner-root signature on the envelope satisfies the quorum alone;
/// 4. otherwise `votes.len() >= threshold` and every vote is from a known
///    delegate, distinct, for this exact state version, for this exact update
///    hash, with a valid delegate signature.
///
/// `Err` is reserved for malformed input (an invalid delegate set, an update
/// whose snapshot cannot be canonicalised). A well-formed update that is merely
/// unauthorised — a minority partition, a duplicate voter, a wrong hash — is
/// `Refused`, because that is a yes/no decision rather than a parse failure.
pub fn check_quorum(
    update: &StateUpdate,
    delegates: &DelegateSet,
    votes: &[DelegateVote],
    now_ms: i64,
) -> Result<QuorumDecision, ZeroError> {
    delegates.validate()?;
    let bytes = update.canonical_bytes()?;

    match update.base_version.checked_add(1) {
        Some(expected) if update.state.version == expected => {}
        _ => {
            return Ok(refused(format!(
                "quorum: state version {} does not follow base version {}",
                update.state.version, update.base_version
            )))
        }
    }
    if update.state.updated_ms > now_ms {
        return Ok(refused(format!(
            "quorum: update is signed in the future ({} > {now_ms})",
            update.state.updated_ms
        )));
    }

    // The single-owner path. Verify against the root key *and* require the
    // snapshot to name that root, so a root-key signature cannot be reused on a
    // snapshot attributed to somebody else.
    if let Some(owner_public_key_b64) = &delegates.owner_public_key_b64 {
        if let Ok(owner_id) = device_id_for(owner_public_key_b64) {
            if update.state.signed_by == owner_id
                && verify(owner_public_key_b64, &bytes, &update.signature).is_ok()
            {
                return Ok(QuorumDecision::Accepted);
            }
        }
    }

    // The delegate-threshold path.
    let required = usize::from(delegates.threshold);
    if votes.len() < required {
        return Ok(refused(format!(
            "quorum: minority partition: {} vote(s), {required} required",
            votes.len()
        )));
    }

    let hash = blake3::hash(&bytes).to_hex().to_string();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut counted = 0usize;
    for vote in votes {
        let Some(public_key_b64) = delegates.public_key(&vote.delegate_id) else {
            return Ok(refused(format!(
                "quorum: `{}` is not a known delegate",
                vote.delegate_id
            )));
        };
        if !seen.insert(vote.delegate_id.as_str()) {
            return Ok(refused(format!(
                "quorum: duplicate vote from delegate `{}`",
                vote.delegate_id
            )));
        }
        if vote.state_version != update.state.version {
            return Ok(refused(format!(
                "quorum: vote for version {} but the update is version {}",
                vote.state_version, update.state.version
            )));
        }
        if vote.state_hash != hash {
            return Ok(refused(format!(
                "quorum: vote from `{}` does not bind this update hash",
                vote.delegate_id
            )));
        }
        if verify(public_key_b64, &vote.canonical_bytes(), &vote.signature_b64).is_err() {
            return Ok(refused(format!(
                "quorum: vote signature from `{}` does not verify",
                vote.delegate_id
            )));
        }
        counted += 1;
    }

    if counted >= required {
        Ok(QuorumDecision::Accepted)
    } else {
        Ok(refused(format!(
            "quorum: minority partition: {counted} valid vote(s), {required} required"
        )))
    }
}

/// An owner-signed, versioned revocation list.
///
/// Only the owner root can sign it, so a stolen device cannot revoke another
/// member (MESH-09). `revoked` is a sorted set, so the canonical encoding does
/// not depend on insertion order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationSet {
    /// Monotonic revocation version: 1 for the first signed set.
    pub version: u64,
    /// Revoked device ids.
    pub revoked: BTreeSet<String>,
    /// Standard padded base64 Ed25519 signature by the owner root.
    #[serde(default)]
    pub signature_b64: String,
}

impl RevocationSet {
    /// Canonical, deterministic bytes the owner signs. All integers big-endian:
    ///
    /// ```text
    /// "zero.mesh.revocation-set.v1\0"  domain separator
    /// version                          u64
    /// count                            u32
    /// repeated ids, ascending:         u32 length + UTF-8 bytes
    /// ```
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ZeroError> {
        self.validate()?;
        let mut out = Vec::with_capacity(64 + self.revoked.len() * 68);
        out.extend_from_slice(REVOCATION_SET_DOMAIN);
        out.extend_from_slice(&self.version.to_be_bytes());
        put_count(&mut out, self.revoked.len(), MAX_REVOCATION_IDS, "ids")?;
        for device_id in &self.revoked {
            put_str(&mut out, device_id)?;
        }
        Ok(out)
    }

    /// Refuse version 0, too many ids, and a malformed device id.
    pub fn validate(&self) -> Result<(), ZeroError> {
        if self.version == 0 {
            return Err(invalid("a signed revocation set must have version 1 or greater"));
        }
        if self.revoked.len() > MAX_REVOCATION_IDS {
            return Err(limit(format!(
                "revocation set has {} ids; the limit is {MAX_REVOCATION_IDS}",
                self.revoked.len()
            )));
        }
        for device_id in &self.revoked {
            validate_device_id(device_id)?;
        }
        Ok(())
    }
}

/// Sign a revocation list with the owner root.
pub fn sign_revocation_set(
    owner_key: &KeyPair,
    version: u64,
    revoked: BTreeSet<String>,
) -> Result<RevocationSet, ZeroError> {
    if revoked.contains(owner_key.device_id()) {
        return Err(denied(
            "a revocation set cannot revoke the owner root itself",
        ));
    }
    let mut set = RevocationSet {
        version,
        revoked,
        signature_b64: String::new(),
    };
    let bytes = set.canonical_bytes()?;
    set.signature_b64 = owner_key.sign(&bytes);
    Ok(set)
}

/// Verify a revocation list against the owner public key.
///
/// A malformed shape is `zero.fnd.invalid_input`; a wrong signature, a foreign
/// owner, or a set that revokes the owner root itself is `zero.pol.denied`.
pub fn verify_revocation_set(
    set: &RevocationSet,
    owner_public_key_b64: &str,
) -> Result<(), ZeroError> {
    set.validate()?;
    let owner_id = device_id_for(owner_public_key_b64)?;
    if set.revoked.contains(&owner_id) {
        return Err(denied(
            "a revocation set cannot revoke the owner root itself",
        ));
    }
    verify(
        owner_public_key_b64,
        &set.canonical_bytes()?,
        &set.signature_b64,
    )
    .map_err(|_| denied("revocation set is not signed by the owner root"))
}

/// A node's local revocation table.
///
/// `version` is the highest owner-signed revocation version applied;
/// `is_revoked` is the gate relay, discovery, and state acceptance share.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revoked {
    /// Highest revocation version applied. Zero means none seen yet.
    pub version: u64,
    /// Revoked device ids.
    pub revoked: BTreeSet<String>,
}

impl Revoked {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adopt a verified set without unioning. Callers should prefer
    /// [`propagate`], which verifies the signature first.
    pub fn from_set(set: &RevocationSet) -> Self {
        Self {
            version: set.version,
            revoked: set.revoked.clone(),
        }
    }

    /// The highest revocation version applied.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The revoked ids.
    pub fn revoked(&self) -> &BTreeSet<String> {
        &self.revoked
    }

    /// True when `device_id` has been revoked.
    pub fn is_revoked(&self, device_id: &str) -> bool {
        self.revoked.contains(device_id)
    }
}

/// Apply an owner-signed revocation set to a local table.
///
/// The signature is verified first, so an unauthenticated set is an error even
/// when it is old. Then the monotonic rule applies:
///
/// - an **older** version (`incoming.version < local.version`) is ignored and the
///   local table is returned unchanged;
/// - an **equal or newer** version is unioned into the local table. Ids are only
///   ever added: a revocation is permanent, and a newer set cannot un-revoke an
///   id by omission.
pub fn propagate(
    local: &Revoked,
    incoming: &RevocationSet,
    owner_public_key_b64: &str,
) -> Result<Revoked, ZeroError> {
    verify_revocation_set(incoming, owner_public_key_b64)?;
    if incoming.version < local.version {
        return Ok(local.clone());
    }
    let mut unioned = local.revoked.clone();
    unioned.extend(incoming.revoked.iter().cloned());
    Ok(Revoked {
        version: local.version.max(incoming.version),
        revoked: unioned,
    })
}

/// Refuse a revoked device at any acceptance point (discovery, relay, state).
///
/// This is the shared gate: [`Revoked::is_revoked`] answers the question and
/// this turns it into the crate's typed denial so every caller reports the same
/// thing.
pub fn ensure_not_revoked(revoked: &Revoked, device_id: &str) -> Result<(), ZeroError> {
    if revoked.is_revoked(device_id) {
        return Err(denied(format!(
            "device `{device_id}` is revoked and cannot participate"
        )));
    }
    Ok(())
}

/// Apply a replicated update only when its sender is not revoked.
///
/// This wraps [`crate::state::apply`]: a sender in the revocation table is
/// `Rejected` before the update is examined, so a node that has seen the signed
/// revocation refuses the revoked device's updates even if the device still
/// holds a key.
pub fn accept_update(
    revoked: &Revoked,
    current: &MembershipState,
    update: &StateUpdate,
    sender_id: &str,
    owner_public_key_b64: &str,
) -> ApplyOutcome {
    if revoked.is_revoked(sender_id) {
        return ApplyOutcome::Rejected {
            reason: format!("sender `{sender_id}` is revoked; its updates are refused"),
        };
    }
    apply(current, update, owner_public_key_b64)
}

/// Remove every revoked device from local discovery and presence tables.
///
/// Returns the ids that were dropped, ascending. Relay has no peer table — its
/// per-hop approval is [`ensure_not_revoked`] plus the signed state's own
/// `revoked` set — so dropping the node from the two tables here and gating
/// relay with that function is the whole propagation path.
pub fn drop_revoked(
    revoked: &Revoked,
    discovery: &mut Discovery,
    presence: &mut PresenceTable,
) -> Vec<String> {
    let mut dropped: BTreeSet<String> = BTreeSet::new();
    for device_id in discovery::peers(discovery).keys() {
        if revoked.is_revoked(device_id) {
            dropped.insert(device_id.clone());
        }
    }
    for view in presence.public_view() {
        if revoked.is_revoked(&view.device_id) {
            dropped.insert(view.device_id);
        }
    }
    for device_id in &dropped {
        discovery::remove(discovery, device_id);
        presence.remove(device_id);
    }
    dropped.into_iter().collect()
}

/// What a partition can currently reach.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionView {
    /// Delegate ids this partition can reach.
    #[serde(default)]
    pub reachable_delegates: BTreeSet<String>,
    /// True when the owner root is reachable.
    pub has_owner: bool,
}

impl PartitionView {
    /// A view with no reachable delegate and no owner.
    pub fn new() -> Self {
        Self::default()
    }

    /// A view that can reach the owner root.
    pub fn owner_reachable() -> Self {
        Self {
            reachable_delegates: BTreeSet::new(),
            has_owner: true,
        }
    }

    /// A view with the given reachable delegates.
    pub fn with_delegates(delegates: impl IntoIterator<Item = String>) -> Self {
        Self {
            reachable_delegates: delegates.into_iter().collect(),
            has_owner: false,
        }
    }
}

/// Whether this node may write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The owner root or a quorum of delegates is reachable.
    Write,
    /// The write is refused. The reason is for logs and tests; the caller must
    /// not write locally.
    Refuse {
        /// Why the write was refused.
        reason: String,
    },
}

impl Decision {
    /// True for [`Decision::Write`].
    pub fn is_write(&self) -> bool {
        matches!(self, Self::Write)
    }

    /// The refusal reason, when refused.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Write => None,
            Self::Refuse { reason } => Some(reason),
        }
    }
}

/// Decide whether this partition may write.
///
/// Rules (LCK-10, MESH-02):
///
/// - no signed membership state yet — refuse; there is no authority to write
///   under, and this function never falls back to a silent local write;
/// - the owner root is reachable — write;
/// - otherwise count the reachable delegates that are named in `membership` and
///   not revoked in `state`. At or above `threshold` — write; below it — refuse
///   as a minority.
///
/// Holding a delegate signing key is not enough: in a minority partition the
/// node has a key and no quorum, so the write is refused.
///
/// `state` must already have been checked with
/// [`verify_state`](crate::state::verify_state) or
/// [`apply`](crate::state::apply); this function reads its version and revoked
/// set and does not re-verify the snapshot.
pub fn can_write(
    state: &MembershipState,
    membership: &DelegateSet,
    partition: PartitionView,
) -> Decision {
    if state.version == 0 {
        return Decision::Refuse {
            reason: "no owner-signed membership state; refusing a silent local write".to_string(),
        };
    }
    if let Err(error) = membership.validate() {
        return Decision::Refuse {
            reason: format!(
                "invalid delegate set ({}: {})",
                error.code().as_str(),
                error.message()
            ),
        };
    }
    if partition.has_owner {
        return Decision::Write;
    }

    let reachable = partition
        .reachable_delegates
        .iter()
        .filter(|device_id| membership.is_delegate(device_id) && !state.revoked.contains(*device_id))
        .count();
    let required = usize::from(membership.threshold);
    if reachable >= required {
        Decision::Write
    } else {
        Decision::Refuse {
            reason: format!(
                "minority partition: {reachable} of {required} delegates reachable; write refused"
            ),
        }
    }
}

fn framed(domain: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + fields.len() * 4 + 64);
    out.extend_from_slice(domain);
    for field in fields {
        let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

fn put_str(out: &mut Vec<u8>, value: &str) -> Result<(), ZeroError> {
    let len = u32::try_from(value.len())
        .map_err(|_| limit("a revocation field exceeds the u32 length prefix"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_count(out: &mut Vec<u8>, count: usize, max: usize, field: &str) -> Result<(), ZeroError> {
    if count > max {
        return Err(limit(format!(
            "revocation set has {count} {field}; the limit is {max}"
        )));
    }
    let count =
        u32::try_from(count).map_err(|_| limit(format!("{field} count exceeds a u32 prefix")))?;
    out.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

fn validate_device_id(device_id: &str) -> Result<(), ZeroError> {
    if device_id.len() != 64 || !device_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(
            "device id must be 64 hex characters (the blake3 hash of the public key)",
        ));
    }
    Ok(())
}

fn refused(message: impl Into<String>) -> QuorumDecision {
    QuorumDecision::Refused {
        reason: message.into(),
    }
}

fn denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyDenied, message)
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn limit(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

type Result<T, E = ZeroError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::IpAddr;

    use crate::discovery::{accept, sign_announce, AcceptOutcome};
    use crate::identity::DeviceRecord;
    use crate::presence::{LinkKind, PowerState};
    use crate::relay::{seal, RelayNode, RelayPolicy, KEY_BYTES};
    use crate::state::{sign_update, MembershipState};

    const NOW: i64 = 1_700_000_000_000;
    const ANNOUNCE_TTL: i64 = 60_000;

    fn key() -> KeyPair {
        KeyPair::generate().expect("device key")
    }

    fn add_device(state: &mut MembershipState, device: &KeyPair, name: Option<&str>) {
        state.devices.insert(
            device.device_id().to_string(),
            DeviceRecord {
                device_id: device.device_id().to_string(),
                public_key_b64: device.public_key_b64(),
                name: name.map(str::to_string),
                added_ms: NOW,
                revoked: false,
                rotated_from: None,
            },
        );
        if let Some(name) = name {
            state
                .names
                .insert(device.device_id().to_string(), name.to_string());
        }
    }

    fn state_with(owner: &KeyPair, members: &[&KeyPair]) -> MembershipState {
        let genesis = MembershipState::new(owner, NOW).expect("genesis state");
        if members.is_empty() {
            return genesis;
        }
        let mut next = genesis.clone();
        next.version = 2;
        for device in members {
            add_device(&mut next, device, None);
        }
        sign_update(owner, &mut next, 1, NOW + 1)
            .expect("signed membership")
            .state
    }

    fn state_with_revoked(
        owner: &KeyPair,
        members: &[&KeyPair],
        revoked: &KeyPair,
    ) -> MembershipState {
        let state = state_with(owner, members);
        let mut next = state.clone();
        next.version = state.version + 1;
        next.devices
            .get_mut(revoked.device_id())
            .expect("revoked member")
            .revoked = true;
        next.revoked.insert(revoked.device_id().to_string());
        sign_update(owner, &mut next, state.version, NOW + 2)
            .expect("revocation state")
            .state
    }

    fn update_by(author: &KeyPair, members: &[&KeyPair], now_ms: i64) -> StateUpdate {
        let base = MembershipState::new(author, NOW).expect("genesis state");
        let mut next = base.clone();
        next.version = 2;
        for device in members {
            add_device(&mut next, device, None);
        }
        sign_update(author, &mut next, 1, now_ms).expect("signed update")
    }

    fn delegate_set(threshold: u8, keys: &[&KeyPair]) -> DelegateSet {
        DelegateSet::new(
            threshold,
            keys.iter()
                .map(|device| (device.device_id().to_string(), device.public_key_b64()))
                .collect(),
        )
        .expect("delegate set")
    }

    fn votes_for(keys: &[&KeyPair], update: &StateUpdate) -> Vec<DelegateVote> {
        keys.iter()
            .map(|device| sign_vote(device, update).expect("vote"))
            .collect()
    }

    fn refusal(result: Result<QuorumDecision, ZeroError>) -> String {
        match result.expect("a quorum decision, not a parse error") {
            QuorumDecision::Refused { reason } => reason,
            QuorumDecision::Accepted => panic!("expected Refused, got Accepted"),
        }
    }

    fn revoke_set(owner: &KeyPair, version: u64, ids: &[&str]) -> RevocationSet {
        sign_revocation_set(
            owner,
            version,
            ids.iter().map(|id| (*id).to_string()).collect(),
        )
        .expect("signed revocation set")
    }

    #[test]
    fn a_minority_below_threshold_cannot_write() {
        let (delegate_one, delegate_two, delegate_three) = (key(), key(), key());
        let author = key();
        let set = delegate_set(
            3,
            &[&delegate_one, &delegate_two, &delegate_three],
        );
        let update = update_by(&author, &[&author], NOW);
        let votes = votes_for(&[&delegate_one, &delegate_two], &update);

        let reason = refusal(check_quorum(&update, &set, &votes, NOW));
        assert!(reason.contains("minority partition"), "{reason}");
        assert!(reason.contains("2 vote(s), 3 required"), "{reason}");

        // The same minority is refused for a local write, even though the node
        // holds one of the delegate signing keys.
        let state = state_with(&delegate_one, &[&delegate_one, &delegate_two]);
        let decision = can_write(
            &state,
            &set,
            PartitionView::with_delegates([delegate_one.device_id().to_string()]),
        );
        assert!(!decision.is_write());
        assert!(
            decision
                .reason()
                .is_some_and(|reason| reason.contains("minority partition")),
            "{decision:?}"
        );
    }

    #[test]
    fn threshold_delegates_accept_the_update() {
        let (delegate_one, delegate_two, delegate_three) = (key(), key(), key());
        let author = key();
        let set = delegate_set(
            3,
            &[&delegate_one, &delegate_two, &delegate_three],
        );
        let update = update_by(&author, &[&author], NOW);
        let votes = votes_for(&[&delegate_one, &delegate_two, &delegate_three], &update);

        assert_eq!(
            check_quorum(&update, &set, &votes, NOW).expect("quorum decision"),
            QuorumDecision::Accepted
        );
    }

    #[test]
    fn duplicate_voters_are_refused() {
        let (delegate_one, delegate_two) = (key(), key());
        let author = key();
        let set = delegate_set(2, &[&delegate_one, &delegate_two, &key()]);
        let update = update_by(&author, &[&author], NOW);
        let vote = sign_vote(&delegate_one, &update).expect("vote");
        let votes = vec![vote.clone(), vote];

        let reason = refusal(check_quorum(&update, &set, &votes, NOW));
        assert!(reason.contains("duplicate vote"), "{reason}");
    }

    #[test]
    fn votes_must_bind_the_exact_update_version_and_hash() {
        let (delegate_one, delegate_two, delegate_three) = (key(), key(), key());
        let author = key();
        let set = delegate_set(
            2,
            &[&delegate_one, &delegate_two, &delegate_three],
        );
        let update = update_by(&author, &[&author], NOW);

        let mut wrong_version = votes_for(&[&delegate_one, &delegate_two], &update);
        wrong_version[0].state_version += 1;
        let reason = refusal(check_quorum(&update, &set, &wrong_version, NOW));
        assert!(reason.contains("vote for version"), "{reason}");

        let mut wrong_hash = votes_for(&[&delegate_one, &delegate_two], &update);
        wrong_hash[1].state_hash = "0".repeat(64);
        let reason = refusal(check_quorum(&update, &set, &wrong_hash, NOW));
        assert!(reason.contains("does not bind this update hash"), "{reason}");

        // A vote for a different update of the same shape does not transfer.
        let other = update_by(&author, &[&author, &key()], NOW);
        let foreign_votes = votes_for(&[&delegate_one, &delegate_two], &other);
        let reason = refusal(check_quorum(&update, &set, &foreign_votes, NOW));
        assert!(reason.contains("does not bind this update hash"), "{reason}");
    }

    #[test]
    fn a_non_delegate_vote_is_refused() {
        let (delegate_one, delegate_two) = (key(), key());
        let outsider = key();
        let author = key();
        let set = delegate_set(2, &[&delegate_one, &delegate_two]);
        let update = update_by(&author, &[&author], NOW);
        let votes = votes_for(&[&delegate_one, &outsider], &update);

        let reason = refusal(check_quorum(&update, &set, &votes, NOW));
        assert!(reason.contains("not a known delegate"), "{reason}");
        assert!(reason.contains(outsider.device_id()), "{reason}");
    }

    #[test]
    fn a_tampered_vote_signature_is_refused() {
        let (delegate_one, delegate_two) = (key(), key());
        let author = key();
        let set = delegate_set(2, &[&delegate_one, &delegate_two]);
        let update = update_by(&author, &[&author], NOW);
        let mut votes = votes_for(&[&delegate_one, &delegate_two], &update);
        votes[1].signature_b64 = key().sign(b"some other payload");

        let reason = refusal(check_quorum(&update, &set, &votes, NOW));
        assert!(reason.contains("signature"), "{reason}");
    }

    #[test]
    fn the_owner_root_signature_satisfies_quorum_alone() {
        let owner = key();
        let delegates = [key(), key(), key()];
        let set = delegate_set(
            3,
            &[&delegates[0], &delegates[1], &delegates[2]],
        )
        .with_owner(owner.public_key_b64())
        .expect("quorum with owner");

        let update = update_by(&owner, &[&owner], NOW);
        assert_eq!(
            check_quorum(&update, &set, &[], NOW).expect("quorum decision"),
            QuorumDecision::Accepted
        );

        // The owner may also be one delegate in a threshold. Its vote counts
        // once, and the other votes must still reach the threshold.
        let mixed = delegate_set(2, &[&owner, &delegates[0]]);
        let update = update_by(&delegates[0], &[&delegates[0]], NOW);
        let votes = votes_for(&[&owner], &update);
        let reason = refusal(check_quorum(&update, &mixed, &votes, NOW));
        assert!(reason.contains("1 vote(s), 2 required"), "{reason}");

        let votes = votes_for(&[&owner, &delegates[0]], &update);
        assert_eq!(
            check_quorum(&update, &mixed, &votes, NOW).expect("quorum decision"),
            QuorumDecision::Accepted
        );
    }

    #[test]
    fn a_future_dated_update_is_refused() {
        let (delegate_one, delegate_two) = (key(), key());
        let author = key();
        let set = delegate_set(2, &[&delegate_one, &delegate_two]);
        let update = update_by(&author, &[&author], NOW + 10);
        let votes = votes_for(&[&delegate_one, &delegate_two], &update);

        let reason = refusal(check_quorum(&update, &set, &votes, NOW));
        assert!(reason.contains("signed in the future"), "{reason}");
    }

    #[test]
    fn a_malformed_delegate_set_is_typed() {
        let delegate = key();
        let good: BTreeMap<String, String> = [(
            delegate.device_id().to_string(),
            delegate.public_key_b64(),
        )]
        .into_iter()
        .collect();

        assert_eq!(
            DelegateSet::new(0, good.clone())
                .expect_err("zero threshold")
                .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            DelegateSet::new(2, good.clone())
                .expect_err("threshold above the delegate count")
                .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            DelegateSet::new(1, BTreeMap::new())
                .expect_err("empty delegate set")
                .code(),
            ErrorCode::InvalidInput
        );

        let mismatched: BTreeMap<String, String> = [(
            "0".repeat(64),
            delegate.public_key_b64(),
        )]
        .into_iter()
        .collect();
        assert_eq!(
            DelegateSet::new(1, mismatched)
                .expect_err("id does not match its key")
                .code(),
            ErrorCode::InvalidInput
        );

        let malformed: BTreeMap<String, String> =
            [(delegate.device_id().to_string(), "not base64".to_string())]
                .into_iter()
                .collect();
        assert_eq!(
            DelegateSet::new(1, malformed)
                .expect_err("malformed public key")
                .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            DelegateSet::new(1, good)
                .expect("valid set")
                .with_owner("not base64")
                .expect_err("malformed owner key")
                .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn a_revocation_signature_is_verified() {
        let owner = key();
        let victim = key();
        let mut set = revoke_set(&owner, 1, &[victim.device_id()]);
        verify_revocation_set(&set, &owner.public_key_b64()).expect("owner-signed set");

        set.revoked.insert(key().device_id().to_string());
        assert_eq!(
            verify_revocation_set(&set, &owner.public_key_b64())
                .expect_err("changed ids")
                .code(),
            ErrorCode::PolicyDenied
        );

        let foreign = key();
        assert_eq!(
            verify_revocation_set(&set, &foreign.public_key_b64())
                .expect_err("foreign owner")
                .code(),
            ErrorCode::PolicyDenied
        );

        let mut self_revoke = revoke_set(&owner, 1, &[]);
        self_revoke.revoked.insert(owner.device_id().to_string());
        let signing = sign_revocation_set(
            &owner,
            1,
            [owner.device_id().to_string()].into_iter().collect(),
        );
        assert!(signing.is_err(), "the owner cannot sign its own revocation");
        assert!(verify_revocation_set(&self_revoke, &owner.public_key_b64()).is_err());
    }

    #[test]
    fn an_older_revocation_is_ignored() {
        let owner = key();
        let first = key();
        let second = key();
        let local = Revoked {
            version: 2,
            revoked: [first.device_id().to_string()].into_iter().collect(),
        };
        let incoming = revoke_set(&owner, 1, &[second.device_id()]);

        let applied = propagate(&local, &incoming, &owner.public_key_b64()).expect("propagate");
        assert_eq!(applied, local);
        assert!(!applied.is_revoked(second.device_id()));
        assert!(applied.is_revoked(first.device_id()));
    }

    #[test]
    fn a_newer_revocation_unions_the_ids() {
        let owner = key();
        let first = key();
        let second = key();
        let local = Revoked {
            version: 1,
            revoked: [first.device_id().to_string()].into_iter().collect(),
        };

        let equal = revoke_set(&owner, 1, &[second.device_id()]);
        let unioned = propagate(&local, &equal, &owner.public_key_b64()).expect("propagate");
        assert_eq!(unioned.version, 1);
        assert!(unioned.is_revoked(first.device_id()));
        assert!(unioned.is_revoked(second.device_id()));

        let newer = revoke_set(&owner, 3, &[key().device_id()]);
        let unioned = propagate(&unioned, &newer, &owner.public_key_b64()).expect("propagate");
        assert_eq!(unioned.version, 3);
        assert!(unioned.is_revoked(first.device_id()));
        assert!(unioned.is_revoked(second.device_id()));

        // An unauthenticated older set is an error, not a silent ignore.
        let mut forged = revoke_set(&owner, 4, &[]);
        forged.version = 4;
        forged.signature_b64 = key().sign(b"not this revocation");
        assert_eq!(
            propagate(&unioned, &forged, &owner.public_key_b64())
                .expect_err("forged signature")
                .code(),
            ErrorCode::PolicyDenied
        );
    }

    #[test]
    fn revocation_propagates_between_two_nodes() {
        let owner = key();
        let victim = key();
        let peer = key();
        let relay = key();
        let membership = state_with(&owner, &[&victim, &peer, &relay]);

        // Node A revokes the victim and keeps its own table.
        let signed = revoke_set(&owner, 1, &[victim.device_id()]);
        let node_a = propagate(&Revoked::new(), &signed, &owner.public_key_b64())
            .expect("node A applies the revocation");
        assert!(node_a.is_revoked(victim.device_id()));

        // Node B has not seen the revocation yet: it still accepts the victim.
        let mut discovery = Discovery::default();
        let announce = sign_announce(
            &victim,
            Some("victim"),
            &["192.168.1.20".parse::<IpAddr>().expect("address")],
            5000,
            "victimnonce1",
            NOW,
            NOW + ANNOUNCE_TTL,
        )
        .expect("signed announce");
        assert_eq!(
            accept(&mut discovery, &announce, &membership, NOW),
            AcceptOutcome::Accepted
        );
        let mut presence = PresenceTable::default();
        presence
            .announce(
                victim.device_id(),
                LinkKind::Wifi,
                PowerState::Plugged,
                NOW,
            )
            .expect("presence");
        assert_eq!(discovery::peers(&discovery).len(), 1);
        assert!(presence.get(victim.device_id()).is_some());

        // Node B receives the signed revocation and applies it.
        let node_b = propagate(&Revoked::new(), &signed, &owner.public_key_b64())
            .expect("node B applies the revocation");
        let dropped = drop_revoked(&node_b, &mut discovery, &mut presence);
        assert_eq!(dropped, vec![victim.device_id().to_string()]);
        assert!(discovery::peers(&discovery).is_empty());
        assert!(presence.get(victim.device_id()).is_none());

        // The shared gates now refuse the revoked device everywhere.
        assert_eq!(
            ensure_not_revoked(&node_b, victim.device_id())
                .expect_err("revoked device")
                .code(),
            ErrorCode::PolicyDenied
        );
        assert!(ensure_not_revoked(&node_b, peer.device_id()).is_ok());

        let update = update_by(&owner, &[&owner], NOW);
        match accept_update(
            &node_b,
            &membership,
            &update,
            victim.device_id(),
            &owner.public_key_b64(),
        ) {
            ApplyOutcome::Rejected { reason } => assert!(reason.contains("revoked"), "{reason}"),
            other => panic!("expected Rejected, got {other:?}"),
        }

        let revoked_state = state_with_revoked(&owner, &[&victim, &peer, &relay], &victim);
        let node = RelayNode::new(
            relay.device_id(),
            RelayPolicy {
                approved_relays: [relay.device_id().to_string()].into_iter().collect(),
                ..RelayPolicy::default()
            },
        );
        let envelope = seal(b"opaque payload", &[0x5a; KEY_BYTES])
            .expect("sealed payload")
            .envelope(
                "00000000000000000000000000000001",
                victim.device_id(),
                peer.device_id(),
                NOW,
                60_000,
            );
        let error = node
            .forward(&envelope, &revoked_state, NOW)
            .expect_err("a revoked source is refused");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("revoked"), "{error}");
    }

    #[test]
    fn a_partition_heals_with_a_higher_version() {
        let owner = key();
        let (delegate_one, delegate_two, delegate_three) = (key(), key(), key());
        let set = delegate_set(
            2,
            &[&delegate_one, &delegate_two, &delegate_three],
        );
        let state = state_with(&owner, &[&owner, &delegate_one, &delegate_two, &delegate_three]);

        // Minority: one reachable delegate, no owner.
        let minority = can_write(
            &state,
            &set,
            PartitionView::with_delegates([delegate_one.device_id().to_string()]),
        );
        assert!(!minority.is_write());

        // Healed: two reachable delegates meet the threshold.
        let healed = can_write(
            &state,
            &set,
            PartitionView::with_delegates([
                delegate_one.device_id().to_string(),
                delegate_two.device_id().to_string(),
            ]),
        );
        assert!(healed.is_write(), "{healed:?}");

        // An owner-root node writes without any delegate.
        assert!(can_write(&state, &set, PartitionView::owner_reachable()).is_write());

        // Revocations resume at a higher version after the heal, and the older
        // version is ignored.
        let first = revoke_set(&owner, 1, &[delegate_three.device_id()]);
        let applied = propagate(&Revoked::new(), &first, &owner.public_key_b64())
            .expect("version 1 revocation");
        assert_eq!(applied.version, 1);
        let newer = revoke_set(&owner, 2, &[key().device_id()]);
        let applied = propagate(&applied, &newer, &owner.public_key_b64())
            .expect("version 2 revocation");
        assert_eq!(applied.version, 2);
        let stale = revoke_set(&owner, 1, &[key().device_id()]);
        assert_eq!(
            propagate(&applied, &stale, &owner.public_key_b64()).expect("older is ignored"),
            applied
        );

        // A revoked delegate no longer counts toward the quorum.
        let mut next = state.clone();
        next.version = state.version + 1;
        next.devices
            .get_mut(delegate_two.device_id())
            .expect("delegate")
            .revoked = true;
        next.revoked.insert(delegate_two.device_id().to_string());
        let next = sign_update(&owner, &mut next, state.version, NOW + 3)
            .expect("signed revocation state")
            .state;
        let decision = can_write(
            &next,
            &set,
            PartitionView::with_delegates([
                delegate_one.device_id().to_string(),
                delegate_two.device_id().to_string(),
            ]),
        );
        assert!(!decision.is_write(), "{decision:?}");
    }

    #[test]
    fn no_write_happens_without_authority() {
        let owner = key();
        let delegate = key();
        let set = delegate_set(1, &[&delegate]);

        // No signed state: refuse rather than write locally.
        let empty = MembershipState::empty(owner.public_key_b64()).expect("genesis placeholder");
        let decision = can_write(&empty, &set, PartitionView::owner_reachable());
        assert!(!decision.is_write());
        assert!(
            decision
                .reason()
                .is_some_and(|reason| reason.contains("silent local write")),
            "{decision:?}"
        );

        // A reachable id that is not a delegate does not count.
        let state = state_with(&owner, &[&owner, &delegate]);
        let stranger = key();
        let decision = can_write(
            &state,
            &set,
            PartitionView::with_delegates([stranger.device_id().to_string()]),
        );
        assert!(!decision.is_write(), "{decision:?}");
    }

    #[test]
    fn quorum_and_revocation_types_survive_serde() {
        let owner = key();
        let victim = key();
        let set = revoke_set(&owner, 2, &[victim.device_id()]);
        let json = serde_json::to_string(&set).expect("revocation serialise");
        let restored: RevocationSet = serde_json::from_str(&json).expect("revocation parse");
        assert_eq!(restored, set);
        verify_revocation_set(&restored, &owner.public_key_b64()).expect("restored verifies");

        let tableau = Revoked::from_set(&set);
        let json = serde_json::to_string(&tableau).expect("revoked serialise");
        let restored: Revoked = serde_json::from_str(&json).expect("revoked parse");
        assert_eq!(restored, tableau);
        assert!(restored.is_revoked(victim.device_id()));

        let delegates = delegate_set(1, &[&victim]);
        let json = serde_json::to_string(&delegates).expect("delegate serialise");
        let restored: DelegateSet = serde_json::from_str(&json).expect("delegate parse");
        assert_eq!(restored, delegates);
        restored.validate().expect("restored set validates");
    }
}
