//! Signed, versioned mesh membership state (T-MESH-02, MESH-02, MESH-09,
//! MESH-11, MESH-15).
//!
//! [`MembershipState`] is a complete snapshot of the mesh: the approved devices,
//! the revoked device ids, and the in-mesh name registry. The owner root key
//! signs the canonical bytes of the snapshot, so every peer can verify that a
//! transferred state came from the root of trust rather than from a member.
//!
//! There is no privileged node: every peer holds the same owner public key and
//! applies the same rules. Devices replicate whole snapshots with
//! [`StateUpdate`]; [`apply`] accepts only owner-signed states, orders them by
//! [`MembershipState::version`], and never silently picks a side when two
//! different states claim the same version.
//!
//! The security property this slice exists for: a stolen device key can sign
//! anything with its own key, but no peer verifies device signatures for
//! membership. In particular it cannot forge a revocation or an eviction,
//! because [`apply`] and [`verify_state`] check the owner public key only
//! (MESH-09's "a stolen device cannot evict others").
//!
//! Threshold delegates and the audit log are deferred; see `docs/mesh.md`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, ZeroError};

use crate::identity::{device_id_for, verify, DeviceRecord, KeyPair};

/// Domain separator for a signed membership snapshot.
pub const STATE_DOMAIN: &[u8] = b"zero.mesh.membership.v1\0";

/// Domain separator for a signed snapshot envelope.
pub const UPDATE_DOMAIN: &[u8] = b"zero.mesh.state-update.v1\0";

/// Largest snapshot [`canonical_bytes`] will produce: 1 MiB.
pub const MAX_STATE_BYTES: usize = 1024 * 1024;

/// Most device records a snapshot may carry.
pub const MAX_DEVICES: usize = 4096;

/// Most revoked ids a snapshot may carry.
pub const MAX_REVOKED: usize = 8192;

/// Most name entries a snapshot may carry.
pub const MAX_NAMES: usize = 4096;

/// Longest allowed device name, in bytes.
pub const MAX_NAME_BYTES: usize = 64;

/// A full, signed membership snapshot.
///
/// `devices`, `revoked`, and `names` are sorted maps and sets, so the canonical
/// encoding is independent of insertion order. `signature_b64` is the owner
/// root's Ed25519 signature over [`canonical_bytes`] and is **not** covered by
/// its own signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipState {
    /// Monotonic snapshot version: 1 for the first signed state, one greater
    /// for each owner-signed successor.
    pub version: u64,
    /// Owner-root epoch. Reserved for an owner re-key; this slice signs and
    /// replicates it but assigns no further meaning.
    pub epoch: u64,
    /// Approved devices, including revoked records, keyed by device id.
    pub devices: BTreeMap<String, DeviceRecord>,
    /// Revoked device ids, including ids whose record was evicted.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub revoked: BTreeSet<String>,
    /// Stable in-mesh names, keyed by device id (MESH-11).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub names: BTreeMap<String, String>,
    /// When the owner signed this snapshot, in milliseconds since the Unix
    /// epoch.
    pub updated_ms: i64,
    /// The owner root's device id; the only id whose signatures are accepted.
    pub signed_by: String,
    /// Standard padded base64 Ed25519 signature by the owner root.
    #[serde(default)]
    pub signature_b64: String,
}

impl MembershipState {
    /// An unsigned version-0 placeholder for a node that has no state yet.
    ///
    /// It records the owner device id so [`apply`] can refuse a bootstrap from
    /// a different mesh. It cannot be signed or canonicalised: the first
    /// replicated snapshot is owner-signed version 1.
    pub fn empty(owner_public_key_b64: impl AsRef<str>) -> Result<Self, ZeroError> {
        let owner_public_key_b64 = owner_public_key_b64.as_ref();
        // Reject a malformed key here rather than at the first replicated
        // update; the caller uses this value as the mesh's root of trust.
        let signed_by = device_id_for(owner_public_key_b64)?;
        Ok(Self {
            version: 0,
            epoch: 0,
            devices: BTreeMap::new(),
            revoked: BTreeSet::new(),
            names: BTreeMap::new(),
            updated_ms: 0,
            signed_by,
            signature_b64: String::new(),
        })
    }

    /// The first signed snapshot (version 1) for a new mesh.
    pub fn new(owner_key: &KeyPair, now_ms: i64) -> Result<Self, ZeroError> {
        let mut state = Self::empty(owner_key.public_key_b64())?;
        state.version = 1;
        sign_state(owner_key, &mut state, now_ms)?;
        Ok(state)
    }

    /// True for the version-0 unsigned placeholder produced by
    /// [`MembershipState::empty`].
    fn is_unsigned_genesis(&self) -> bool {
        self.version == 0
            && self.epoch == 0
            && self.devices.is_empty()
            && self.revoked.is_empty()
            && self.names.is_empty()
            && self.updated_ms == 0
            && self.signature_b64.is_empty()
    }
}

/// A replicated snapshot plus the base version its signer built on.
///
/// `signature` is the owner root's signature over [`StateUpdate::canonical_bytes`],
/// which binds `base_version` as well as the snapshot content. `state` carries
/// its own independent owner signature; [`apply`] requires both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateUpdate {
    /// The version the signer observed before producing `state`; must equal
    /// `state.version - 1`.
    pub base_version: u64,
    /// The complete owner-signed snapshot.
    pub state: MembershipState,
    /// Standard padded base64 Ed25519 signature by the owner root over the
    /// update envelope.
    pub signature: String,
}

impl StateUpdate {
    /// Canonical envelope bytes: the domain, `base_version`, and the canonical
    /// snapshot bytes, each length-prefixed. `state.signature_b64` is excluded
    /// (it is deterministic, but the envelope must not depend on the inner
    /// signature's encoding).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ZeroError> {
        let state = canonical_bytes(&self.state)?;
        Ok(framed(
            UPDATE_DOMAIN,
            &[&self.base_version.to_be_bytes(), &state],
        ))
    }
}

/// Result of offering a [`StateUpdate`] to [`apply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The update was valid and newer; the returned snapshot replaces local
    /// state.
    Applied(MembershipState),
    /// The peer already holds this exact snapshot at this version.
    AlreadyApplied,
    /// The update is authentic but cannot be reconciled without owner action:
    /// same version with different content, or a version gap after a genesis.
    Conflict {
        /// Why the update conflicts.
        reason: String,
    },
    /// The update failed authentication or ordering rules and must not be
    /// stored.
    Rejected {
        /// Why the update was rejected.
        reason: String,
    },
}

use ApplyOutcome::{AlreadyApplied, Applied, Conflict, Rejected};

/// The canonical, deterministic bytes the owner signs for a snapshot.
///
/// Byte layout, all integers big-endian:
///
/// ```text
/// "zero.mesh.membership.v1\0"         domain separator
/// version                            u64
/// epoch                              u64
/// device count                       u32
/// repeated devices, ascending id:
///   device id                        u32 length + UTF-8 bytes
///   public_key_b64                   u32 length + UTF-8 bytes
///   name present                     u8 (0 or 1)
///     name                           u32 length + UTF-8 bytes when present
///   added_ms                         i64
///   revoked                          u8 (0 or 1)
///   rotated_from present             u8 (0 or 1)
///     rotated_from                   u32 length + UTF-8 bytes when present
/// revoked count                      u32
/// repeated revoked ids, ascending:   u32 length + UTF-8 bytes
/// name count                         u32
/// repeated names, ascending id:
///   device id                        u32 length + UTF-8 bytes
///   name                             u32 length + UTF-8 bytes
/// updated_ms                         i64
/// signed_by                          u32 length + UTF-8 bytes
/// ```
///
/// Every variable-length field is length-prefixed, so bytes cannot be moved
/// across a boundary to produce a second encoding of the same snapshot. The
/// signature is excluded, because it is produced over these bytes.
///
/// Validation is part of canonicalisation: malformed ids, a record whose
/// device id does not match its key or its map key, a revoked flag that
/// disagrees with the revoked set, an unknown or revoked name entry, duplicate
/// names (compared ASCII case-insensitively), the owner id in `revoked`, a
/// version of zero, and any count or length above its [`MAX_*`](MAX_STATE_BYTES)
/// limit are refused.
pub fn canonical_bytes(state: &MembershipState) -> Result<Vec<u8>, ZeroError> {
    validate(state)?;

    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(STATE_DOMAIN);
    out.extend_from_slice(&state.version.to_be_bytes());
    out.extend_from_slice(&state.epoch.to_be_bytes());

    put_count(&mut out, state.devices.len(), MAX_DEVICES, "devices")?;
    for (device_id, record) in &state.devices {
        put_str(&mut out, device_id)?;
        put_str(&mut out, &record.public_key_b64)?;
        match &record.name {
            Some(name) => {
                out.push(1);
                put_str(&mut out, name)?;
            }
            None => out.push(0),
        }
        out.extend_from_slice(&record.added_ms.to_be_bytes());
        out.push(u8::from(record.revoked));
        match &record.rotated_from {
            Some(rotated_from) => {
                out.push(1);
                put_str(&mut out, rotated_from)?;
            }
            None => out.push(0),
        }
    }

    put_count(&mut out, state.revoked.len(), MAX_REVOKED, "revoked ids")?;
    for device_id in &state.revoked {
        put_str(&mut out, device_id)?;
    }

    put_count(&mut out, state.names.len(), MAX_NAMES, "names")?;
    for (device_id, name) in &state.names {
        put_str(&mut out, device_id)?;
        put_str(&mut out, name)?;
    }

    out.extend_from_slice(&state.updated_ms.to_be_bytes());
    put_str(&mut out, &state.signed_by)?;

    if out.len() > MAX_STATE_BYTES {
        return Err(limit(format!(
            "membership state is {} bytes; the limit is {MAX_STATE_BYTES}",
            out.len()
        )));
    }
    Ok(out)
}

/// Sign `state` with the owner root key, setting `updated_ms` and `signed_by`.
///
/// This is a signing primitive; it cannot itself prove that `owner_key` is the
/// root of trust. Authority is enforced on receipt: [`verify_state`] and
/// [`apply`] compare `signed_by` with the owner public key and verify the
/// signature against it. A device key can therefore produce a signature, but
/// no peer accepts a device-signed snapshot.
pub fn sign_state(owner_key: &KeyPair, state: &mut MembershipState, now_ms: i64) -> Result<()> {
    if state.version == 0 {
        return Err(invalid(
            "a signed membership state must have version 1 or greater",
        ));
    }
    let previous_updated_ms = state.updated_ms;
    let previous_signed_by = std::mem::take(&mut state.signed_by);
    let previous_signature = std::mem::take(&mut state.signature_b64);
    state.updated_ms = now_ms;
    state.signed_by = owner_key.device_id().to_string();
    match canonical_bytes(state) {
        Ok(bytes) => {
            state.signature_b64 = owner_key.sign(&bytes);
            Ok(())
        }
        Err(error) => {
            state.updated_ms = previous_updated_ms;
            state.signed_by = previous_signed_by;
            state.signature_b64 = previous_signature;
            Err(error)
        }
    }
}

/// Sign a snapshot and its envelope, ready to replicate.
///
/// `state.version` must be exactly `base_version + 1`; a gap means the caller
/// built the snapshot on a version it did not name.
pub fn sign_update(
    owner_key: &KeyPair,
    state: &mut MembershipState,
    base_version: u64,
    now_ms: i64,
) -> Result<StateUpdate> {
    let expected = base_version
        .checked_add(1)
        .ok_or_else(|| invalid("base version overflows the version counter"))?;
    if state.version != expected {
        return Err(invalid(format!(
            "state version {} does not follow base version {base_version}",
            state.version
        )));
    }
    sign_state(owner_key, state, now_ms)?;
    let mut update = StateUpdate {
        base_version,
        state: state.clone(),
        signature: String::new(),
    };
    update.signature = owner_key.sign(&update.canonical_bytes()?);
    Ok(update)
}

/// Verify that `state` is a well-formed snapshot signed by the owner root.
///
/// Checks, in order:
///
/// 1. `signed_by` is the device id derived from `owner_public_key_b64`
///    (`zero.pol.denied` otherwise);
/// 2. the snapshot validates and canonicalises;
/// 3. `revoked` does not contain the owner's own id;
/// 4. the Ed25519 signature verifies against the owner public key
///    (`zero.pol.denied`).
///
/// A tampered field, a device-signed snapshot, or a snapshot from another
/// owner all fail.
pub fn verify_state(state: &MembershipState, owner_public_key_b64: &str) -> Result<(), ZeroError> {
    let owner_id = device_id_for(owner_public_key_b64)?;
    if state.signed_by != owner_id {
        return Err(denied(
            "membership state is not attributed to the owner root key",
        ));
    }
    if state.revoked.contains(&state.signed_by) {
        return Err(denied(
            "membership state revokes the owner root and cannot be accepted",
        ));
    }
    let bytes = canonical_bytes(state)?;
    verify(owner_public_key_b64, &bytes, &state.signature_b64)
        .map_err(|_| denied("membership state is not signed by the owner root"))
}

/// Apply a replicated update to local state.
///
/// Authentication comes first: the envelope signature and the snapshot
/// signature must both verify against `owner_public_key_b64`, and the snapshot
/// must be structurally valid. Only the owner root is accepted, so a device key
/// cannot add, revoke, evict, rename, or re-sign membership — the stolen-device
/// guarantee.
///
/// Ordering then follows these rules:
///
/// - **Unsigned genesis.** A version-0 placeholder from [`MembershipState::empty`]
///   accepts its first owner-signed version-1 snapshot, provided the
///   placeholder names the same owner.
/// - **Same version.** Identical canonical content is [`ApplyOutcome::AlreadyApplied`];
///   different content is [`ApplyOutcome::Conflict`]. No side is picked.
/// - **Lower version.** Rejected as a rollback, even when the old snapshot is
///   authentically owner-signed.
/// - **Owner record.** Once the current snapshot carries the owner root's own
///   device record, a successor may not evict it; root rotation is deferred, so
///   the root record is permanent.
/// - **Higher version.** Applied. Snapshots are complete, so a peer that
///   skipped intermediate versions can still adopt a fresher signed state; the
///   version is the owner's total order.
///
/// `state.version` must equal `base_version + 1` in every case. Revocation and
/// eviction need no separate rule because only the owner can sign the snapshot
/// at all, and [`verify_state`] refuses a snapshot that revokes the owner's own
/// id. Threshold delegates are deferred.
pub fn apply(
    current: &MembershipState,
    update: &StateUpdate,
    owner_public_key_b64: &str,
) -> ApplyOutcome {
    let owner_id = match device_id_for(owner_public_key_b64) {
        Ok(owner_id) => owner_id,
        Err(error) => return rejected(error),
    };

    if let Err(error) = update
        .canonical_bytes()
        .and_then(|bytes| verify(owner_public_key_b64, &bytes, &update.signature))
    {
        return Rejected {
            reason: format!(
                "state update is not signed by the owner root ({}: {})",
                error.code().as_str(),
                error.message()
            ),
        };
    }
    if let Err(error) = verify_state(&update.state, owner_public_key_b64) {
        return rejected(error);
    }

    let state = &update.state;
    match update.base_version.checked_add(1) {
        Some(expected) if state.version == expected => {}
        _ => {
            return Rejected {
                reason: format!(
                    "state version {} does not follow base version {}",
                    state.version, update.base_version
                ),
            }
        }
    }

    if current.version == 0 {
        if !current.is_unsigned_genesis() {
            return Rejected {
                reason: "local state has version 0 but is not an unsigned genesis placeholder"
                    .to_string(),
            };
        }
        if current.signed_by != owner_id {
            return Rejected {
                reason: "local genesis names a different owner root".to_string(),
            };
        }
        if state.version != 1 {
            return Conflict {
                reason: format!(
                    "the first replicated state must be version 1, not {}",
                    state.version
                ),
            };
        }
        return Applied(state.clone());
    }

    if state.version == current.version {
        let incoming = match canonical_bytes(state) {
            Ok(bytes) => bytes,
            Err(error) => return rejected(error),
        };
        let local = match canonical_bytes(current) {
            Ok(bytes) => bytes,
            Err(error) => return rejected(error),
        };
        return if local == incoming {
            AlreadyApplied
        } else {
            Conflict {
                reason: format!(
                    "two different membership states claim version {}",
                    state.version
                ),
            }
        };
    }

    if state.version < current.version {
        return Rejected {
            reason: format!(
                "rollback: state version {} is older than local version {}",
                state.version, current.version
            ),
        };
    }

    // The owner root's own device record, once present, is permanent in this
    // slice: root rotation is deferred, so a successor snapshot may not evict
    // it. It also cannot be revoked, because validation refuses an owner id in
    // the revoked set.
    if current.devices.contains_key(&state.signed_by)
        && !state.devices.contains_key(&state.signed_by)
    {
        return Rejected {
            reason: "an update cannot evict the owner root's own device record".to_string(),
        };
    }

    Applied(state.clone())
}

fn validate(state: &MembershipState) -> Result<(), ZeroError> {
    if state.version == 0 {
        return Err(invalid(
            "a signed membership state must have version 1 or greater",
        ));
    }
    if state.devices.len() > MAX_DEVICES {
        return Err(limit(format!(
            "membership state has {} devices; the limit is {MAX_DEVICES}",
            state.devices.len()
        )));
    }
    if state.revoked.len() > MAX_REVOKED {
        return Err(limit(format!(
            "membership state has {} revoked ids; the limit is {MAX_REVOKED}",
            state.revoked.len()
        )));
    }
    if state.names.len() > MAX_NAMES {
        return Err(limit(format!(
            "membership state has {} names; the limit is {MAX_NAMES}",
            state.names.len()
        )));
    }
    validate_device_id(&state.signed_by)?;

    for (device_id, record) in &state.devices {
        validate_device_id(device_id)?;
        if record.device_id != *device_id {
            return Err(invalid(format!(
                "device record `{}` is stored under `{device_id}`",
                record.device_id
            )));
        }
        if device_id_for(&record.public_key_b64)? != *device_id {
            return Err(invalid(format!(
                "device id `{device_id}` does not match its public key"
            )));
        }
        if let Some(name) = &record.name {
            validate_name(name)?;
        }
        if let Some(rotated_from) = &record.rotated_from {
            validate_device_id(rotated_from)?;
        }
        if state.revoked.contains(device_id) != record.revoked {
            return Err(invalid(format!(
                "device `{device_id}` revoked flag disagrees with the revoked set"
            )));
        }
    }

    for device_id in &state.revoked {
        validate_device_id(device_id)?;
    }
    if state.revoked.contains(&state.signed_by) {
        return Err(denied(
            "membership state revokes the owner root and cannot be signed",
        ));
    }

    let mut seen_names: BTreeMap<String, &str> = BTreeMap::new();
    for (device_id, name) in &state.names {
        validate_device_id(device_id)?;
        validate_name(name)?;
        match state.devices.get(device_id) {
            Some(record) if !record.revoked => {}
            _ => {
                return Err(invalid(format!(
                    "name `{name}` is registered for unknown or revoked device `{device_id}`"
                )))
            }
        }
        let folded = name.to_lowercase();
        if seen_names.insert(folded, name).is_some() {
            return Err(invalid(format!(
                "two devices claim the name `{name}`; in-mesh names must be unique"
            )));
        }
    }
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

fn validate_name(name: &str) -> Result<(), ZeroError> {
    if name.is_empty() {
        return Err(invalid("device name must not be empty"));
    }
    if name.len() > MAX_NAME_BYTES {
        return Err(limit(format!(
            "device name is {} bytes; the limit is {MAX_NAME_BYTES}",
            name.len()
        )));
    }
    if name.trim() != name {
        return Err(invalid("device name must not start or end with whitespace"));
    }
    if name.chars().any(char::is_control) {
        return Err(invalid("device name must not contain control characters"));
    }
    Ok(())
}

fn put_str(out: &mut Vec<u8>, value: &str) -> Result<(), ZeroError> {
    let len = u32::try_from(value.len())
        .map_err(|_| limit("a membership field exceeds the u32 length prefix"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_count(out: &mut Vec<u8>, count: usize, max: usize, field: &str) -> Result<(), ZeroError> {
    if count > max {
        return Err(limit(format!(
            "membership state has {count} {field}; the limit is {max}"
        )));
    }
    let count =
        u32::try_from(count).map_err(|_| limit(format!("{field} count exceeds a u32 prefix")))?;
    out.extend_from_slice(&count.to_be_bytes());
    Ok(())
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

fn rejected(error: ZeroError) -> ApplyOutcome {
    Rejected {
        reason: format!("{}: {}", error.code().as_str(), error.message()),
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

    const NOW: i64 = 1_700_000_000_000;

    fn key() -> KeyPair {
        KeyPair::generate().expect("device key")
    }

    fn record(device: &KeyPair, name: Option<&str>, added_ms: i64) -> DeviceRecord {
        DeviceRecord {
            device_id: device.device_id().to_string(),
            public_key_b64: device.public_key_b64(),
            name: name.map(str::to_string),
            added_ms,
            revoked: false,
            rotated_from: None,
        }
    }

    fn add_device(state: &mut MembershipState, device: &KeyPair, name: &str) {
        state.devices.insert(
            device.device_id().to_string(),
            record(device, Some(name), NOW),
        );
        state
            .names
            .insert(device.device_id().to_string(), name.to_string());
    }

    fn signed_update<F>(
        owner: &KeyPair,
        base: &MembershipState,
        now_ms: i64,
        mutate: F,
    ) -> StateUpdate
    where
        F: FnOnce(&mut MembershipState),
    {
        let mut next = base.clone();
        next.version = base.version + 1;
        mutate(&mut next);
        sign_update(owner, &mut next, base.version, now_ms).expect("sign update")
    }

    fn applied(outcome: ApplyOutcome) -> MembershipState {
        match outcome {
            ApplyOutcome::Applied(state) => state,
            other => panic!("expected Applied, got {other:?}"),
        }
    }

    fn rejection(outcome: ApplyOutcome) -> String {
        match outcome {
            ApplyOutcome::Rejected { reason } => reason,
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn owner_signed_add_and_revoke_apply() {
        let owner = key();
        let current = MembershipState::new(&owner, NOW).expect("genesis state");
        assert_eq!(current.version, 1);
        verify_state(&current, &owner.public_key_b64()).expect("owner-signed genesis");

        let alice = key();
        let bob = key();
        let added = signed_update(&owner, &current, NOW + 1, |state| {
            add_device(state, &alice, "alice");
            add_device(state, &bob, "bob");
        });
        let version_two = applied(apply(&current, &added, &owner.public_key_b64()));
        assert_eq!(version_two.version, 2);
        assert_eq!(version_two.names[alice.device_id()], "alice");
        assert!(version_two.devices.contains_key(bob.device_id()));

        let revoked = signed_update(&owner, &version_two, NOW + 2, |state| {
            state
                .devices
                .get_mut(alice.device_id())
                .expect("alice")
                .revoked = true;
            state.revoked.insert(alice.device_id().to_string());
            state.names.remove(alice.device_id());
        });
        let version_three = applied(apply(&version_two, &revoked, &owner.public_key_b64()));
        assert_eq!(version_three.version, 3);
        assert!(version_three.devices[alice.device_id()].revoked);
        assert!(version_three.revoked.contains(alice.device_id()));
        assert!(!version_three.names.contains_key(alice.device_id()));
        assert!(!version_three.devices[bob.device_id()].revoked);
    }

    #[test]
    fn owner_signed_eviction_applies() {
        let owner = key();
        let device = key();
        let version_one = MembershipState::new(&owner, NOW).expect("genesis state");
        let update_two = signed_update(&owner, &version_one, NOW + 1, |state| {
            add_device(state, &device, "device");
        });
        let version_two = applied(apply(&version_one, &update_two, &owner.public_key_b64()));

        let evict = signed_update(&owner, &version_two, NOW + 2, |state| {
            state.devices.remove(device.device_id());
            state.names.remove(device.device_id());
            state.revoked.insert(device.device_id().to_string());
        });
        let version_three = applied(apply(&version_two, &evict, &owner.public_key_b64()));
        assert_eq!(version_three.version, 3);
        assert!(!version_three.devices.contains_key(device.device_id()));
        assert!(version_three.revoked.contains(device.device_id()));
        assert!(!version_three.names.contains_key(device.device_id()));
    }

    #[test]
    fn the_owner_root_record_cannot_be_evicted() {
        let owner = key();
        let device = key();
        let version_one = MembershipState::new(&owner, NOW).expect("genesis state");

        let mut with_owner = version_one.clone();
        with_owner.version = 2;
        with_owner.devices.insert(
            owner.device_id().to_string(),
            record(&owner, Some("root"), NOW),
        );
        with_owner
            .names
            .insert(owner.device_id().to_string(), "root".to_string());
        add_device(&mut with_owner, &device, "device");
        let with_owner =
            sign_update(&owner, &mut with_owner, 1, NOW + 1).expect("owner record signed");
        let version_two = applied(apply(&version_one, &with_owner, &owner.public_key_b64()));

        let mut evict_owner = version_two.clone();
        evict_owner.version = 3;
        evict_owner.devices.remove(owner.device_id());
        evict_owner.names.remove(owner.device_id());
        let evict_owner =
            sign_update(&owner, &mut evict_owner, 2, NOW + 2).expect("snapshot is signable");
        verify_state(&evict_owner.state, &owner.public_key_b64())
            .expect("the snapshot is structurally owner-signed");

        let reason = rejection(apply(&version_two, &evict_owner, &owner.public_key_b64()));
        assert!(reason.contains("owner root"), "{reason}");
        assert!(version_two.devices.contains_key(owner.device_id()));
    }

    #[test]
    fn a_device_signed_eviction_is_rejected() {
        let owner = key();
        let victim = key();
        let current = MembershipState::new(&owner, NOW).expect("genesis state");
        let with_victim = signed_update(&owner, &current, NOW + 1, |state| {
            add_device(state, &victim, "victim");
        });
        let current = applied(apply(&current, &with_victim, &owner.public_key_b64()));
        assert!(!current.devices[victim.device_id()].revoked);

        let attacker = key();
        let mut forged = current.clone();
        forged.version = 3;
        forged
            .devices
            .get_mut(victim.device_id())
            .expect("victim")
            .revoked = true;
        forged.revoked.insert(victim.device_id().to_string());
        forged.names.remove(victim.device_id());
        let forged = sign_update(&attacker, &mut forged, 2, NOW + 2).expect("device-signed update");

        // The attacker really did sign it, with its own key.
        verify_state(&forged.state, &attacker.public_key_b64())
            .expect("the forgery is a valid device-signed state");
        assert!(verify_state(&forged.state, &owner.public_key_b64()).is_err());

        let reason = rejection(apply(&current, &forged, &owner.public_key_b64()));
        assert!(reason.contains("owner root"), "{reason}");
        assert!(!current.devices[victim.device_id()].revoked);
        assert!(current.names.contains_key(victim.device_id()));
    }

    #[test]
    fn tampered_state_and_signature_are_rejected() {
        let owner = key();
        let current = MembershipState::new(&owner, NOW).expect("genesis state");

        let mut tampered = current.clone();
        tampered.updated_ms += 1;
        assert_eq!(
            verify_state(&tampered, &owner.public_key_b64())
                .expect_err("tampered field")
                .code(),
            ErrorCode::PolicyDenied
        );

        let mut other_signature = current.clone();
        other_signature.signature_b64 = key().sign(b"not this state");
        assert_eq!(
            verify_state(&other_signature, &owner.public_key_b64())
                .expect_err("wrong signature")
                .code(),
            ErrorCode::PolicyDenied
        );

        let device = key();
        let mut device_signed = current.clone();
        sign_state(&device, &mut device_signed, NOW + 1).expect("device can produce a signature");
        assert_eq!(
            verify_state(&device_signed, &owner.public_key_b64())
                .expect_err("device key is not the owner root")
                .code(),
            ErrorCode::PolicyDenied
        );

        let mut update = signed_update(&owner, &current, NOW + 2, |state| {
            add_device(state, &device, "device");
        });
        update.state.updated_ms += 1;
        let reason = rejection(apply(&current, &update, &owner.public_key_b64()));
        assert!(reason.contains("zero.pol.denied"), "{reason}");
        assert!(!current.devices.contains_key(device.device_id()));
    }

    #[test]
    fn version_rollback_is_rejected() {
        let owner = key();
        let version_one = MembershipState::new(&owner, NOW).expect("genesis state");
        let device = key();
        let update_two = signed_update(&owner, &version_one, NOW + 1, |state| {
            add_device(state, &device, "device");
        });
        let version_two = applied(apply(&version_one, &update_two, &owner.public_key_b64()));
        let update_three = signed_update(&owner, &version_two, NOW + 2, |state| {
            state
                .names
                .insert(device.device_id().to_string(), "renamed".to_string());
        });
        let version_three = applied(apply(&version_two, &update_three, &owner.public_key_b64()));
        assert_eq!(version_three.version, 3);

        // The old update is authentically owner-signed, but it is a rollback.
        let reason = rejection(apply(&version_three, &update_two, &owner.public_key_b64()));
        assert!(reason.contains("rollback"), "{reason}");
    }

    #[test]
    fn a_duplicate_update_is_already_applied() {
        let owner = key();
        let version_one = MembershipState::new(&owner, NOW).expect("genesis state");
        let device = key();
        let update = signed_update(&owner, &version_one, NOW + 1, |state| {
            add_device(state, &device, "device");
        });
        let version_two = applied(apply(&version_one, &update, &owner.public_key_b64()));
        assert_eq!(
            apply(&version_two, &update, &owner.public_key_b64()),
            ApplyOutcome::AlreadyApplied
        );
    }

    #[test]
    fn same_version_different_content_conflicts() {
        let owner = key();
        let version_one = MembershipState::new(&owner, NOW).expect("genesis state");
        let alice = key();
        let bob = key();

        let first = signed_update(&owner, &version_one, NOW + 1, |state| {
            add_device(state, &alice, "alice");
        });
        let version_two = applied(apply(&version_one, &first, &owner.public_key_b64()));

        // A second owner-signed snapshot also claims version 2, with different
        // content. Neither side may be picked silently.
        let second = signed_update(&owner, &version_one, NOW + 2, |state| {
            add_device(state, &bob, "bob");
        });
        match apply(&version_two, &second, &owner.public_key_b64()) {
            ApplyOutcome::Conflict { reason } => {
                assert!(reason.contains("claim version 2"), "{reason}");
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn a_higher_owner_signed_version_wins() {
        let owner = key();
        let version_one = MembershipState::new(&owner, NOW).expect("genesis state");
        let device = key();
        let update_two = signed_update(&owner, &version_one, NOW + 1, |state| {
            add_device(state, &device, "device");
        });
        let version_two = applied(apply(&version_one, &update_two, &owner.public_key_b64()));
        let update_three = signed_update(&owner, &version_two, NOW + 2, |state| {
            state
                .names
                .insert(device.device_id().to_string(), "renamed".to_string());
        });

        // A peer that never saw version 2 adopts version 3 from the owner.
        let version_three = applied(apply(&version_one, &update_three, &owner.public_key_b64()));
        assert_eq!(version_three.version, 3);
        assert_eq!(version_three.names[device.device_id()], "renamed");
    }

    #[test]
    fn name_changes_are_signed() {
        let owner = key();
        let version_one = MembershipState::new(&owner, NOW).expect("genesis state");
        let device = key();
        let update_two = signed_update(&owner, &version_one, NOW + 1, |state| {
            add_device(state, &device, "desk");
        });
        let version_two = applied(apply(&version_one, &update_two, &owner.public_key_b64()));

        let rename = signed_update(&owner, &version_two, NOW + 2, |state| {
            state
                .names
                .insert(device.device_id().to_string(), "kitchen".to_string());
        });
        let version_three = applied(apply(&version_two, &rename, &owner.public_key_b64()));
        assert_eq!(version_three.names[device.device_id()], "kitchen");

        let mut tampered = rename.clone();
        tampered
            .state
            .names
            .insert(device.device_id().to_string(), "attic".to_string());
        let reason = rejection(apply(&version_three, &tampered, &owner.public_key_b64()));
        assert!(reason.contains("zero.pol.denied"), "{reason}");
        assert_eq!(version_three.names[device.device_id()], "kitchen");
    }

    #[test]
    fn duplicate_device_ids_and_names_conflict() {
        let owner = key();
        let base = MembershipState::new(&owner, NOW).expect("genesis state");
        let alice = key();
        let bob = key();

        let mut duplicate_name = base.clone();
        duplicate_name.version = 2;
        add_device(&mut duplicate_name, &alice, "laptop");
        add_device(&mut duplicate_name, &bob, "LAPTOP");
        assert_eq!(
            canonical_bytes(&duplicate_name)
                .expect_err("two devices share a name")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut mismatched = base.clone();
        mismatched.version = 2;
        mismatched
            .devices
            .insert(alice.device_id().to_string(), record(&bob, None, NOW));
        assert_eq!(
            canonical_bytes(&mismatched)
                .expect_err("record id does not match its map key")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut inconsistent = base.clone();
        inconsistent.version = 2;
        inconsistent
            .devices
            .insert(alice.device_id().to_string(), record(&alice, None, NOW));
        inconsistent.revoked.insert(alice.device_id().to_string());
        assert_eq!(
            canonical_bytes(&inconsistent)
                .expect_err("revoked flag disagrees with the revoked set")
                .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn canonical_bytes_are_stable_and_exclude_the_signature() {
        let owner = key();
        let base = MembershipState::new(&owner, NOW).expect("genesis state");
        let alice = key();
        let bob = key();

        let mut first = base.clone();
        first.version = 2;
        add_device(&mut first, &alice, "alice");
        add_device(&mut first, &bob, "bob");

        let mut second = base.clone();
        second.version = 2;
        add_device(&mut second, &bob, "bob");
        add_device(&mut second, &alice, "alice");

        let first_bytes = canonical_bytes(&first).expect("canonical");
        assert!(first_bytes.starts_with(STATE_DOMAIN));
        assert_eq!(first_bytes, canonical_bytes(&second).expect("canonical"));

        let mut resignature = first.clone();
        resignature.signature_b64 = "different signature".to_string();
        assert_eq!(
            first_bytes,
            canonical_bytes(&resignature).expect("signature is excluded")
        );

        let mut renamed = first.clone();
        renamed
            .names
            .insert(alice.device_id().to_string(), "alice-2".to_string());
        assert_ne!(
            first_bytes,
            canonical_bytes(&renamed).expect("a name change changes the bytes")
        );
    }

    #[test]
    fn oversized_and_invalid_fields_are_typed() {
        let owner = key();
        let base = MembershipState::new(&owner, NOW).expect("genesis state");
        let device = key();

        let mut long_name = base.clone();
        long_name.version = 2;
        add_device(&mut long_name, &device, &"n".repeat(MAX_NAME_BYTES + 1));
        assert_eq!(
            sign_state(&owner, &mut long_name, NOW + 1)
                .expect_err("name above the limit")
                .code(),
            ErrorCode::LimitExceeded
        );

        let mut control_name = base.clone();
        control_name.version = 2;
        add_device(&mut control_name, &device, "bad\u{7}name");
        assert_eq!(
            sign_state(&owner, &mut control_name, NOW + 1)
                .expect_err("control character")
                .code(),
            ErrorCode::InvalidInput
        );

        let empty = MembershipState::empty(owner.public_key_b64()).expect("genesis placeholder");
        assert_eq!(
            canonical_bytes(&empty)
                .expect_err("version 0 is not signable")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut too_many = base.clone();
        too_many.version = 2;
        for index in 0..=MAX_DEVICES {
            let id = format!("{index:064x}");
            too_many.devices.insert(
                id.clone(),
                DeviceRecord {
                    device_id: id,
                    public_key_b64: "x".to_string(),
                    name: None,
                    added_ms: NOW,
                    revoked: false,
                    rotated_from: None,
                },
            );
        }
        assert_eq!(
            canonical_bytes(&too_many)
                .expect_err("device count above the limit")
                .code(),
            ErrorCode::LimitExceeded
        );

        let mut bad_revoked = base.clone();
        bad_revoked.version = 2;
        bad_revoked.revoked.insert("zz".to_string());
        assert_eq!(
            canonical_bytes(&bad_revoked)
                .expect_err("malformed revoked id")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut self_revoke = base.clone();
        self_revoke.version = 2;
        self_revoke.revoked.insert(owner.device_id().to_string());
        assert_eq!(
            sign_state(&owner, &mut self_revoke, NOW + 1)
                .expect_err("the owner cannot be revoked")
                .code(),
            ErrorCode::PolicyDenied
        );

        assert_eq!(
            MembershipState::empty("not base64")
                .expect_err("bad owner key")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut gap = base.clone();
        gap.version = 5;
        assert_eq!(
            sign_update(&owner, &mut gap, 0, NOW + 1)
                .expect_err("version gap")
                .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn state_and_update_survive_serde() {
        let owner = key();
        let version_one = MembershipState::new(&owner, NOW).expect("genesis state");
        let device = key();
        let update = signed_update(&owner, &version_one, NOW + 1, |state| {
            add_device(state, &device, "device");
        });
        let version_two = applied(apply(&version_one, &update, &owner.public_key_b64()));

        let state_json = serde_json::to_string(&version_two).expect("state serialise");
        let restored: MembershipState = serde_json::from_str(&state_json).expect("state parse");
        assert_eq!(restored, version_two);
        verify_state(&restored, &owner.public_key_b64()).expect("restored state verifies");

        let update_json = serde_json::to_string(&update).expect("update serialise");
        let restored_update: StateUpdate =
            serde_json::from_str(&update_json).expect("update parse");
        assert_eq!(restored_update, update);
        assert_eq!(
            apply(&version_one, &restored_update, &owner.public_key_b64()),
            ApplyOutcome::Applied(version_two)
        );
    }

    #[test]
    fn an_unsigned_genesis_accepts_one_owner_signed_update() {
        let owner = key();
        let genesis = MembershipState::empty(owner.public_key_b64()).expect("genesis placeholder");
        assert!(genesis.is_unsigned_genesis());

        let mut first = genesis.clone();
        first.version = 1;
        let update = sign_update(&owner, &mut first, 0, NOW).expect("first update");
        let version_one = applied(apply(&genesis, &update, &owner.public_key_b64()));
        assert_eq!(version_one.version, 1);
        assert_eq!(
            apply(&version_one, &update, &owner.public_key_b64()),
            ApplyOutcome::AlreadyApplied
        );

        let other_owner = key();
        let reason = rejection(apply(&genesis, &update, &other_owner.public_key_b64()));
        assert!(reason.contains("owner root"), "{reason}");

        let invalid_key = rejection(apply(&genesis, &update, "not base64"));
        assert!(
            invalid_key.contains("zero.fnd.invalid_input"),
            "{invalid_key}"
        );
    }
}
