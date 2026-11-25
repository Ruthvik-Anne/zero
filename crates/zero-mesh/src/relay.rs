//! Ciphertext-only relay through approved nodes (T-MESH-05, MESH-05, MESH-06).
//!
//! A relay sees an opaque [`RelayEnvelope`]: an id, two device ids, a nonce, an
//! opaque ciphertext, associated data, and a time-to-live. There is no
//! plaintext field, no key field, and no accessor that decrypts anything. The
//! relay's job is to check that it and both endpoints satisfy the policy and
//! membership rules, check the size and lifetime bounds, and hand the exact same
//! bytes to the next hop. It never parses or decrypts the payload (MESH-05: "a
//! relay cannot read payloads").
//!
//! Inbound is default-deny (MESH-06): [`RelayPolicy::default`] approves no
//! relays, so a node with the default policy refuses everything until an owner
//! explicitly lists it in [`RelayPolicy::approved_relays`]. An empty chain, an
//! unknown or revoked source, destination, or relay, and an expired or oversized
//! envelope are all refused with a typed [`ZeroError`].
//!
//! [`Endpoint`] is the sender/receiver side helper. It models an authenticated
//! encryption sealed for one key so tests can prove the relay only moves
//! ciphertext while the endpoint recovers the plaintext. **The test cipher is
//! not production cryptography**: it is a blake3-keyed XOR stream plus a MAC,
//! used only to demonstrate the relay boundary. Transport encryption and key
//! agreement belong to T-MESH-07 and are not implemented here.
//!
//! There is no socket, no queue, and no timer. [`RelayNode::forward`] and
//! [`relay_chain`] are pure functions over a snapshot and an injected clock.

use std::collections::BTreeSet;
use std::fmt;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, ZeroError};

use crate::identity::device_id_for;
use crate::state::MembershipState;

/// Length of an envelope id in bytes (32 hex characters).
pub const ENVELOPE_ID_BYTES: usize = 16;

/// Largest opaque ciphertext an envelope may carry: 256 KiB.
pub const MAX_CIPHERTEXT_BYTES: usize = 256 * 1024;

/// Longest accepted associated data, in bytes.
pub const MAX_AAD_BYTES: usize = 256;

/// Shortest accepted nonce, in bytes.
pub const MIN_RELAY_NONCE_BYTES: usize = 8;

/// Longest accepted nonce, in bytes.
pub const MAX_RELAY_NONCE_BYTES: usize = 32;

/// Longest accepted envelope lifetime: ten minutes.
pub const MAX_TTL_MS: i64 = 10 * 60 * 1000;

/// Default per-relay ciphertext ceiling: 64 KiB.
pub const DEFAULT_MAX_BYTES: usize = 64 * 1024;

/// Default per-relay lifetime ceiling: five minutes.
pub const DEFAULT_MAX_TTL_MS: i64 = 5 * 60 * 1000;

/// Length of the [`Endpoint`] test-cipher key, in bytes.
pub const KEY_BYTES: usize = 32;

/// Length of the nonce [`Endpoint::seal`] generates, in bytes.
pub const NONCE_BYTES: usize = 16;

/// Length of the [`Endpoint`] test-cipher authentication tag, in bytes.
pub const TAG_BYTES: usize = 32;

/// Domain separator for the test cipher's keystream.
const STREAM_DOMAIN: &[u8] = b"zero.mesh.test-cipher.stream.v1\0";

/// Domain separator for the test cipher's MAC.
const MAC_DOMAIN: &[u8] = b"zero.mesh.test-cipher.mac.v1\0";

/// How a relay compares an envelope's timestamps with its own clock.
///
/// The relay receives `now_ms` from the caller, so this is not a time source:
/// it is the small amount of future skew the relay tolerates on `created_ms`.
/// The default is strict (`0`), matching the rest of the mesh, where a future
/// timestamp is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayClock {
    /// Future skew allowed on `created_ms`, in milliseconds.
    #[serde(default)]
    pub max_future_skew_ms: i64,
}

impl RelayClock {
    /// Strict clock agreement: nothing may be dated in the future.
    pub const STRICT: Self = Self {
        max_future_skew_ms: 0,
    };

    /// A clock agreement that tolerates `max_future_skew_ms` of skew.
    pub fn with_skew(max_future_skew_ms: i64) -> Self {
        Self { max_future_skew_ms }
    }
}

impl Default for RelayClock {
    fn default() -> Self {
        Self::STRICT
    }
}

/// An opaque relay envelope.
///
/// The envelope carries ciphertext and routing metadata only. It has no
/// plaintext field and no key material. [`Debug`] prints ids and sizes, never
/// the ciphertext, nonce, or associated-data contents, so a relay log cannot
/// become a payload channel.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEnvelope {
    /// 32 hex characters identifying this envelope.
    pub id: String,
    /// Source device id: 64 hex characters, the blake3 hash of its public key.
    pub src_device: String,
    /// Destination device id: 64 hex characters.
    pub dst_device: String,
    /// Standard padded base64 of the opaque ciphertext.
    pub ciphertext_b64: String,
    /// Standard padded base64 of the nonce the sender used.
    pub nonce_b64: String,
    /// Public associated data bound into the sender's authentication tag.
    pub aad: String,
    /// When the sender created the envelope, in milliseconds since the epoch.
    pub created_ms: i64,
    /// How long the envelope may be forwarded, in milliseconds.
    pub ttl_ms: i64,
    /// Ciphertext length in bytes, including any sender authentication tag.
    pub bytes: usize,
}

impl fmt::Debug for RelayEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayEnvelope")
            .field("id", &self.id)
            .field("src_device", &self.src_device)
            .field("dst_device", &self.dst_device)
            .field("bytes", &self.bytes)
            .field("created_ms", &self.created_ms)
            .field("ttl_ms", &self.ttl_ms)
            .field("ciphertext_b64_len", &self.ciphertext_b64.len())
            .field("nonce_b64_len", &self.nonce_b64.len())
            .field("aad_len", &self.aad.len())
            .finish()
    }
}

impl RelayEnvelope {
    /// Validate the envelope's shape, independent of any relay policy.
    ///
    /// The checks are structural: hex ids, a base64 ciphertext whose decoded
    /// length equals `bytes`, a non-empty ciphertext within
    /// [`MAX_CIPHERTEXT_BYTES`], a nonce within the accepted range, printable
    /// associated data within [`MAX_AAD_BYTES`], and a positive lifetime within
    /// [`MAX_TTL_MS`]. The contents of the ciphertext are never inspected.
    pub fn validate(&self) -> Result<(), ZeroError> {
        validate_envelope_id(&self.id)?;
        validate_device_id(&self.src_device)?;
        validate_device_id(&self.dst_device)?;
        validate_aad(&self.aad)?;

        if self.bytes == 0 {
            return Err(invalid("relay envelope bytes must be positive"));
        }
        if self.bytes > MAX_CIPHERTEXT_BYTES {
            return Err(limit(format!(
                "relay envelope declares {} bytes; the limit is {MAX_CIPHERTEXT_BYTES}",
                self.bytes
            )));
        }
        if self.ciphertext_b64.len() > MAX_CIPHERTEXT_BYTES * 2 {
            return Err(limit(format!(
                "relay envelope ciphertext is {} base64 characters; the limit is {}",
                self.ciphertext_b64.len(),
                MAX_CIPHERTEXT_BYTES * 2
            )));
        }
        let ciphertext = B64
            .decode(self.ciphertext_b64.trim())
            .map_err(|_| invalid("relay envelope ciphertext is not valid base64"))?;
        if ciphertext.is_empty() {
            return Err(invalid("relay envelope ciphertext must be non-empty"));
        }
        if ciphertext.len() != self.bytes {
            return Err(invalid(format!(
                "relay envelope declares {} bytes but carries {}",
                self.bytes,
                ciphertext.len()
            )));
        }

        let nonce = B64
            .decode(self.nonce_b64.trim())
            .map_err(|_| invalid("relay envelope nonce is not valid base64"))?;
        if nonce.len() < MIN_RELAY_NONCE_BYTES || nonce.len() > MAX_RELAY_NONCE_BYTES {
            return Err(invalid(format!(
                "relay envelope nonce must be between {MIN_RELAY_NONCE_BYTES} and {MAX_RELAY_NONCE_BYTES} bytes, not {}",
                nonce.len()
            )));
        }

        if self.ttl_ms <= 0 {
            return Err(invalid("relay envelope ttl must be positive"));
        }
        if self.ttl_ms > MAX_TTL_MS {
            return Err(limit(format!(
                "relay envelope ttl {} ms exceeds {MAX_TTL_MS} ms",
                self.ttl_ms
            )));
        }
        Ok(())
    }
}

/// A relay's forwarding policy and approved-relay list.
///
/// [`Default`] is default-deny: no relay is approved, the ciphertext ceiling is
/// [`DEFAULT_MAX_BYTES`], the lifetime ceiling is [`DEFAULT_MAX_TTL_MS`], and
/// the relaying device must itself be an approved member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayPolicy {
    /// Largest ciphertext this relay will forward, in bytes.
    pub max_bytes: usize,
    /// Longest envelope lifetime this relay will forward, in milliseconds.
    pub max_ttl_ms: i64,
    /// Device ids explicitly approved to relay. Empty means default-deny.
    #[serde(default)]
    pub approved_relays: BTreeSet<String>,
    /// Require the relaying device itself to be an approved member of the
    /// owner-signed state, in addition to being listed in `approved_relays`.
    pub require_member: bool,
}

impl Default for RelayPolicy {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            max_ttl_ms: DEFAULT_MAX_TTL_MS,
            approved_relays: BTreeSet::new(),
            require_member: true,
        }
    }
}

impl RelayPolicy {
    /// Refuse a policy that cannot be enforced: a zero or above-global size
    /// ceiling, a zero or above-global lifetime ceiling, or a malformed
    /// approved-relay id.
    pub fn validate(&self) -> Result<(), ZeroError> {
        if self.max_bytes == 0 {
            return Err(invalid("relay policy max_bytes must be positive"));
        }
        if self.max_bytes > MAX_CIPHERTEXT_BYTES {
            return Err(limit(format!(
                "relay policy max_bytes {} exceeds {MAX_CIPHERTEXT_BYTES}",
                self.max_bytes
            )));
        }
        if self.max_ttl_ms <= 0 {
            return Err(invalid("relay policy max_ttl_ms must be positive"));
        }
        if self.max_ttl_ms > MAX_TTL_MS {
            return Err(limit(format!(
                "relay policy max_ttl_ms {} exceeds {MAX_TTL_MS}",
                self.max_ttl_ms
            )));
        }
        for device_id in &self.approved_relays {
            validate_device_id(device_id)?;
        }
        Ok(())
    }
}

/// One relay node: its device id, its policy, and its clock agreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayNode {
    /// This relay's device id: 64 hex characters.
    pub device_id: String,
    /// Forwarding policy, including the explicit approved-relay set.
    pub policy: RelayPolicy,
    /// How this relay judges envelope timestamps.
    pub clock: RelayClock,
}

impl RelayNode {
    /// Build a relay with the strict clock agreement.
    pub fn new(device_id: impl Into<String>, policy: RelayPolicy) -> Self {
        Self {
            device_id: device_id.into(),
            policy,
            clock: RelayClock::STRICT,
        }
    }

    /// Replace the clock agreement.
    pub fn with_clock(mut self, clock: RelayClock) -> Self {
        self.clock = clock;
        self
    }

    /// Forward one envelope after checking approval, membership, bounds, and
    /// lifetime.
    ///
    /// Checks run in this order, and the relay never inspects the ciphertext or
    /// nonce contents:
    ///
    /// 1. the policy and envelope are structurally valid;
    /// 2. this relay's device id is well formed and listed in
    ///    [`RelayPolicy::approved_relays`];
    /// 3. when [`RelayPolicy::require_member`] is set, this relay is an
    ///    approved, non-revoked member;
    /// 4. the source and destination are approved, non-revoked members whose
    ///    recorded public key hashes to their device id;
    /// 5. `bytes` and `ttl_ms` are within this relay's policy ceilings;
    /// 6. `created_ms` is not in the future beyond the clock skew, and the
    ///    envelope has not expired at `now_ms`.
    ///
    /// On success the returned [`Forwarded`] holds the exact same envelope: no
    /// field is rewritten and the opaque bytes are unchanged.
    pub fn forward(
        &self,
        envelope: &RelayEnvelope,
        membership: &MembershipState,
        now_ms: i64,
    ) -> Result<Forwarded, ZeroError> {
        self.policy.validate()?;
        envelope.validate()?;
        validate_device_id(&self.device_id)?;

        if !self.policy.approved_relays.contains(&self.device_id) {
            return Err(denied(format!(
                "relay `{}` is not in the approved relay set",
                self.device_id
            )));
        }
        if self.policy.require_member {
            require_member(membership, &self.device_id, "relay")?;
        }
        require_member(membership, &envelope.src_device, "source")?;
        require_member(membership, &envelope.dst_device, "destination")?;

        if envelope.bytes > self.policy.max_bytes {
            return Err(limit(format!(
                "envelope carries {} bytes; this relay forwards at most {}",
                envelope.bytes, self.policy.max_bytes
            )));
        }
        if envelope.ttl_ms > self.policy.max_ttl_ms {
            return Err(limit(format!(
                "envelope ttl {} ms exceeds this relay's {} ms",
                envelope.ttl_ms, self.policy.max_ttl_ms
            )));
        }

        if self.clock.max_future_skew_ms < 0 {
            return Err(invalid("relay clock skew must not be negative"));
        }
        let latest_created_ms = now_ms.saturating_add(self.clock.max_future_skew_ms);
        if envelope.created_ms > latest_created_ms {
            return Err(denied(format!(
                "envelope `{}` is not yet valid: created at {} ms, now {} ms",
                envelope.id, envelope.created_ms, now_ms
            )));
        }
        let expires_ms = envelope
            .created_ms
            .checked_add(envelope.ttl_ms)
            .ok_or_else(|| invalid("relay envelope expiry overflows the clock"))?;
        if now_ms >= expires_ms {
            return Err(denied(format!(
                "envelope `{}` expired at {expires_ms} ms",
                envelope.id
            )));
        }

        Ok(Forwarded {
            envelope: envelope.clone(),
            relay_id: self.device_id.clone(),
            at_ms: now_ms,
        })
    }
}

/// The result of one relay hop.
///
/// It contains the opaque envelope, the relay's own id, and the time the hop
/// accepted it. There is no plaintext, no key, and no decryption helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Forwarded {
    /// The envelope exactly as received; no field is rewritten.
    pub envelope: RelayEnvelope,
    /// The device id of the relay that accepted it.
    pub relay_id: String,
    /// The relay's clock when it accepted the envelope.
    pub at_ms: i64,
}

/// Relay one envelope through each node in order.
///
/// Every hop runs the same checks as [`RelayNode::forward`]; the first refusal
/// is returned and no partial chain is produced. A repeated relay id is refused
/// as a loop, and an empty chain is refused because inbound is default-deny.
/// The ciphertext is copied verbatim, so every [`Forwarded`] carries the same
/// opaque bytes.
pub fn relay_chain(
    envelope: &RelayEnvelope,
    relays: &[RelayNode],
    membership: &MembershipState,
    now_ms: i64,
) -> Result<Vec<Forwarded>, ZeroError> {
    if relays.is_empty() {
        return Err(denied(
            "no relay nodes were supplied; inbound is default-deny",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut hops = Vec::with_capacity(relays.len());
    for relay in relays {
        if !seen.insert(relay.device_id.clone()) {
            return Err(denied(format!(
                "relay chain loops through `{}`",
                relay.device_id
            )));
        }
        hops.push(relay.forward(envelope, membership, now_ms)?);
    }
    Ok(hops)
}

/// Envelope parts produced by [`Endpoint::seal`].
///
/// The caller adds routing fields to make a [`RelayEnvelope`]. `Debug` prints
/// sizes only.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed {
    /// Standard padded base64 of the test-cipher ciphertext and tag.
    pub ciphertext_b64: String,
    /// Standard padded base64 of the random nonce.
    pub nonce_b64: String,
    /// Associated data bound into the authentication tag.
    pub aad: String,
    /// Ciphertext length in bytes, including the tag.
    pub bytes: usize,
}

impl fmt::Debug for Sealed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealed")
            .field("bytes", &self.bytes)
            .field("ciphertext_b64_len", &self.ciphertext_b64.len())
            .field("nonce_b64_len", &self.nonce_b64.len())
            .field("aad_len", &self.aad.len())
            .finish()
    }
}

impl Sealed {
    /// Fill an envelope with this sealed payload and the routing fields.
    pub fn envelope(
        self,
        id: impl Into<String>,
        src_device: impl Into<String>,
        dst_device: impl Into<String>,
        created_ms: i64,
        ttl_ms: i64,
    ) -> RelayEnvelope {
        RelayEnvelope {
            id: id.into(),
            src_device: src_device.into(),
            dst_device: dst_device.into(),
            ciphertext_b64: self.ciphertext_b64,
            nonce_b64: self.nonce_b64,
            aad: self.aad,
            created_ms,
            ttl_ms,
            bytes: self.bytes,
        }
    }
}

/// The endpoint side of the relay: seal a plaintext for a key and open an
/// envelope with that key.
///
/// This is a **test helper**, not a production cryptographic API. The cipher is
/// a blake3-keyed XOR stream with a blake3-keyed MAC. It exists so a test can
/// show that a [`RelayNode`] forwards only opaque bytes while the endpoint
/// recovers the plaintext, and that a tampered ciphertext or the wrong key fails
/// authentication. Real transport encryption and key agreement are T-MESH-07.
#[derive(Debug, Clone, Copy, Default)]
pub struct Endpoint;

impl Endpoint {
    /// Seal `plaintext` for `key`, with empty associated data.
    pub fn seal(plaintext: &[u8], key: &[u8; KEY_BYTES]) -> Result<Sealed, ZeroError> {
        Self::seal_with_aad(plaintext, key, "")
    }

    /// Seal `plaintext` for `key`, binding `aad` into the authentication tag.
    pub fn seal_with_aad(
        plaintext: &[u8],
        key: &[u8; KEY_BYTES],
        aad: &str,
    ) -> Result<Sealed, ZeroError> {
        validate_aad(aad)?;
        if plaintext.len() > MAX_CIPHERTEXT_BYTES - TAG_BYTES {
            return Err(limit(format!(
                "plaintext is {} bytes; the largest this test cipher seals is {}",
                plaintext.len(),
                MAX_CIPHERTEXT_BYTES - TAG_BYTES
            )));
        }

        let mut nonce = [0u8; NONCE_BYTES];
        getrandom::getrandom(&mut nonce)
            .map_err(|error| internal(format!("cannot read random bytes: {error}")))?;

        let body = apply_stream(key, &nonce, plaintext);
        let tag = mac(key, &nonce, aad.as_bytes(), &body);
        let mut ciphertext = body;
        ciphertext.extend_from_slice(&tag);

        Ok(Sealed {
            ciphertext_b64: B64.encode(&ciphertext),
            nonce_b64: B64.encode(nonce),
            aad: aad.to_string(),
            bytes: ciphertext.len(),
        })
    }

    /// Open an envelope with `key`, returning the plaintext.
    ///
    /// The envelope is validated first, then the tag is checked in constant
    /// time. A truncated ciphertext, a modified byte, a changed `aad`, or the
    /// wrong key is `zero.pol.denied`.
    pub fn open(envelope: &RelayEnvelope, key: &[u8; KEY_BYTES]) -> Result<Vec<u8>, ZeroError> {
        envelope.validate()?;
        let ciphertext = B64
            .decode(envelope.ciphertext_b64.trim())
            .map_err(|_| invalid("relay envelope ciphertext is not valid base64"))?;
        let nonce = B64
            .decode(envelope.nonce_b64.trim())
            .map_err(|_| invalid("relay envelope nonce is not valid base64"))?;

        if ciphertext.len() < TAG_BYTES {
            return Err(denied(
                "ciphertext is shorter than the test-cipher authentication tag",
            ));
        }
        let (body, tag) = ciphertext.split_at(ciphertext.len() - TAG_BYTES);
        let expected = mac(key, &nonce, envelope.aad.as_bytes(), body);
        if !constant_time_eq(tag, &expected) {
            return Err(denied(
                "test cipher authentication failed: the envelope was tampered with or the key is wrong",
            ));
        }
        Ok(apply_stream(key, &nonce, body))
    }
}

/// See [`Endpoint::seal`].
pub fn seal(plaintext: &[u8], key: &[u8; KEY_BYTES]) -> Result<Sealed, ZeroError> {
    Endpoint::seal(plaintext, key)
}

/// See [`Endpoint::seal_with_aad`].
pub fn seal_with_aad(
    plaintext: &[u8],
    key: &[u8; KEY_BYTES],
    aad: &str,
) -> Result<Sealed, ZeroError> {
    Endpoint::seal_with_aad(plaintext, key, aad)
}

/// See [`Endpoint::open`].
pub fn open(envelope: &RelayEnvelope, key: &[u8; KEY_BYTES]) -> Result<Vec<u8>, ZeroError> {
    Endpoint::open(envelope, key)
}

fn apply_stream(key: &[u8; KEY_BYTES], nonce: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for (index, chunk) in data.chunks(32).enumerate() {
        let block = keyed_block(key, STREAM_DOMAIN, nonce, index as u64);
        out.extend(
            chunk
                .iter()
                .zip(block.iter())
                .map(|(byte, keystream)| byte ^ keystream),
        );
    }
    out
}

fn mac(key: &[u8; KEY_BYTES], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> [u8; TAG_BYTES] {
    let mut input =
        Vec::with_capacity(MAC_DOMAIN.len() + nonce.len() + 4 + aad.len() + ciphertext.len());
    input.extend_from_slice(MAC_DOMAIN);
    input.extend_from_slice(nonce);
    input.extend_from_slice(&u32::try_from(aad.len()).unwrap_or(u32::MAX).to_be_bytes());
    input.extend_from_slice(aad);
    input.extend_from_slice(ciphertext);
    *blake3::keyed_hash(key, &input).as_bytes()
}

fn keyed_block(key: &[u8; KEY_BYTES], domain: &[u8], nonce: &[u8], counter: u64) -> [u8; 32] {
    let mut input = Vec::with_capacity(domain.len() + nonce.len() + 8);
    input.extend_from_slice(domain);
    input.extend_from_slice(nonce);
    input.extend_from_slice(&counter.to_be_bytes());
    *blake3::keyed_hash(key, &input).as_bytes()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

fn require_member(
    membership: &MembershipState,
    device_id: &str,
    role: &str,
) -> Result<(), ZeroError> {
    if membership.revoked.contains(device_id) {
        return Err(denied(format!("{role} `{device_id}` is revoked")));
    }
    let record = match membership.devices.get(device_id) {
        Some(record) if !record.revoked => record,
        Some(_) => return Err(denied(format!("{role} `{device_id}` is revoked"))),
        None => {
            return Err(denied(format!(
                "{role} `{device_id}` is not an approved member"
            )))
        }
    };
    match device_id_for(&record.public_key_b64) {
        Ok(derived) if derived == device_id => Ok(()),
        Ok(_) => Err(denied(format!(
            "membership record for {role} `{device_id}` does not match its public key"
        ))),
        Err(error) => Err(denied(format!(
            "membership record for {role} `{device_id}` has an unusable public key: {}",
            error.message()
        ))),
    }
}

fn validate_envelope_id(id: &str) -> Result<(), ZeroError> {
    if id.len() != ENVELOPE_ID_BYTES * 2 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(format!(
            "relay envelope id must be {} hex characters",
            ENVELOPE_ID_BYTES * 2
        )));
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

fn validate_aad(aad: &str) -> Result<(), ZeroError> {
    if aad.len() > MAX_AAD_BYTES {
        return Err(limit(format!(
            "relay associated data is {} bytes; the limit is {MAX_AAD_BYTES}",
            aad.len()
        )));
    }
    if !aad.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
        return Err(invalid(
            "relay associated data must be printable ASCII and carry no binary or control bytes",
        ));
    }
    Ok(())
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

fn internal(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Internal, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{DeviceRecord, KeyPair};
    use crate::state::sign_update;

    const NOW: i64 = 1_700_000_000_000;
    const TTL: i64 = 60_000;

    fn key() -> KeyPair {
        KeyPair::generate().expect("device key")
    }

    fn endpoint_key() -> [u8; KEY_BYTES] {
        [0x5a; KEY_BYTES]
    }

    fn envelope_id(n: u8) -> String {
        format!("{n:032x}")
    }

    fn add_device(state: &mut MembershipState, device: &KeyPair) {
        state.devices.insert(
            device.device_id().to_string(),
            DeviceRecord {
                device_id: device.device_id().to_string(),
                public_key_b64: device.public_key_b64(),
                name: None,
                added_ms: NOW,
                revoked: false,
                rotated_from: None,
            },
        );
    }

    fn state_with(owner: &KeyPair, members: &[&KeyPair]) -> MembershipState {
        let genesis = MembershipState::new(owner, NOW).expect("genesis state");
        if members.is_empty() {
            return genesis;
        }
        let mut next = genesis.clone();
        next.version = 2;
        for device in members {
            add_device(&mut next, device);
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

    fn node(device: &KeyPair, approved: &[&KeyPair], require_member: bool) -> RelayNode {
        RelayNode::new(
            device.device_id(),
            RelayPolicy {
                approved_relays: approved
                    .iter()
                    .map(|approved| approved.device_id().to_string())
                    .collect(),
                require_member,
                ..RelayPolicy::default()
            },
        )
    }

    fn seal_for_endpoint(plaintext: &[u8]) -> Sealed {
        seal(plaintext, &endpoint_key()).expect("sealed payload")
    }

    fn make_envelope(
        id: u8,
        src: &KeyPair,
        dst: &KeyPair,
        sealed: Sealed,
        created_ms: i64,
        ttl_ms: i64,
    ) -> RelayEnvelope {
        sealed.envelope(
            envelope_id(id),
            src.device_id(),
            dst.device_id(),
            created_ms,
            ttl_ms,
        )
    }

    fn assert_denied(result: Result<Forwarded, ZeroError>) -> String {
        let error = result.expect_err("the relay should refuse");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        error.message().to_string()
    }

    #[test]
    fn a_relay_forwards_opaque_bytes_and_the_endpoint_decrypts() {
        let (owner, src, dst, relay) = (key(), key(), key(), key());
        let membership = state_with(&owner, &[&src, &dst, &relay]);
        let plaintext = b"the relay must never read this payload";
        let sealed = seal_for_endpoint(plaintext);
        let envelope = make_envelope(1, &src, &dst, sealed, NOW, TTL);
        assert!(
            !envelope.ciphertext_b64.contains("relay must never"),
            "the wire ciphertext must not carry the plaintext"
        );

        let forwarded = node(&relay, &[&relay], true)
            .forward(&envelope, &membership, NOW + 1)
            .expect("an approved relay forwards");

        assert_eq!(forwarded.envelope, envelope, "the bytes are unchanged");
        assert_eq!(forwarded.relay_id, relay.device_id());
        assert_eq!(forwarded.at_ms, NOW + 1);
        assert_eq!(
            open(&forwarded.envelope, &endpoint_key()).expect("the endpoint decrypts"),
            plaintext
        );

        let relay_view = format!("{forwarded:?}");
        assert!(!relay_view.contains("relay must never"), "{relay_view}");
        assert!(
            !relay_view.contains(&envelope.ciphertext_b64),
            "{relay_view}"
        );
        assert!(!relay_view.contains(&envelope.nonce_b64), "{relay_view}");
        assert!(relay_view.contains(src.device_id()));
        assert!(relay_view.contains(dst.device_id()));
    }

    #[test]
    fn an_unapproved_relay_is_refused() {
        let (owner, src, dst, relay) = (key(), key(), key(), key());
        let membership = state_with(&owner, &[&src, &dst, &relay]);
        let envelope = make_envelope(2, &src, &dst, seal_for_endpoint(b"payload"), NOW, TTL);

        let reason = assert_denied(node(&relay, &[], true).forward(&envelope, &membership, NOW));
        assert!(reason.contains("not in the approved relay set"), "{reason}");

        // Explicit approval is not a membership substitute unless the policy
        // deliberately relaxes `require_member`.
        let outsider = state_with(&owner, &[&src, &dst]);
        let reason =
            assert_denied(node(&relay, &[&relay], true).forward(&envelope, &outsider, NOW));
        assert!(reason.contains("is not an approved member"), "{reason}");
        assert!(node(&relay, &[&relay], false)
            .forward(&envelope, &outsider, NOW)
            .is_ok());
    }

    #[test]
    fn default_deny_refuses_when_no_relay_is_approved() {
        let (owner, src, dst, relay) = (key(), key(), key(), key());
        let membership = state_with(&owner, &[&src, &dst, &relay]);
        let envelope = make_envelope(3, &src, &dst, seal_for_endpoint(b"payload"), NOW, TTL);

        let policy = RelayPolicy::default();
        assert!(policy.approved_relays.is_empty());
        assert!(policy.require_member);
        let reason = assert_denied(RelayNode::new(relay.device_id(), policy).forward(
            &envelope,
            &membership,
            NOW,
        ));
        assert!(reason.contains("not in the approved relay set"), "{reason}");

        assert_eq!(
            relay_chain(&envelope, &[], &membership, NOW)
                .expect_err("an empty chain cannot carry inbound")
                .code(),
            ErrorCode::PolicyDenied
        );
    }

    #[test]
    fn a_revoked_relay_source_or_destination_is_refused() {
        let (owner, src, dst, relay) = (key(), key(), key(), key());
        let envelope = make_envelope(4, &src, &dst, seal_for_endpoint(b"payload"), NOW, TTL);

        let relay_revoked = state_with_revoked(&owner, &[&src, &dst, &relay], &relay);
        let reason =
            assert_denied(node(&relay, &[&relay], true).forward(&envelope, &relay_revoked, NOW));
        assert!(
            reason.contains("relay") && reason.contains("revoked"),
            "{reason}"
        );

        let src_revoked = state_with_revoked(&owner, &[&src, &dst, &relay], &src);
        let reason =
            assert_denied(node(&relay, &[&relay], true).forward(&envelope, &src_revoked, NOW));
        assert!(
            reason.contains("source") && reason.contains("revoked"),
            "{reason}"
        );

        let dst_revoked = state_with_revoked(&owner, &[&src, &dst, &relay], &dst);
        let reason =
            assert_denied(node(&relay, &[&relay], true).forward(&envelope, &dst_revoked, NOW));
        assert!(
            reason.contains("destination") && reason.contains("revoked"),
            "{reason}"
        );
    }

    #[test]
    fn unknown_members_are_refused() {
        let (owner, src, dst, relay) = (key(), key(), key(), key());
        let envelope = make_envelope(5, &src, &dst, seal_for_endpoint(b"payload"), NOW, TTL);

        let no_src = state_with(&owner, &[&dst, &relay]);
        let reason = assert_denied(node(&relay, &[&relay], true).forward(&envelope, &no_src, NOW));
        assert!(reason.contains("source") && reason.contains("not an approved member"));

        let no_dst = state_with(&owner, &[&src, &relay]);
        let reason = assert_denied(node(&relay, &[&relay], true).forward(&envelope, &no_dst, NOW));
        assert!(reason.contains("destination") && reason.contains("not an approved member"));

        let mut mismatched = state_with(&owner, &[&src, &dst, &relay]);
        mismatched
            .devices
            .get_mut(src.device_id())
            .expect("source record")
            .public_key_b64 = key().public_key_b64();
        let reason =
            assert_denied(node(&relay, &[&relay], true).forward(&envelope, &mismatched, NOW));
        assert!(reason.contains("does not match its public key"), "{reason}");
    }

    #[test]
    fn size_bounds_are_enforced() {
        let (owner, src, dst, relay) = (key(), key(), key(), key());
        let membership = state_with(&owner, &[&src, &dst, &relay]);
        let relay = node(&relay, &[&relay], true);

        let big = vec![7u8; DEFAULT_MAX_BYTES];
        let large = make_envelope(6, &src, &dst, seal_for_endpoint(&big), NOW, TTL);
        assert!(large.bytes > DEFAULT_MAX_BYTES);
        assert_eq!(
            relay
                .forward(&large, &membership, NOW)
                .expect_err("over the policy ceiling")
                .code(),
            ErrorCode::LimitExceeded
        );

        let mut understated = make_envelope(7, &src, &dst, seal_for_endpoint(b"payload"), NOW, TTL);
        understated.bytes -= 1;
        assert_eq!(
            relay
                .forward(&understated, &membership, NOW)
                .expect_err("declared bytes disagree with the ciphertext")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut above_global =
            make_envelope(8, &src, &dst, seal_for_endpoint(b"payload"), NOW, TTL);
        above_global.bytes = MAX_CIPHERTEXT_BYTES + 1;
        assert_eq!(
            relay
                .forward(&above_global, &membership, NOW)
                .expect_err("above the global ciphertext ceiling")
                .code(),
            ErrorCode::LimitExceeded
        );

        let zero_policy = RelayNode::new(
            relay.device_id.clone(),
            RelayPolicy {
                max_bytes: 0,
                ..RelayPolicy::default()
            },
        );
        assert_eq!(
            zero_policy
                .forward(&large, &membership, NOW)
                .expect_err("a zero-byte policy is unusable")
                .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn ttl_bounds_are_enforced() {
        let (owner, src, dst, relay) = (key(), key(), key(), key());
        let membership = state_with(&owner, &[&src, &dst, &relay]);
        let relay = node(&relay, &[&relay], true);

        let zero = make_envelope(9, &src, &dst, seal_for_endpoint(b"payload"), NOW, 0);
        assert_eq!(
            relay
                .forward(&zero, &membership, NOW)
                .expect_err("a zero ttl is invalid")
                .code(),
            ErrorCode::InvalidInput
        );

        let above_policy = make_envelope(
            10,
            &src,
            &dst,
            seal_for_endpoint(b"payload"),
            NOW,
            DEFAULT_MAX_TTL_MS + 1,
        );
        assert_eq!(
            relay
                .forward(&above_policy, &membership, NOW)
                .expect_err("over the policy ttl")
                .code(),
            ErrorCode::LimitExceeded
        );

        let above_global = make_envelope(
            11,
            &src,
            &dst,
            seal_for_endpoint(b"payload"),
            NOW,
            MAX_TTL_MS + 1,
        );
        assert_eq!(
            relay
                .forward(&above_global, &membership, NOW)
                .expect_err("over the global ttl")
                .code(),
            ErrorCode::LimitExceeded
        );

        // A ttl exactly at both ceilings is accepted, and the relay does not
        // extend or shorten it.
        let at_limit = make_envelope(
            12,
            &src,
            &dst,
            seal_for_endpoint(b"payload"),
            NOW,
            DEFAULT_MAX_TTL_MS,
        );
        let forwarded = relay
            .forward(&at_limit, &membership, NOW + DEFAULT_MAX_TTL_MS - 1)
            .expect("still live");
        assert_eq!(forwarded.envelope.ttl_ms, DEFAULT_MAX_TTL_MS);
    }

    #[test]
    fn expired_and_future_envelopes_are_refused() {
        let (owner, src, dst, relay) = (key(), key(), key(), key());
        let membership = state_with(&owner, &[&src, &dst, &relay]);
        let envelope = make_envelope(13, &src, &dst, seal_for_endpoint(b"payload"), NOW, 1_000);
        let relay = node(&relay, &[&relay], true);

        assert!(relay.forward(&envelope, &membership, NOW).is_ok());
        let reason = assert_denied(relay.forward(&envelope, &membership, NOW + 1_000));
        assert!(reason.contains("expired"), "{reason}");

        let future = make_envelope(
            14,
            &src,
            &dst,
            seal_for_endpoint(b"payload"),
            NOW + 1_000,
            TTL,
        );
        let reason = assert_denied(relay.forward(&future, &membership, NOW));
        assert!(reason.contains("not yet valid"), "{reason}");
        assert!(relay
            .clone()
            .with_clock(RelayClock::with_skew(1_000))
            .forward(&future, &membership, NOW)
            .is_ok());

        let negative_skew = RelayNode {
            clock: RelayClock::with_skew(-1),
            ..relay
        };
        assert_eq!(
            negative_skew
                .forward(&envelope, &membership, NOW)
                .expect_err("negative skew is invalid")
                .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn a_multi_hop_chain_passes_the_same_opaque_bytes() {
        let (owner, src, dst, first, second, third) = (key(), key(), key(), key(), key(), key());
        let membership = state_with(&owner, &[&src, &dst, &first, &second, &third]);
        let envelope = make_envelope(
            15,
            &src,
            &dst,
            seal_for_endpoint(b"multi-hop payload"),
            NOW,
            TTL,
        );

        let relays = [
            node(&first, &[&first], true),
            node(&second, &[&second], true),
            node(&third, &[&third], true),
        ];
        let hops = relay_chain(&envelope, &relays, &membership, NOW + 1).expect("chain forwards");
        assert_eq!(hops.len(), 3);
        for (hop, relay) in hops.iter().zip(relays.iter()) {
            assert_eq!(hop.envelope, envelope, "the opaque bytes are unchanged");
            assert_eq!(hop.relay_id, relay.device_id);
            assert_eq!(hop.at_ms, NOW + 1);
        }
        assert_eq!(
            open(&hops[2].envelope, &endpoint_key()).expect("endpoint decrypts"),
            b"multi-hop payload"
        );
    }

    #[test]
    fn a_chain_refuses_a_bad_hop_or_a_loop() {
        let (owner, src, dst, first, second) = (key(), key(), key(), key(), key());
        let membership = state_with(&owner, &[&src, &dst, &first, &second]);
        let envelope = make_envelope(16, &src, &dst, seal_for_endpoint(b"payload"), NOW, TTL);

        let relays = [node(&first, &[&first], true), node(&second, &[], true)];
        let error = relay_chain(&envelope, &relays, &membership, NOW)
            .expect_err("the second hop is not approved");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("not in the approved relay set"));

        let looped = [
            node(&first, &[&first], true),
            node(&second, &[&second], true),
            node(&first, &[&first], true),
        ];
        let error = relay_chain(&envelope, &looped, &membership, NOW)
            .expect_err("a repeated relay is a loop");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("loops"));
    }

    #[test]
    fn a_tampered_ciphertext_or_wrong_key_fails_endpoint_decryption() {
        let (src, dst) = (key(), key());
        let envelope = make_envelope(
            17,
            &src,
            &dst,
            seal_for_endpoint(b"authenticated payload"),
            NOW,
            TTL,
        );
        let key = endpoint_key();

        assert!(open(&envelope, &key).is_ok());

        let mut tampered = envelope.clone();
        let first = tampered.ciphertext_b64.remove(0);
        let replacement = if first == 'A' { 'B' } else { 'A' };
        tampered.ciphertext_b64.insert(0, replacement);
        assert_eq!(
            open(&tampered, &key)
                .expect_err("a flipped ciphertext byte")
                .code(),
            ErrorCode::PolicyDenied
        );

        let mut aad_changed = envelope.clone();
        aad_changed.aad = "tampered".to_string();
        assert_eq!(
            open(&aad_changed, &key)
                .expect_err("changed associated data")
                .code(),
            ErrorCode::PolicyDenied
        );

        let mut truncated = envelope.clone();
        truncated.ciphertext_b64 = B64.encode([0u8; 4]);
        truncated.bytes = 4;
        assert_eq!(
            open(&truncated, &key)
                .expect_err("ciphertext shorter than the tag")
                .code(),
            ErrorCode::PolicyDenied
        );

        let mut wrong_key = [0u8; KEY_BYTES];
        wrong_key[0] = 0xff;
        assert_eq!(
            open(&envelope, &wrong_key)
                .expect_err("the wrong key")
                .code(),
            ErrorCode::PolicyDenied
        );
    }

    #[test]
    fn debug_and_serde_never_expose_plaintext_or_keys() {
        let (src, dst) = (key(), key());
        let key = endpoint_key();
        let plaintext = b"payload marker 0123456789";
        let sealed = seal_with_aad(plaintext, &key, "route:v1").expect("sealed");
        let envelope = make_envelope(18, &src, &dst, sealed, NOW, TTL);

        let debug = format!("{envelope:?}");
        assert!(!debug.contains("payload marker"), "{debug}");
        assert!(!debug.contains(&envelope.ciphertext_b64), "{debug}");
        assert!(!debug.contains(&envelope.nonce_b64), "{debug}");
        assert!(!debug.contains("route:v1"), "{debug}");
        assert!(debug.contains(&envelope.id));
        assert!(debug.contains(src.device_id()));

        let json = serde_json::to_string(&envelope).expect("serialise");
        assert!(!json.contains("payload marker"), "{json}");
        assert!(!json.contains("\"plaintext\""), "{json}");
        assert!(!json.contains(&B64.encode(key)), "{json}");
        assert!(!json.contains(&key.iter().map(|b| format!("{b:02x}")).collect::<String>()));

        let forwarded = Forwarded {
            envelope: envelope.clone(),
            relay_id: "relay".to_string(),
            at_ms: NOW,
        };
        let forwarded_json = serde_json::to_string(&forwarded).expect("serialise hop");
        assert!(
            !forwarded_json.contains("payload marker"),
            "{forwarded_json}"
        );
    }

    #[test]
    fn malformed_envelopes_and_policies_are_typed() {
        let (src, dst) = (key(), key());
        let valid = make_envelope(19, &src, &dst, seal_for_endpoint(b"payload"), NOW, TTL);

        let mut bad_id = valid.clone();
        bad_id.id = "zz".to_string();
        assert_eq!(
            bad_id.validate().expect_err("bad envelope id").code(),
            ErrorCode::InvalidInput
        );

        let mut bad_src = valid.clone();
        bad_src.src_device = "not-a-device".to_string();
        assert_eq!(
            bad_src.validate().expect_err("bad source id").code(),
            ErrorCode::InvalidInput
        );

        let mut empty = valid.clone();
        empty.ciphertext_b64.clear();
        empty.bytes = 0;
        assert_eq!(
            empty.validate().expect_err("empty ciphertext").code(),
            ErrorCode::InvalidInput
        );

        let mut not_base64 = valid.clone();
        not_base64.ciphertext_b64 = "!!!!".to_string();
        assert_eq!(
            not_base64
                .validate()
                .expect_err("non-base64 ciphertext")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut short_nonce = valid.clone();
        short_nonce.nonce_b64 = B64.encode([1u8; MIN_RELAY_NONCE_BYTES - 1]);
        assert_eq!(
            short_nonce.validate().expect_err("short nonce").code(),
            ErrorCode::InvalidInput
        );

        let mut long_nonce = valid.clone();
        long_nonce.nonce_b64 = B64.encode([1u8; MAX_RELAY_NONCE_BYTES + 1]);
        assert_eq!(
            long_nonce.validate().expect_err("long nonce").code(),
            ErrorCode::InvalidInput
        );

        let mut control_aad = valid.clone();
        control_aad.aad = "route\ninjected".to_string();
        assert_eq!(
            control_aad.validate().expect_err("control aad").code(),
            ErrorCode::InvalidInput
        );

        let mut long_aad = valid.clone();
        long_aad.aad = "a".repeat(MAX_AAD_BYTES + 1);
        assert_eq!(
            long_aad.validate().expect_err("long aad").code(),
            ErrorCode::LimitExceeded
        );

        let mut zero_ttl = valid;
        zero_ttl.ttl_ms = 0;
        assert_eq!(
            zero_ttl.validate().expect_err("zero ttl").code(),
            ErrorCode::InvalidInput
        );

        let zero_bytes = RelayPolicy {
            max_bytes: 0,
            ..RelayPolicy::default()
        };
        assert_eq!(
            zero_bytes.validate().expect_err("zero max_bytes").code(),
            ErrorCode::InvalidInput
        );

        let zero_ttl_policy = RelayPolicy {
            max_ttl_ms: 0,
            ..RelayPolicy::default()
        };
        assert_eq!(
            zero_ttl_policy
                .validate()
                .expect_err("zero max_ttl_ms")
                .code(),
            ErrorCode::InvalidInput
        );

        let bad_relay = RelayPolicy {
            approved_relays: ["bad".to_string()].into_iter().collect(),
            ..RelayPolicy::default()
        };
        assert_eq!(
            bad_relay.validate().expect_err("malformed relay id").code(),
            ErrorCode::InvalidInput
        );

        assert!(RelayPolicy::default().validate().is_ok());
    }

    #[test]
    fn envelopes_and_hops_survive_serde() {
        let (src, dst) = (key(), key());
        let envelope = make_envelope(20, &src, &dst, seal_for_endpoint(b"payload"), NOW, TTL);
        let json = serde_json::to_string(&envelope).expect("serialise");
        let restored: RelayEnvelope = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(restored, envelope);
        assert_eq!(
            open(&restored, &endpoint_key()).expect("restored envelope opens"),
            b"payload"
        );

        let hop = Forwarded {
            envelope: restored,
            relay_id: src.device_id().to_string(),
            at_ms: NOW,
        };
        let json = serde_json::to_string(&hop).expect("serialise hop");
        let restored: Forwarded = serde_json::from_str(&json).expect("deserialise hop");
        assert_eq!(restored, hop);
    }
}
