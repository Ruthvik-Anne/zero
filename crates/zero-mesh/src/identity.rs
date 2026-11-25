//! Mesh device identity, join tokens, approval, revocation, and rotation
//! (T-MESH-01, MESH-07, MESH-08, MESH-09).
//!
//! Every device owns an Ed25519 key pair. Its device id is the hex blake3 hash
//! of the public key, so the id is a stable function of the key and cannot be
//! chosen independently. Private key bytes never cross a `Debug`, `Display`, or
//! error boundary.
//!
//! Joining is a two-step flow. The owner root mints a short-lived, single-use
//! [`JoinToken`] and hands the device a [`short code`](JoinToken::short_code) or
//! a [`QR payload`](JoinToken::payload). The owner records the device's public
//! key with that token; [`join`](Membership::join) records a pending request and
//! refuses with `zero.pol.denied`, so an unapproved device is never a member.
//! Only the owner root key can [`approve`](Membership::approve) or
//! [`revoke`](Membership::revoke); a [`rotation`](Membership::rotate) must be
//! signed by the device key it replaces.
//!
//! Membership state is local to this process and serialisable with serde.
//! Owner-signed, versioned snapshots live in [`crate::state`]; threshold
//! delegates and the audit trail are deferred. Nothing here talks to the
//! network.

use std::collections::BTreeMap;
use std::fmt;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, ZeroError};

/// Length of an Ed25519 public key in bytes.
pub const PUBLIC_KEY_BYTES: usize = 32;

/// Length of an Ed25519 signature in bytes.
pub const SIGNATURE_BYTES: usize = 64;

/// Number of random bytes in a join-token id (16 hex characters).
pub const TOKEN_ID_BYTES: usize = 8;

/// Number of random bytes in a join-token secret (128 bits).
pub const TOKEN_SECRET_BYTES: usize = 16;

/// Default join-token lifetime: ten minutes.
pub const DEFAULT_TOKEN_TTL_MS: i64 = 10 * 60 * 1000;

/// Longest accepted join-token lifetime: twenty-four hours. Tokens are meant to
/// be short-lived, so an accidental "forever" invite is refused.
pub const MAX_TOKEN_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// Prefix of the QR payload string.
pub const JOIN_PAYLOAD_PREFIX: &str = "zero-join:v1:";

/// Domain separator for a signed join token. `used` is deliberately excluded:
/// consumption is local state; signed membership snapshots in [`crate::state`]
/// do not carry a token-consumption ledger.
const TOKEN_DOMAIN: &[u8] = b"zero.mesh.join-token.v1\0";

/// Domain separator for an owner approval.
const APPROVAL_DOMAIN: &[u8] = b"zero.mesh.approval.v1\0";

/// Domain separator for an owner revocation.
const REVOCATION_DOMAIN: &[u8] = b"zero.mesh.revocation.v1\0";

/// Domain separator for a device-signed key rotation.
const ROTATION_DOMAIN: &[u8] = b"zero.mesh.rotation.v1\0";

/// Crockford base32 alphabet used by the short join code.
const CODE_ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// An Ed25519 device key pair.
///
/// The signing key is private to this type: it has no accessor, and `Debug`
/// prints only the derived device id. Generate one with
/// [`KeyPair::generate`], which draws the seed from the operating system.
pub struct KeyPair {
    signing: SigningKey,
    device_id: String,
}

/// A device key pair. Alias kept for the requirement's wording.
pub type DeviceKey = KeyPair;

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

impl KeyPair {
    /// Mint a device key pair from operating-system entropy.
    pub fn generate() -> Result<Self, ZeroError> {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret)
            .map_err(|error| internal(format!("cannot read random bytes: {error}")))?;
        let signing = SigningKey::from_bytes(&secret);
        secret.fill(0);
        let device_id = derived_device_id(&signing.verifying_key());
        Ok(Self { signing, device_id })
    }

    /// The hex blake3 hash of this key's public bytes.
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Standard padded base64 of the 32-byte Ed25519 public key.
    pub fn public_key_b64(&self) -> String {
        B64.encode(self.signing.verifying_key().to_bytes())
    }

    /// Sign `bytes` and return the standard padded base64 signature.
    pub fn sign(&self, bytes: &[u8]) -> String {
        B64.encode(self.signing.sign(bytes).to_bytes())
    }

    /// Verify `signature_b64` over `bytes` with this pair's public key.
    pub fn verify(&self, bytes: &[u8], signature_b64: &str) -> Result<(), ZeroError> {
        verify(&self.public_key_b64(), bytes, signature_b64)
    }
}

/// Compute the device id for a base64 public key: the full 64-character hex
/// blake3 hash of the 32 key bytes.
pub fn device_id_for(public_key_b64: &str) -> Result<String, ZeroError> {
    Ok(derived_device_id(&decode_public_key(public_key_b64)?))
}

/// Verify a base64 Ed25519 signature over `bytes` with a base64 public key.
///
/// This is the only verification primitive in the module; callers never touch
/// `ed25519-dalek` directly. A malformed key, a malformed signature, or a
/// signature that does not match is `zero.pol.denied`.
pub fn verify(public_key_b64: &str, bytes: &[u8], signature_b64: &str) -> Result<(), ZeroError> {
    let public = decode_public_key(public_key_b64)?;
    let signature = decode_signature(signature_b64)?;
    public
        .verify_strict(bytes, &signature)
        .map_err(|_| denied("signature does not match the public key and payload"))
}

fn derived_device_id(public: &VerifyingKey) -> String {
    blake3::hash(&public.to_bytes()).to_hex().to_string()
}

fn decode_public_key(public_key_b64: &str) -> Result<VerifyingKey, ZeroError> {
    let bytes = B64
        .decode(public_key_b64.trim())
        .map_err(|_| invalid("public key is not valid base64"))?;
    let bytes: [u8; PUBLIC_KEY_BYTES] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid(format!("public key must be {PUBLIC_KEY_BYTES} bytes")))?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| invalid("public key is not a valid Ed25519 key"))
}

fn decode_signature(signature_b64: &str) -> Result<Signature, ZeroError> {
    let bytes = B64
        .decode(signature_b64.trim())
        .map_err(|_| invalid("signature is not valid base64"))?;
    let bytes: [u8; SIGNATURE_BYTES] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid(format!("signature must be {SIGNATURE_BYTES} bytes")))?;
    Ok(Signature::from_bytes(&bytes))
}

/// A device the owner has added to the mesh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    /// Hex blake3 of the public key.
    pub device_id: String,
    /// Base64 Ed25519 public key.
    pub public_key_b64: String,
    /// Optional human label, preserved across rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// When the owner approved the device, in milliseconds since the Unix epoch.
    pub added_ms: i64,
    /// True once the owner revoked the device. The record is kept so the id
    /// cannot silently re-enter with the old key.
    pub revoked: bool,
    /// The device id this key replaced, when the record came from a rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_from: Option<String>,
}

/// A join request awaiting owner approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingJoin {
    /// Hex blake3 of the requesting device's public key.
    pub device_id: String,
    /// Base64 Ed25519 public key supplied with the request.
    pub public_key_b64: String,
    /// The token that authorised the request.
    pub token_id: String,
    /// When the request was recorded, in milliseconds since the Unix epoch.
    pub requested_ms: i64,
}

/// A signed, short-lived, single-use invitation minted by the owner root.
///
/// The signature covers the id, secret, issue time, expiry, and `max_uses`.
/// `used` is local consumption state and is not signed; the owner-signed
/// membership snapshot in [`crate::state`] does not carry it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinToken {
    /// 16 hex characters of random id.
    pub id: String,
    /// Standard padded base64 of the 16-byte secret.
    pub secret_b64: String,
    /// Issue time, in milliseconds since the Unix epoch.
    pub issued_ms: i64,
    /// Expiry time, in milliseconds since the Unix epoch.
    pub expires_ms: i64,
    /// Number of successful uses allowed; tokens are single-use.
    #[serde(default = "default_max_uses")]
    pub max_uses: u32,
    /// Local use counter; refused at `max_uses`.
    #[serde(default)]
    pub used: u32,
    /// Standard padded base64 Ed25519 signature by the owner root.
    #[serde(default)]
    pub signature_b64: String,
}

fn default_max_uses() -> u32 {
    1
}

/// The id and secret a device presents to the owner, without the signature.
///
/// [`parse_join_payload`] returns this shape for both the QR payload and the
/// short code. The owner looks the matching [`JoinToken`] up locally and then
/// runs the full signature, expiry, and use checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinPayload {
    /// The token id the device claims.
    pub id: String,
    /// The token secret the device claims.
    pub secret_b64: String,
}

impl JoinToken {
    /// The QR payload string:
    /// `zero-join:v1:<id>:<secret_b64>`. It carries no signature, so treat it
    /// as a secret with the same handling as the short code.
    pub fn payload(&self) -> Result<String, ZeroError> {
        self.validate_material()?;
        Ok(format!(
            "{JOIN_PAYLOAD_PREFIX}{}:{}",
            self.id, self.secret_b64
        ))
    }

    /// The human-typeable short code: Crockford base32 of the id bytes followed
    /// by the secret bytes, grouped in fours with hyphens.
    pub fn short_code(&self) -> Result<String, ZeroError> {
        self.validate_material()?;
        let mut bytes = Vec::with_capacity(TOKEN_ID_BYTES + TOKEN_SECRET_BYTES);
        bytes.extend_from_slice(&hex_decode(&self.id)?);
        bytes.extend_from_slice(&self.secret_bytes()?);
        Ok(group_code(&base32_encode(&bytes)))
    }

    fn secret_bytes(&self) -> Result<Vec<u8>, ZeroError> {
        let secret = B64
            .decode(&self.secret_b64)
            .map_err(|_| invalid("join token secret is not valid base64"))?;
        if secret.len() != TOKEN_SECRET_BYTES {
            return Err(invalid(format!(
                "join token secret must be {TOKEN_SECRET_BYTES} bytes"
            )));
        }
        Ok(secret)
    }

    fn validate_material(&self) -> Result<(), ZeroError> {
        validate_token_id(&self.id)?;
        self.secret_bytes()?;
        Ok(())
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        framed(
            TOKEN_DOMAIN,
            &[
                self.id.as_bytes(),
                self.secret_b64.as_bytes(),
                &self.issued_ms.to_be_bytes(),
                &self.expires_ms.to_be_bytes(),
                &self.max_uses.to_be_bytes(),
            ],
        )
    }
}

/// Mint a join token signed by the owner root. `ttl_ms` must be positive.
pub fn issue_token(owner_key: &KeyPair, ttl_ms: i64, now_ms: i64) -> Result<JoinToken, ZeroError> {
    if ttl_ms <= 0 {
        return Err(invalid("join token ttl must be positive"));
    }
    if ttl_ms > MAX_TOKEN_TTL_MS {
        return Err(ZeroError::new(
            ErrorCode::LimitExceeded,
            format!("join token ttl {ttl_ms} ms exceeds {MAX_TOKEN_TTL_MS} ms"),
        ));
    }
    let expires_ms = now_ms
        .checked_add(ttl_ms)
        .ok_or_else(|| invalid("join token expiry overflows the clock"))?;
    let mut id_bytes = [0u8; TOKEN_ID_BYTES];
    let mut secret = [0u8; TOKEN_SECRET_BYTES];
    getrandom::getrandom(&mut id_bytes)
        .map_err(|error| internal(format!("cannot read random bytes: {error}")))?;
    getrandom::getrandom(&mut secret)
        .map_err(|error| internal(format!("cannot read random bytes: {error}")))?;
    let secret_b64 = B64.encode(secret);
    secret.fill(0);
    let mut token = JoinToken {
        id: hex(&id_bytes),
        secret_b64,
        issued_ms: now_ms,
        expires_ms,
        max_uses: 1,
        used: 0,
        signature_b64: String::new(),
    };
    token.signature_b64 = owner_key.sign(&token.canonical_bytes());
    Ok(token)
}

/// Check a join token against the owner public key at `now_ms`: signature,
/// expiry, and remaining uses. It does not consume the token.
pub fn verify_token(
    token: &JoinToken,
    owner_public_key_b64: &str,
    now_ms: i64,
) -> Result<(), ZeroError> {
    if token.max_uses == 0 {
        return Err(invalid("join token max_uses must be at least one"));
    }
    token.validate_material()?;
    verify(
        owner_public_key_b64,
        &token.canonical_bytes(),
        &token.signature_b64,
    )
    .map_err(|_| denied("join token is not signed by the owner root"))?;
    if now_ms > token.expires_ms {
        return Err(ZeroError::new(
            ErrorCode::ApprovalExpired,
            format!(
                "join token `{}` expired at {} ms",
                token.id, token.expires_ms
            ),
        ));
    }
    if token.used >= token.max_uses {
        return Err(denied(format!(
            "join token `{}` has already been used {} time(s)",
            token.id, token.used
        )));
    }
    Ok(())
}

/// Consume one use of a token. A second use of a single-use token is refused
/// with `zero.pol.denied`; an expired token is `zero.pol.approval_expired`.
pub fn consume(token: &mut JoinToken, now_ms: i64) -> Result<(), ZeroError> {
    if token.max_uses == 0 {
        return Err(invalid("join token max_uses must be at least one"));
    }
    if now_ms > token.expires_ms {
        return Err(ZeroError::new(
            ErrorCode::ApprovalExpired,
            format!(
                "join token `{}` expired at {} ms",
                token.id, token.expires_ms
            ),
        ));
    }
    if token.used >= token.max_uses {
        return Err(denied(format!(
            "join token `{}` has already been used {} time(s)",
            token.id, token.used
        )));
    }
    token.used += 1;
    Ok(())
}

/// Parse a QR payload or a short code into the id and secret a device presents.
///
/// The short code tolerates lower case, spaces, and missing or extra hyphens;
/// Crockford aliases `O`/`I`/`L` are folded to `0`/`1`.
pub fn parse_join_payload(text: &str) -> Result<JoinPayload, ZeroError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(invalid("join payload is empty"));
    }
    if let Some(rest) = text.strip_prefix(JOIN_PAYLOAD_PREFIX) {
        let (id, secret_b64) = rest
            .split_once(':')
            .ok_or_else(|| invalid("join payload is missing the token secret"))?;
        validate_token_id(id)?;
        let payload = JoinPayload {
            id: id.to_string(),
            secret_b64: secret_b64.to_string(),
        };
        validate_payload_secret(&payload)?;
        return Ok(payload);
    }

    let compact: String = text
        .chars()
        .filter(|ch| !matches!(ch, '-' | ' ' | '\t' | '\r' | '\n'))
        .collect();
    if compact.is_empty() {
        return Err(invalid("join code is empty"));
    }
    let bytes = base32_decode(&compact)?;
    if bytes.len() != TOKEN_ID_BYTES + TOKEN_SECRET_BYTES {
        return Err(invalid(format!(
            "join code must carry {} bytes, not {}",
            TOKEN_ID_BYTES + TOKEN_SECRET_BYTES,
            bytes.len()
        )));
    }
    let payload = JoinPayload {
        id: hex(&bytes[..TOKEN_ID_BYTES]),
        secret_b64: B64.encode(&bytes[TOKEN_ID_BYTES..]),
    };
    validate_payload_secret(&payload)?;
    Ok(payload)
}

fn validate_payload_secret(payload: &JoinPayload) -> Result<(), ZeroError> {
    let secret = B64
        .decode(&payload.secret_b64)
        .map_err(|_| invalid("join payload secret is not valid base64"))?;
    if secret.len() != TOKEN_SECRET_BYTES {
        return Err(invalid(format!(
            "join payload secret must be {TOKEN_SECRET_BYTES} bytes"
        )));
    }
    Ok(())
}

/// The owner's signed key rotation request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationRequest {
    /// The device id being replaced.
    pub from_device_id: String,
    /// The replacement public key.
    pub new_public_key_b64: String,
    /// The replacement device id, derived from the new public key.
    pub new_device_id: String,
    /// When the rotation was signed, in milliseconds since the Unix epoch.
    pub rotated_ms: i64,
    /// The old device key's standard padded base64 signature.
    pub signature_b64: String,
}

impl RotationRequest {
    fn canonical_bytes(&self) -> Vec<u8> {
        framed(
            ROTATION_DOMAIN,
            &[
                self.from_device_id.as_bytes(),
                self.new_public_key_b64.as_bytes(),
                self.new_device_id.as_bytes(),
                &self.rotated_ms.to_be_bytes(),
            ],
        )
    }
}

/// Sign a rotation with the old device key. The new key's id is derived, not
/// supplied, so the signature binds the exact replacement key.
pub fn sign_rotation(
    old_key: &KeyPair,
    new_key: &KeyPair,
    now_ms: i64,
) -> Result<RotationRequest, ZeroError> {
    if old_key.device_id() == new_key.device_id() {
        return Err(invalid(
            "a rotation must name a different key than the one it replaces",
        ));
    }
    let mut request = RotationRequest {
        from_device_id: old_key.device_id().to_string(),
        new_public_key_b64: new_key.public_key_b64(),
        new_device_id: new_key.device_id().to_string(),
        rotated_ms: now_ms,
        signature_b64: String::new(),
    };
    request.signature_b64 = old_key.sign(&request.canonical_bytes());
    Ok(request)
}

/// Apply a rotation request after checking the old key's signature.
///
/// The old record is marked revoked and kept, and the replacement record carries
/// `rotated_from = Some(old_device_id)`. A revoked device cannot rotate, and a
/// key whose id was revoked cannot become the replacement.
pub fn apply_rotation(
    membership: &mut Membership,
    request: &RotationRequest,
) -> Result<DeviceRecord, ZeroError> {
    validate_device_id(&request.from_device_id)?;
    validate_device_id(&request.new_device_id)?;
    let old = membership
        .devices
        .get(&request.from_device_id)
        .cloned()
        .ok_or_else(|| not_found(format!("no device `{}` to rotate", request.from_device_id)))?;
    if old.revoked {
        return Err(denied(format!(
            "device `{}` is revoked and cannot rotate its key",
            request.from_device_id
        )));
    }
    if request.new_device_id == request.from_device_id {
        return Err(invalid(
            "a rotation must name a different key than the one it replaces",
        ));
    }
    let derived = device_id_for(&request.new_public_key_b64)?;
    if derived != request.new_device_id {
        return Err(invalid(
            "rotation device id does not match the replacement public key",
        ));
    }
    if let Some(existing) = membership.devices.get(&request.new_device_id) {
        if existing.revoked {
            return Err(denied(format!(
                "device id `{}` is revoked and cannot be rotated in",
                request.new_device_id
            )));
        }
        return Err(already_exists(format!(
            "device `{}` is already a member",
            request.new_device_id
        )));
    }
    verify(
        &old.public_key_b64,
        &request.canonical_bytes(),
        &request.signature_b64,
    )
    .map_err(|_| denied("rotation is not signed by the device key it replaces"))?;

    let name = old.name.clone();
    let mut old = old;
    old.revoked = true;
    membership
        .devices
        .insert(request.from_device_id.clone(), old);
    let record = DeviceRecord {
        device_id: request.new_device_id.clone(),
        public_key_b64: request.new_public_key_b64.clone(),
        name,
        added_ms: request.rotated_ms,
        revoked: false,
        rotated_from: Some(request.from_device_id.clone()),
    };
    membership
        .devices
        .insert(request.new_device_id.clone(), record.clone());
    Ok(record)
}

/// Local membership state: the owner root, approved devices, pending joins, and
/// consumed tokens.
///
/// This type is serialisable, but it is not replicated or independently
/// verifiable; the owner-signed snapshot is [`crate::state::MembershipState`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Membership {
    /// Base64 owner root public key. Only this key can approve, revoke, or
    /// rotate.
    pub owner_public_key_b64: String,
    /// Approved devices, including revoked records, keyed by device id.
    pub devices: BTreeMap<String, DeviceRecord>,
    /// Join requests awaiting approval, keyed by device id.
    pub pending: BTreeMap<String, PendingJoin>,
    /// Token id to consumption time. Enforces single use across one membership
    /// even if a token is copied.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub consumed_tokens: BTreeMap<String, i64>,
}

impl Membership {
    /// Start an empty membership for an owner root public key.
    pub fn new(owner_public_key_b64: impl Into<String>) -> Result<Self, ZeroError> {
        let owner_public_key_b64 = owner_public_key_b64.into();
        decode_public_key(&owner_public_key_b64)?;
        Ok(Self {
            owner_public_key_b64,
            devices: BTreeMap::new(),
            pending: BTreeMap::new(),
            consumed_tokens: BTreeMap::new(),
        })
    }

    /// True when `device_id` is an approved, non-revoked member.
    pub fn is_member(&self, device_id: &str) -> bool {
        self.devices
            .get(device_id)
            .map(|record| !record.revoked)
            .unwrap_or(false)
    }

    /// True when the device is not already a member and has no revocation on
    /// record, so a join request could still be recorded for it.
    pub fn can_join(&self, device_id: &str) -> bool {
        if self.is_member(device_id) {
            return false;
        }
        !self
            .devices
            .get(device_id)
            .map(|record| record.revoked)
            .unwrap_or(false)
    }

    /// Present a join token for a device.
    ///
    /// The token is verified and consumed, and the request is recorded in
    /// [`Membership::pending`]. The call still returns `zero.pol.denied`: an
    /// unapproved device is not a member. Once the owner approves, a repeated
    /// call is idempotent and returns the approved record.
    pub fn join(
        &mut self,
        token: &mut JoinToken,
        device_public_key_b64: &str,
        now_ms: i64,
    ) -> Result<DeviceRecord, ZeroError> {
        let device_id = device_id_for(device_public_key_b64)?;

        let mut revoked = false;
        if let Some(record) = self.devices.get(&device_id).cloned() {
            if record.public_key_b64 != device_public_key_b64 {
                return Err(denied(
                    "device id does not match the public key presented for it",
                ));
            }
            if !record.revoked {
                return Ok(record);
            }
            revoked = true;
        }

        verify_token(token, &self.owner_public_key_b64, now_ms)?;
        if self.consumed_tokens.contains_key(&token.id) {
            return Err(denied(format!(
                "join token `{}` has already been used",
                token.id
            )));
        }
        if self.pending.contains_key(&device_id) {
            return Err(denied(format!(
                "device `{device_id}` already has a join request pending owner approval"
            )));
        }

        consume(token, now_ms)?;
        self.consumed_tokens.insert(token.id.clone(), now_ms);
        self.pending.insert(
            device_id.clone(),
            PendingJoin {
                device_id: device_id.clone(),
                public_key_b64: device_public_key_b64.to_string(),
                token_id: token.id.clone(),
                requested_ms: now_ms,
            },
        );
        if revoked {
            return Err(denied(format!(
                "device `{device_id}` is revoked; a fresh owner approval is required"
            )));
        }
        Err(denied(format!(
            "device `{device_id}` is pending owner approval"
        )))
    }

    /// Approve a pending join, or re-admit a revoked device with a fresh owner
    /// approval. Only the owner root key may call this.
    pub fn approve(
        &mut self,
        owner_key: &KeyPair,
        device_id: &str,
        now_ms: i64,
    ) -> Result<DeviceRecord, ZeroError> {
        self.require_owner(owner_key)?;
        validate_device_id(device_id)?;

        let existing = self.devices.get(device_id).cloned();
        if let Some(record) = &existing {
            if !record.revoked {
                return Ok(record.clone());
            }
        }

        let (public_key_b64, rotated_from, name) = match &existing {
            Some(record) => (
                record.public_key_b64.clone(),
                record.rotated_from.clone(),
                record.name.clone(),
            ),
            None => {
                let pending = self.pending.get(device_id).ok_or_else(|| {
                    not_found(format!("no join request for device `{device_id}`"))
                })?;
                (pending.public_key_b64.clone(), None, None)
            }
        };
        if device_id_for(&public_key_b64)? != device_id {
            return Err(invalid(
                "pending device id does not match the public key it presents",
            ));
        }

        let bytes = approval_bytes(device_id, &public_key_b64, now_ms);
        let signature_b64 = owner_key.sign(&bytes);
        verify(&self.owner_public_key_b64, &bytes, &signature_b64)?;

        let record = DeviceRecord {
            device_id: device_id.to_string(),
            public_key_b64,
            name,
            added_ms: now_ms,
            revoked: false,
            rotated_from,
        };
        self.devices.insert(device_id.to_string(), record.clone());
        self.pending.remove(device_id);
        Ok(record)
    }

    /// Mark an approved device revoked. The record is kept so the same key
    /// cannot silently re-join. Only the owner root key may call this.
    pub fn revoke(
        &mut self,
        owner_key: &KeyPair,
        device_id: &str,
        now_ms: i64,
    ) -> Result<DeviceRecord, ZeroError> {
        self.require_owner(owner_key)?;
        validate_device_id(device_id)?;
        let mut record = self
            .devices
            .get(device_id)
            .cloned()
            .ok_or_else(|| not_found(format!("no device `{device_id}` to revoke")))?;
        if record.revoked {
            return Ok(record);
        }

        let bytes = revocation_bytes(device_id, now_ms);
        let signature_b64 = owner_key.sign(&bytes);
        verify(&self.owner_public_key_b64, &bytes, &signature_b64)?;

        record.revoked = true;
        self.devices.insert(device_id.to_string(), record.clone());
        Ok(record)
    }

    /// Rotate a device key. The old key signs the replacement, the old record is
    /// revoked, and the new record keeps `rotated_from`.
    pub fn rotate(
        &mut self,
        old_key: &KeyPair,
        new_key: &KeyPair,
        now_ms: i64,
    ) -> Result<DeviceRecord, ZeroError> {
        let request = sign_rotation(old_key, new_key, now_ms)?;
        apply_rotation(self, &request)
    }

    fn require_owner(&self, owner_key: &KeyPair) -> Result<(), ZeroError> {
        if owner_key.public_key_b64() != self.owner_public_key_b64 {
            return Err(denied(
                "only the owner root key can approve, revoke, or rotate membership",
            ));
        }
        Ok(())
    }
}

/// See [`Membership::join`].
pub fn join(
    membership: &mut Membership,
    token: &mut JoinToken,
    device_public_key_b64: &str,
    now_ms: i64,
) -> Result<DeviceRecord, ZeroError> {
    membership.join(token, device_public_key_b64, now_ms)
}

/// See [`Membership::approve`].
pub fn approve(
    membership: &mut Membership,
    owner_key: &KeyPair,
    device_id: &str,
    now_ms: i64,
) -> Result<DeviceRecord, ZeroError> {
    membership.approve(owner_key, device_id, now_ms)
}

/// See [`Membership::revoke`].
pub fn revoke(
    membership: &mut Membership,
    owner_key: &KeyPair,
    device_id: &str,
    now_ms: i64,
) -> Result<DeviceRecord, ZeroError> {
    membership.revoke(owner_key, device_id, now_ms)
}

/// See [`Membership::rotate`].
pub fn rotate(
    membership: &mut Membership,
    old_key: &KeyPair,
    new_key: &KeyPair,
    now_ms: i64,
) -> Result<DeviceRecord, ZeroError> {
    membership.rotate(old_key, new_key, now_ms)
}

/// True when `device_id` is an approved, non-revoked member.
pub fn is_member(membership: &Membership, device_id: &str) -> bool {
    membership.is_member(device_id)
}

/// True when a join request from `device_id` could still be recorded.
pub fn can_join(membership: &Membership, device_id: &str) -> bool {
    membership.can_join(device_id)
}

fn approval_bytes(device_id: &str, public_key_b64: &str, approved_ms: i64) -> Vec<u8> {
    framed(
        APPROVAL_DOMAIN,
        &[
            device_id.as_bytes(),
            public_key_b64.as_bytes(),
            &approved_ms.to_be_bytes(),
        ],
    )
}

fn revocation_bytes(device_id: &str, revoked_ms: i64) -> Vec<u8> {
    framed(
        REVOCATION_DOMAIN,
        &[device_id.as_bytes(), &revoked_ms.to_be_bytes()],
    )
}

/// Length-prefix every field so no two payloads can share an encoding by moving
/// bytes across a boundary.
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

fn validate_token_id(id: &str) -> Result<(), ZeroError> {
    if id.len() != TOKEN_ID_BYTES * 2 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(format!(
            "join token id must be {} hex characters",
            TOKEN_ID_BYTES * 2
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

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hex_decode(text: &str) -> Result<Vec<u8>, ZeroError> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(
            "hex input must have an even number of hex characters",
        ));
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(|_| invalid("hex input is not ASCII"))?;
            u8::from_str_radix(pair, 16).map_err(|_| invalid("hex input is malformed"))
        })
        .collect()
}

fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            out.push(CODE_ALPHABET.as_bytes()[index] as char);
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(CODE_ALPHABET.as_bytes()[index] as char);
    }
    out
}

fn base32_decode(text: &str) -> Result<Vec<u8>, ZeroError> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for ch in text.chars() {
        let value = base32_value(ch)
            .ok_or_else(|| invalid(format!("`{ch}` is not a join-code character")))?;
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1u32 << bits) - 1;
        }
    }
    if buffer != 0 {
        return Err(invalid("join code has non-zero padding bits"));
    }
    Ok(out)
}

fn base32_value(ch: char) -> Option<u8> {
    let upper = ch.to_ascii_uppercase();
    let normalized = match upper {
        'O' => '0',
        'I' | 'L' => '1',
        other => other,
    };
    CODE_ALPHABET
        .as_bytes()
        .iter()
        .position(|&byte| byte as char == normalized)
        .map(|index| index as u8)
}

fn group_code(code: &str) -> String {
    let mut grouped = String::with_capacity(code.len() + code.len() / 4);
    for (index, ch) in code.chars().enumerate() {
        if index > 0 && index % 4 == 0 {
            grouped.push('-');
        }
        grouped.push(ch);
    }
    grouped
}

fn denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyDenied, message)
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn not_found(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::NotFound, message)
}

fn already_exists(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::AlreadyExists, message)
}

fn internal(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Internal, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000_000;
    const TTL: i64 = 5 * 60 * 1000;

    fn key() -> KeyPair {
        KeyPair::generate().expect("device key")
    }

    fn new_membership() -> (Membership, KeyPair) {
        let owner = key();
        let membership = Membership::new(owner.public_key_b64()).expect("membership");
        (membership, owner)
    }

    fn approved_device(membership: &mut Membership, owner: &KeyPair) -> (KeyPair, JoinToken) {
        let device = key();
        let mut token = issue_token(owner, TTL, NOW).expect("token");
        let error = join(membership, &mut token, &device.public_key_b64(), NOW)
            .expect_err("an unapproved device cannot join");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        approve(membership, owner, device.device_id(), NOW + 1).expect("approve");
        (device, token)
    }

    fn error_code(result: Result<DeviceRecord, ZeroError>) -> ErrorCode {
        result.expect_err("the operation should fail").code()
    }

    #[test]
    fn an_unapproved_device_cannot_join() {
        let (mut membership, owner) = new_membership();
        let device = key();
        let mut token = issue_token(&owner, TTL, NOW).expect("token");

        let error = join(&mut membership, &mut token, &device.public_key_b64(), NOW)
            .expect_err("an unapproved device cannot join");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("pending owner approval"));
        assert!(!is_member(&membership, device.device_id()));
        assert!(membership.pending.contains_key(device.device_id()));
        assert_eq!(token.used, 1);
    }

    #[test]
    fn a_valid_token_and_owner_approval_joins() {
        let (mut membership, owner) = new_membership();
        let (device, token) = approved_device(&mut membership, &owner);

        assert!(is_member(&membership, device.device_id()));
        assert!(!can_join(&membership, device.device_id()));
        assert!(!membership.devices[device.device_id()].revoked);
        assert_eq!(
            membership.devices[device.device_id()].public_key_b64,
            device.public_key_b64()
        );

        let mut replay = token.clone();
        let record = join(
            &mut membership,
            &mut replay,
            &device.public_key_b64(),
            NOW + 2,
        )
        .expect("a repeated join from an approved device is idempotent");
        assert_eq!(record.device_id, device.device_id());
        assert_eq!(membership.devices.len(), 1);
        assert!(membership.pending.is_empty());
    }

    #[test]
    fn an_expired_token_is_refused() {
        let (mut membership, owner) = new_membership();
        let device = key();
        let mut token = issue_token(&owner, 1_000, NOW).expect("token");

        assert_eq!(
            error_code(join(
                &mut membership,
                &mut token,
                &device.public_key_b64(),
                NOW + 1_001
            )),
            ErrorCode::ApprovalExpired
        );
        assert!(membership.pending.is_empty());
        assert!(!is_member(&membership, device.device_id()));

        let mut direct = token.clone();
        assert_eq!(
            consume(&mut direct, NOW + 1_001)
                .expect_err("expired token cannot be consumed")
                .code(),
            ErrorCode::ApprovalExpired
        );
    }

    #[test]
    fn a_reused_token_is_refused() {
        let (mut membership, owner) = new_membership();
        let first = key();
        let second = key();
        let mut token = issue_token(&owner, TTL, NOW).expect("token");

        assert_eq!(
            error_code(join(
                &mut membership,
                &mut token,
                &first.public_key_b64(),
                NOW
            )),
            ErrorCode::PolicyDenied
        );
        assert_eq!(token.used, 1);

        let error = join(
            &mut membership,
            &mut token,
            &second.public_key_b64(),
            NOW + 1,
        )
        .expect_err("a consumed token cannot be reused");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("already been used"));
        assert!(!membership.pending.contains_key(second.device_id()));
        assert_eq!(
            consume(&mut token, NOW + 1)
                .expect_err("single-use token")
                .code(),
            ErrorCode::PolicyDenied
        );
    }

    #[test]
    fn a_tampered_token_is_refused() {
        let (membership, owner) = new_membership();
        let device = key();
        let token = issue_token(&owner, TTL, NOW).expect("token");

        let mut other_secret = token.clone();
        other_secret.secret_b64 = B64.encode([9u8; TOKEN_SECRET_BYTES]);
        assert_eq!(
            verify_token(&other_secret, &membership.owner_public_key_b64, NOW)
                .expect_err("tampered secret")
                .code(),
            ErrorCode::PolicyDenied
        );

        let mut extended = token.clone();
        extended.expires_ms += 1;
        assert_eq!(
            verify_token(&extended, &membership.owner_public_key_b64, NOW)
                .expect_err("tampered expiry")
                .code(),
            ErrorCode::PolicyDenied
        );

        let mut renamed = token.clone();
        renamed.id = "0123456789abcdef".to_string();
        assert_eq!(
            verify_token(&renamed, &membership.owner_public_key_b64, NOW)
                .expect_err("tampered id")
                .code(),
            ErrorCode::PolicyDenied
        );

        let other_owner = key().public_key_b64();
        assert_eq!(
            verify_token(&token, &other_owner, NOW)
                .expect_err("wrong owner key")
                .code(),
            ErrorCode::PolicyDenied
        );

        assert!(verify_token(&token, &membership.owner_public_key_b64, NOW).is_ok());
        assert!(!is_member(&membership, device.device_id()));
    }

    #[test]
    fn a_non_owner_cannot_approve_or_revoke() {
        let (mut membership, owner) = new_membership();
        let device = key();
        let mut token = issue_token(&owner, TTL, NOW).expect("token");
        assert_eq!(
            error_code(join(
                &mut membership,
                &mut token,
                &device.public_key_b64(),
                NOW
            )),
            ErrorCode::PolicyDenied
        );

        let intruder = key();
        let error = approve(&mut membership, &intruder, device.device_id(), NOW + 1)
            .expect_err("a non-owner cannot approve");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(!is_member(&membership, device.device_id()));

        approve(&mut membership, &owner, device.device_id(), NOW + 2).expect("owner approves");
        assert!(is_member(&membership, device.device_id()));
        assert_eq!(
            error_code(revoke(
                &mut membership,
                &intruder,
                device.device_id(),
                NOW + 3
            )),
            ErrorCode::PolicyDenied
        );
        assert!(is_member(&membership, device.device_id()));
    }

    #[test]
    fn a_revoked_device_cannot_join_or_rotate_back() {
        let (mut membership, owner) = new_membership();
        let (device, _token) = approved_device(&mut membership, &owner);
        let record = revoke(&mut membership, &owner, device.device_id(), NOW + 10).expect("revoke");
        assert!(record.revoked);
        assert!(!is_member(&membership, device.device_id()));
        assert!(!can_join(&membership, device.device_id()));

        let mut fresh = issue_token(&owner, TTL, NOW + 11).expect("fresh token");
        let error = join(
            &mut membership,
            &mut fresh,
            &device.public_key_b64(),
            NOW + 12,
        )
        .expect_err("a revoked device cannot rejoin on its own");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("revoked"));
        assert!(!is_member(&membership, device.device_id()));

        let replacement = key();
        assert_eq!(
            error_code(rotate(&mut membership, &device, &replacement, NOW + 13)),
            ErrorCode::PolicyDenied
        );
        assert!(!is_member(&membership, replacement.device_id()));

        let readmitted = approve(&mut membership, &owner, device.device_id(), NOW + 14)
            .expect("a fresh owner approval re-admits the device");
        assert!(!readmitted.revoked);
        assert!(is_member(&membership, device.device_id()));
    }

    #[test]
    fn rotation_requires_the_old_key_and_updates_the_id() {
        let (mut membership, owner) = new_membership();
        let (old, _token) = approved_device(&mut membership, &owner);
        let new = key();

        let rotated = rotate(&mut membership, &old, &new, NOW + 20).expect("rotate");
        assert_eq!(rotated.device_id, new.device_id());
        assert_eq!(rotated.public_key_b64, new.public_key_b64());
        assert_eq!(rotated.rotated_from.as_deref(), Some(old.device_id()));
        assert!(!rotated.revoked);
        assert!(!is_member(&membership, old.device_id()));
        assert!(is_member(&membership, new.device_id()));
        assert!(membership.devices[old.device_id()].revoked);

        // The old key can no longer rotate, because its record is revoked.
        assert_eq!(
            error_code(rotate(&mut membership, &old, &key(), NOW + 21)),
            ErrorCode::PolicyDenied
        );

        // A request not signed by the old device key is refused even when the
        // derived id is internally consistent.
        let (mut other_membership, other_owner) = new_membership();
        let (other_old, _) = approved_device(&mut other_membership, &other_owner);
        let replacement = key();
        let mut request = sign_rotation(&other_old, &replacement, NOW + 22).expect("sign rotation");
        let stolen = key();
        request.new_public_key_b64 = stolen.public_key_b64();
        request.new_device_id = stolen.device_id().to_string();
        assert_eq!(
            error_code(apply_rotation(&mut other_membership, &request)),
            ErrorCode::PolicyDenied
        );
        assert!(is_member(&other_membership, other_old.device_id()));
        assert!(!is_member(&other_membership, stolen.device_id()));

        // An unrelated key cannot stand in for the old device key.
        assert_eq!(
            error_code(rotate(&mut membership, &key(), &key(), NOW + 23)),
            ErrorCode::NotFound
        );
    }

    #[test]
    fn short_code_and_qr_payload_round_trip() {
        let (_, owner) = new_membership();
        let token = issue_token(&owner, TTL, NOW).expect("token");

        let payload = token.payload().expect("payload");
        assert!(payload.starts_with(JOIN_PAYLOAD_PREFIX));
        let parsed = parse_join_payload(&payload).expect("parse payload");
        assert_eq!(parsed.id, token.id);
        assert_eq!(parsed.secret_b64, token.secret_b64);

        let code = token.short_code().expect("short code");
        assert!(code.contains('-'));
        assert_eq!(token.short_code().expect("stable"), code);
        let parsed = parse_join_payload(&code).expect("parse short code");
        assert_eq!(parsed.id, token.id);
        assert_eq!(parsed.secret_b64, token.secret_b64);

        let messy = format!("  {}  ", code.to_lowercase());
        let parsed = parse_join_payload(&messy).expect("lower case with spaces");
        assert_eq!(parsed.id, token.id);
        assert_eq!(parsed.secret_b64, token.secret_b64);

        assert_eq!(
            parse_join_payload("not a join code")
                .expect_err("garbage")
                .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            parse_join_payload("zero-join:v1:short:AAAA")
                .expect_err("bad id")
                .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn private_key_bytes_never_cross_debug() {
        let device = key();
        let secret = device.signing.to_bytes();
        let secret_hex = hex(&secret);
        let secret_b64 = B64.encode(secret);

        let debug = format!("{device:?}");
        assert!(debug.contains(device.device_id()));
        assert!(!debug.contains(&secret_hex));
        assert!(!debug.contains(&secret_b64));

        let record = DeviceRecord {
            device_id: device.device_id().to_string(),
            public_key_b64: device.public_key_b64(),
            name: Some("laptop".to_string()),
            added_ms: NOW,
            revoked: false,
            rotated_from: None,
        };
        let record_debug = format!("{record:?}");
        assert!(!record_debug.contains(&secret_hex));
        assert!(!record_debug.contains(&secret_b64));

        let signature = device.sign(b"payload");
        assert!(!signature.contains(&secret_b64));
        assert!(device.verify(b"payload", &signature).is_ok());
        assert_eq!(
            device
                .verify(b"other payload", &signature)
                .expect_err("wrong payload")
                .code(),
            ErrorCode::PolicyDenied
        );
    }

    #[test]
    fn membership_survives_a_serde_round_trip() {
        let (mut membership, owner) = new_membership();
        let (device, _token) = approved_device(&mut membership, &owner);
        let mut token = issue_token(&owner, TTL, NOW).expect("second token");
        let second = key();
        assert_eq!(
            error_code(join(
                &mut membership,
                &mut token,
                &second.public_key_b64(),
                NOW + 1
            )),
            ErrorCode::PolicyDenied
        );

        let json = serde_json::to_string(&membership).expect("serialise");
        let restored: Membership = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(restored, membership);
        assert!(is_member(&restored, device.device_id()));
        assert!(!is_member(&restored, second.device_id()));
        assert!(restored.pending.contains_key(second.device_id()));
        assert!(restored.consumed_tokens.contains_key(&token.id));

        let token_json = serde_json::to_string(&token).expect("token serialise");
        let restored_token: JoinToken =
            serde_json::from_str(&token_json).expect("token deserialise");
        assert_eq!(restored_token, token);
    }

    #[test]
    fn a_duplicate_join_is_idempotent_and_a_pending_duplicate_is_refused() {
        let (mut membership, owner) = new_membership();
        let device = key();
        let mut token = issue_token(&owner, TTL, NOW).expect("token");
        assert_eq!(
            error_code(join(
                &mut membership,
                &mut token,
                &device.public_key_b64(),
                NOW
            )),
            ErrorCode::PolicyDenied
        );

        let mut second = issue_token(&owner, TTL, NOW).expect("second token");
        let error = join(
            &mut membership,
            &mut second,
            &device.public_key_b64(),
            NOW + 1,
        )
        .expect_err("a second pending request is refused");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("pending owner approval"));
        assert_eq!(membership.pending.len(), 1);
        assert_eq!(second.used, 0, "the duplicate request consumed no token");

        approve(&mut membership, &owner, device.device_id(), NOW + 2).expect("approve");
        approve(&mut membership, &owner, device.device_id(), NOW + 3)
            .expect("approval is idempotent");
        assert_eq!(membership.devices.len(), 1);
        assert!(membership.pending.is_empty());
    }

    #[test]
    fn malformed_ids_and_keys_are_typed() {
        let (_, owner) = new_membership();
        assert_eq!(
            Membership::new("not base64")
                .expect_err("bad owner key")
                .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            Membership::new(B64.encode([1u8; 8]))
                .expect_err("short owner key")
                .code(),
            ErrorCode::InvalidInput
        );

        let token = issue_token(&owner, TTL, NOW).expect("token");
        let mut bad = token.clone();
        bad.id = "zz".to_string();
        assert_eq!(
            bad.payload().expect_err("bad id").code(),
            ErrorCode::InvalidInput
        );

        assert_eq!(
            issue_token(&owner, 0, NOW).expect_err("zero ttl").code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            issue_token(&owner, MAX_TOKEN_TTL_MS + 1, NOW)
                .expect_err("ttl above the ceiling")
                .code(),
            ErrorCode::LimitExceeded
        );
        assert!(issue_token(&owner, MAX_TOKEN_TTL_MS, NOW).is_ok());
    }
}
