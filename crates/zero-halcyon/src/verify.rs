//! Halcyon mode signature verification (HAL-02, HAL-03, HAL-05).
//!
//! A `.halcyon-mode` file is a JSON [`ModeDocument`] carrying an Ed25519
//! signature over a deterministic canonical encoding of every field except the
//! signature itself. Verification checks, in order, the document's schema and
//! bounds, an exact pinned key id, the signature, the project binding, and the
//! issuance/expiry window. Only a [`VerifiedMode`] — constructible solely by
//! this module — is proof that those checks passed.
//!
//! Signing lives in [`crate::keys`] (T-HAL-03) behind the user-only actor gate;
//! this module stays the single verification path and refuses a key id that the
//! user has revoked, even when the pin record is still present.
//!
//! Errors carry a stable code and a reason, never key material: a base64 public
//! key or the signature bytes are never echoed into a message.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, ZeroError};

use crate::discovery::{
    Activation, Discovery, ModeFile, TrustGate, DEFAULT_MAX_MODE_FILE_BYTES, UNTRUSTED_REASON,
};
use crate::keys::{RevokedKey, RotationRecord};

/// Schema version this build understands.
pub const MODE_DOCUMENT_VERSION: u16 = 1;

/// Domain separation prefix of the canonical encoding.
///
/// Included so a signature over the mode bytes cannot be replayed as a
/// signature over some other Zero structure with the same field shapes.
pub const CANONICAL_DOMAIN: &[u8] = b"zero.halcyon.mode.v1\0";

/// Upper bound on the serialised mode document.
pub const MAX_MODE_DOCUMENT_BYTES: usize = 64 * 1024;

/// Upper bound on `project_id`, `nonce`, `key_id`, and each flag name.
pub const MAX_MODE_FIELD_BYTES: usize = 128;

/// Upper bound on the number of flags in one document.
pub const MAX_MODE_FLAGS: usize = 64;

/// Ed25519 signature length in bytes.
pub const SIGNATURE_BYTES: usize = 64;

/// Ed25519 public key length in bytes.
pub const PUBLIC_KEY_BYTES: usize = 32;

/// Upper bound on the base64 form of a signature.
pub const MAX_SIGNATURE_B64_BYTES: usize = 128;

/// Clock skew tolerated by [`verify`]: zero, so the window is strict by
/// default. Hosts can opt into tolerance with [`verify_with_skew`] or
/// [`Verifier::with_clock_skew_ms`].
pub const DEFAULT_CLOCK_SKEW_MS: i64 = 0;

/// Largest skew [`Verifier::with_clock_skew_ms`] accepts: one hour.
pub const MAX_CLOCK_SKEW_MS: i64 = 3_600_000;

/// Upper bound on the user pin set file.
pub const MAX_PIN_FILE_BYTES: usize = 64 * 1024;

/// Upper bound on the number of pinned keys.
pub const MAX_PINS: usize = 1024;

/// A parsed `.halcyon-mode` document.
///
/// Every field except [`ModeDocument::signature`] is covered by the signature.
/// The `signature` field is kept on the document for JSON round-tripping but is
/// deliberately excluded from [`canonical_bytes`]. Missing required fields and
/// wrong types are typed errors; unknown fields are ignored for forward
/// compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeDocument {
    /// Schema version; must be [`MODE_DOCUMENT_VERSION`].
    pub version: u16,
    /// Project this document binds to (HAL-05). Never a path.
    pub project_id: String,
    /// Issued-at time in milliseconds since the Unix epoch.
    pub issued_ms: i64,
    /// Expiry time in milliseconds since the Unix epoch.
    pub expires_ms: i64,
    /// Mode flags. Sorted by key in the canonical encoding.
    #[serde(default)]
    pub flags: BTreeMap<String, bool>,
    /// Caller-chosen nonce, signed but not interpreted by this layer.
    pub nonce: String,
    /// Identifier of the pinned key that must have produced the signature.
    pub key_id: String,
    /// Base64 Ed25519 signature over [`canonical_bytes`]; not itself signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl ModeDocument {
    /// Parse a document from JSON bytes with a size bound and schema checks.
    ///
    /// Unknown fields are ignored. A missing required field, a wrong type, a
    /// non-ASCII or oversized identifier, an unsupported version, or an
    /// inverted time window is a typed error.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ZeroError> {
        if bytes.len() > MAX_MODE_DOCUMENT_BYTES {
            return Err(limit(format!(
                "mode document is {} bytes, above the {MAX_MODE_DOCUMENT_BYTES} byte limit",
                bytes.len()
            )));
        }
        let document: ModeDocument = serde_json::from_slice(bytes).map_err(|error| {
            invalid(format!("mode document does not match the schema: {error}"))
        })?;
        document.validate()?;
        Ok(document)
    }

    /// Parse a document from a JSON string. See [`ModeDocument::from_json`].
    pub fn from_json_str(text: &str) -> Result<Self, ZeroError> {
        Self::from_json(text.as_bytes())
    }

    /// Check the schema version, identifier bounds, flag count, and time order.
    pub fn validate(&self) -> Result<(), ZeroError> {
        if self.version != MODE_DOCUMENT_VERSION {
            return Err(invalid(format!(
                "mode document version {} is unsupported; this build understands version {MODE_DOCUMENT_VERSION}",
                self.version
            )));
        }
        validate_field("project_id", &self.project_id)?;
        validate_field("nonce", &self.nonce)?;
        validate_field("key_id", &self.key_id)?;
        if self.flags.len() > MAX_MODE_FLAGS {
            return Err(invalid(format!(
                "mode document has {} flags, above the {MAX_MODE_FLAGS} flag limit",
                self.flags.len()
            )));
        }
        for key in self.flags.keys() {
            validate_field("flags key", key)?;
        }
        if self.expires_ms <= self.issued_ms {
            return Err(invalid(
                "mode document expires_ms must be greater than issued_ms",
            ));
        }
        Ok(())
    }
}

/// A deterministic, unambiguous encoding of a mode document.
///
/// `signature` is excluded: the signature is produced over the bytes below and
/// then carried beside them. The layout, measured in bytes, is:
///
/// ```text
/// "zero.halcyon.mode.v1\0"   CANONICAL_DOMAIN, 21 bytes
/// u16le                       version
/// u32le || bytes              project_id (UTF-8; ASCII enforced)
/// i64le                       issued_ms
/// i64le                       expires_ms
/// u32le                       flag count
///   u32le || bytes            flag key (ascending byte order)
///   u8                        1 for true, 0 for false
/// u32le || bytes              nonce
/// u32le || bytes              key_id
/// ```
///
/// Every variable-width field is length-prefixed by a `u32le` byte count, so no
/// two distinct documents share an encoding by shifting bytes across field
/// boundaries. Flag keys come from a `BTreeMap`, which iterates in ascending
/// order, so JSON object order never reaches the signature. The function
/// validates first and returns a typed error instead of encoding an
/// out-of-bounds document.
pub fn canonical_bytes(document: &ModeDocument) -> Result<Vec<u8>, ZeroError> {
    document.validate()?;
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(CANONICAL_DOMAIN);
    out.extend_from_slice(&document.version.to_le_bytes());
    push_field(&mut out, "project_id", &document.project_id)?;
    out.extend_from_slice(&document.issued_ms.to_le_bytes());
    out.extend_from_slice(&document.expires_ms.to_le_bytes());
    let flag_count = u32::try_from(document.flags.len())
        .map_err(|_| invalid("mode document has too many flags"))?;
    out.extend_from_slice(&flag_count.to_le_bytes());
    for (key, value) in &document.flags {
        push_field(&mut out, "flags key", key)?;
        out.push(u8::from(*value));
    }
    push_field(&mut out, "nonce", &document.nonce)?;
    push_field(&mut out, "key_id", &document.key_id)?;
    Ok(out)
}

fn push_field(out: &mut Vec<u8>, field: &str, value: &str) -> Result<(), ZeroError> {
    let length = u32::try_from(value.len())
        .map_err(|_| invalid(format!("mode document field `{field}` is too long")))?;
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn validate_field(field: &str, value: &str) -> Result<(), ZeroError> {
    if value.is_empty() {
        return Err(invalid(format!(
            "mode document field `{field}` must not be empty"
        )));
    }
    if value.len() > MAX_MODE_FIELD_BYTES {
        return Err(invalid(format!(
            "mode document field `{field}` is {} bytes, above the {MAX_MODE_FIELD_BYTES} byte limit",
            value.len()
        )));
    }
    // Visible ASCII without spaces: no non-ASCII, no control characters, and no
    // whitespace that could make two identifiers look identical in a log.
    if !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(invalid(format!(
            "mode document field `{field}` must be non-empty visible ASCII without spaces"
        )));
    }
    Ok(())
}

/// A key pinned in user configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedKey {
    /// Identifier the document must name exactly.
    pub key_id: String,
    /// Base64 (`STANDARD`, padded) Ed25519 public key, 32 bytes decoded.
    pub public_key_b64: String,
}

impl PinnedKey {
    /// Decode and validate this key as an Ed25519 public key.
    ///
    /// The error never contains the key bytes.
    pub fn verifying_key(&self) -> Result<VerifyingKey, ZeroError> {
        let bytes = B64.decode(&self.public_key_b64).map_err(|_| {
            invalid(format!(
                "pinned key `{}` is not valid standard base64",
                self.key_id
            ))
        })?;
        let bytes: [u8; PUBLIC_KEY_BYTES] = bytes.try_into().map_err(|_| {
            invalid(format!(
                "pinned key `{}` must decode to {PUBLIC_KEY_BYTES} bytes",
                self.key_id
            ))
        })?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| {
            invalid(format!(
                "pinned key `{}` is not a valid Ed25519 public key",
                self.key_id
            ))
        })
    }
}

/// The set of keys the user has pinned, loaded from user-scope configuration.
///
/// There is deliberately no project-scope constructor: a repository must not be
/// able to pin a key for itself. Callers pass the user config file path to
/// [`PinSet::load`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinSet {
    pub(crate) keys: Vec<PinnedKey>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) revoked: Vec<RevokedKey>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) rotations: Vec<RotationRecord>,
}

impl PinSet {
    /// Build a set, rejecting duplicates, bad key ids, and malformed keys.
    pub fn new(keys: Vec<PinnedKey>) -> Result<Self, ZeroError> {
        let set = Self {
            keys,
            revoked: Vec::new(),
            rotations: Vec::new(),
        };
        set.validate()?;
        Ok(set)
    }

    /// A set with no keys. Nothing verifies against it.
    pub fn empty() -> Self {
        Self {
            keys: Vec::new(),
            revoked: Vec::new(),
            rotations: Vec::new(),
        }
    }

    /// The pinned keys in configuration order.
    pub fn keys(&self) -> &[PinnedKey] {
        &self.keys
    }

    /// Parse a pin set from JSON bytes with a size bound and validation.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ZeroError> {
        if bytes.len() > MAX_PIN_FILE_BYTES {
            return Err(limit(format!(
                "pin set is {} bytes, above the {MAX_PIN_FILE_BYTES} byte limit",
                bytes.len()
            )));
        }
        let set: PinSet = serde_json::from_slice(bytes)
            .map_err(|error| invalid(format!("pin set does not match the schema: {error}")))?;
        set.validate()?;
        Ok(set)
    }

    /// Parse a pin set from a JSON string. See [`PinSet::from_json`].
    pub fn from_json_str(text: &str) -> Result<Self, ZeroError> {
        Self::from_json(text.as_bytes())
    }

    /// Load a pin set from the user config file, bounded in size.
    pub fn load(path: &Path) -> Result<Self, ZeroError> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| io_error("cannot inspect the pin set", path, error))?;
        if !metadata.is_file() {
            return Err(invalid(format!("{} is not a regular file", path.display())));
        }
        if metadata.len() > MAX_PIN_FILE_BYTES as u64 {
            return Err(limit(format!(
                "pin set is {} bytes, above the {MAX_PIN_FILE_BYTES} byte limit",
                metadata.len()
            )));
        }
        let file = fs::File::open(path)
            .map_err(|error| io_error("cannot open the pin set", path, error))?;
        let mut bytes = Vec::new();
        file.take(MAX_PIN_FILE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| io_error("cannot read the pin set", path, error))?;
        if bytes.len() > MAX_PIN_FILE_BYTES {
            return Err(limit(format!(
                "pin set grew past the {MAX_PIN_FILE_BYTES} byte limit while being read"
            )));
        }
        Self::from_json(&bytes)
    }

    /// Validate every pin and reject duplicate key ids.
    pub fn validate(&self) -> Result<(), ZeroError> {
        if self.keys.len() > MAX_PINS {
            return Err(invalid(format!(
                "pin set has {} keys, above the {MAX_PINS} key limit",
                self.keys.len()
            )));
        }
        let mut seen = std::collections::BTreeSet::new();
        for key in &self.keys {
            validate_field("pin key_id", &key.key_id)?;
            if !seen.insert(key.key_id.as_str()) {
                return Err(invalid(format!("duplicate pinned key id `{}`", key.key_id)));
            }
            key.verifying_key()?;
        }
        let mut seen_revoked = std::collections::BTreeSet::new();
        for revoked in &self.revoked {
            validate_field("revoked key_id", &revoked.key_id)?;
            if !seen_revoked.insert(revoked.key_id.as_str()) {
                return Err(invalid(format!(
                    "duplicate revoked key id `{}`",
                    revoked.key_id
                )));
            }
        }
        for rotation in &self.rotations {
            validate_field("rotation from_key_id", &rotation.from_key_id)?;
            validate_field("rotation to_key_id", &rotation.to_key_id)?;
        }
        Ok(())
    }

    /// The unique pin named `key_id`.
    ///
    /// A duplicate is refused here as well as in [`PinSet::validate`], so a set
    /// built directly through serde cannot make verification pick arbitrarily.
    fn unique_key(&self, key_id: &str) -> Result<&PinnedKey, ZeroError> {
        let mut matches = self.keys.iter().filter(|key| key.key_id == key_id);
        let first = matches.next().ok_or_else(|| {
            denied(format!(
                "no pinned key `{key_id}` can verify this mode file"
            ))
        })?;
        if matches.next().is_some() {
            return Err(denied(format!(
                "pin set contains more than one key named `{key_id}`; refusing to choose"
            )));
        }
        Ok(first)
    }
}

/// A document whose schema, signature, binding, and time window all passed.
///
/// Fields are private and there is no public constructor, so holding one is
/// proof that [`verify`] succeeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMode {
    version: u16,
    project_id: String,
    issued_ms: i64,
    expires_ms: i64,
    flags: BTreeMap<String, bool>,
    nonce: String,
    key_id: String,
    verified_at_ms: i64,
}

impl VerifiedMode {
    /// Schema version of the signed document.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Project the document is bound to.
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    /// Issued-at time in milliseconds since the Unix epoch.
    pub fn issued_ms(&self) -> i64 {
        self.issued_ms
    }

    /// Expiry time in milliseconds since the Unix epoch.
    pub fn expires_ms(&self) -> i64 {
        self.expires_ms
    }

    /// Every signed flag.
    pub fn flags(&self) -> &BTreeMap<String, bool> {
        &self.flags
    }

    /// One signed flag, if present.
    pub fn flag(&self, name: &str) -> Option<bool> {
        self.flags.get(name).copied()
    }

    /// The document's nonce, retained for downstream replay checks.
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// The pinned key id that verified the document.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The `now_ms` supplied to verification.
    pub fn verified_at_ms(&self) -> i64 {
        self.verified_at_ms
    }

    /// True once `expires_ms` is at or before `now_ms`, without skew.
    pub fn is_expired_at(&self, now_ms: i64) -> bool {
        self.expires_ms <= now_ms
    }
}

/// Verify one document against a pin set with the default clock skew.
///
/// Checks, in order: schema and bounds; an exact pinned `key_id`; the Ed25519
/// signature over [`canonical_bytes`] (strict, no fallback key); the project
/// binding (`document.project_id == expected_project_id`); issuance
/// (`issued_ms <= now_ms + skew`) and expiry (`expires_ms > now_ms - skew`).
pub fn verify(
    document: &ModeDocument,
    signature_b64: &str,
    pins: &PinSet,
    expected_project_id: &str,
    now_ms: i64,
) -> Result<VerifiedMode, ZeroError> {
    verify_with_skew(
        document,
        signature_b64,
        pins,
        expected_project_id,
        now_ms,
        DEFAULT_CLOCK_SKEW_MS,
    )
}

/// [`verify`] with an explicit clock skew in milliseconds.
///
/// `clock_skew_ms` must be between 0 and [`MAX_CLOCK_SKEW_MS`]; zero disables
/// skew in both directions.
pub fn verify_with_skew(
    document: &ModeDocument,
    signature_b64: &str,
    pins: &PinSet,
    expected_project_id: &str,
    now_ms: i64,
    clock_skew_ms: i64,
) -> Result<VerifiedMode, ZeroError> {
    if !(0..=MAX_CLOCK_SKEW_MS).contains(&clock_skew_ms) {
        return Err(invalid(format!(
            "clock skew must be between 0 and {MAX_CLOCK_SKEW_MS} ms"
        )));
    }

    // Schema, bounds, and canonical bytes. A document that cannot be encoded
    // unambiguously is never offered to the verifier.
    let canonical = canonical_bytes(document)?;

    // A revoked key id is refused even while its pin record still exists, so
    // revocation (not absence) is what the user sees.
    if pins.is_revoked(&document.key_id) {
        return Err(denied(format!(
            "pinned key `{}` is revoked; a revoked key cannot verify a mode file",
            document.key_id
        )));
    }

    // Exact pin lookup, before any signature work: no fallback key and no
    // prefix matching.
    let pin = pins.unique_key(&document.key_id)?;
    let signature = decode_signature(signature_b64)?;
    let verifying_key = pin.verifying_key()?;
    verifying_key
        .verify_strict(&canonical, &signature)
        .map_err(|_| {
            denied(format!(
                "the Ed25519 signature does not verify for pinned key `{}`",
                document.key_id
            ))
        })?;

    // Only signed fields are inspected below this point.
    if document.project_id != expected_project_id {
        return Err(denied(format!(
            "mode file is bound to project `{}`, not the current project `{}`; a copied repository needs its own signed file",
            document.project_id, expected_project_id
        )));
    }

    let now = i128::from(now_ms);
    let skew = i128::from(clock_skew_ms);
    if i128::from(document.issued_ms) > now + skew {
        return Err(denied(format!(
            "mode file is not valid yet: issued at {} ms, now {} ms, allowed skew {clock_skew_ms} ms",
            document.issued_ms, now_ms
        )));
    }
    if i128::from(document.expires_ms) <= now - skew {
        return Err(denied(format!(
            "mode file expired at {} ms, now {} ms, allowed skew {clock_skew_ms} ms",
            document.expires_ms, now_ms
        )));
    }

    Ok(VerifiedMode {
        version: document.version,
        project_id: document.project_id.clone(),
        issued_ms: document.issued_ms,
        expires_ms: document.expires_ms,
        flags: document.flags.clone(),
        nonce: document.nonce.clone(),
        key_id: document.key_id.clone(),
        verified_at_ms: now_ms,
    })
}

fn decode_signature(signature_b64: &str) -> Result<Signature, ZeroError> {
    if signature_b64.len() > MAX_SIGNATURE_B64_BYTES {
        return Err(invalid(format!(
            "signature is {} bytes of base64, above the {MAX_SIGNATURE_B64_BYTES} byte limit",
            signature_b64.len()
        )));
    }
    let bytes = B64
        .decode(signature_b64)
        .map_err(|_| invalid("signature is not valid standard base64"))?;
    let bytes: [u8; SIGNATURE_BYTES] = bytes
        .try_into()
        .map_err(|_| invalid(format!("signature must decode to {SIGNATURE_BYTES} bytes")))?;
    Ok(Signature::from_bytes(&bytes))
}

/// A [`Verifier`] pins a key set and a clock skew once.
#[derive(Debug, Clone)]
pub struct Verifier {
    pins: PinSet,
    clock_skew_ms: i64,
}

impl Verifier {
    /// Build a verifier with the default clock skew.
    pub fn new(pins: PinSet) -> Self {
        Self {
            pins,
            clock_skew_ms: DEFAULT_CLOCK_SKEW_MS,
        }
    }

    /// Replace the clock skew, rejecting negative or above-limit values.
    pub fn with_clock_skew_ms(mut self, clock_skew_ms: i64) -> Result<Self, ZeroError> {
        if !(0..=MAX_CLOCK_SKEW_MS).contains(&clock_skew_ms) {
            return Err(invalid(format!(
                "clock skew must be between 0 and {MAX_CLOCK_SKEW_MS} ms"
            )));
        }
        self.clock_skew_ms = clock_skew_ms;
        Ok(self)
    }

    /// The pinned keys this verifier uses.
    pub fn pins(&self) -> &PinSet {
        &self.pins
    }

    /// The configured clock skew in milliseconds.
    pub fn clock_skew_ms(&self) -> i64 {
        self.clock_skew_ms
    }

    /// Verify a document; the signature travels separately from the document.
    pub fn verify(
        &self,
        document: &ModeDocument,
        signature_b64: &str,
        expected_project_id: &str,
        now_ms: i64,
    ) -> Result<VerifiedMode, ZeroError> {
        verify_with_skew(
            document,
            signature_b64,
            &self.pins,
            expected_project_id,
            now_ms,
            self.clock_skew_ms,
        )
    }
}

/// Read, parse, and verify a discovered mode file.
///
/// This is the only read path that produces a [`VerifiedMode`]. The file is
/// read with [`ModeFile::read_bounded`], so links and oversized files are
/// refused, and the embedded `signature` field is required.
pub fn verify_mode_file(
    file: &ModeFile,
    verifier: &Verifier,
    expected_project_id: &str,
    now_ms: i64,
) -> Result<VerifiedMode, ZeroError> {
    let bytes = file.read_bounded(DEFAULT_MAX_MODE_FILE_BYTES)?;
    let document = ModeDocument::from_json(&bytes)?;
    let signature = document.signature.as_deref().ok_or_else(|| {
        invalid("mode document carries no `signature` field; it cannot enable the mode")
    })?;
    verifier.verify(&document, signature, expected_project_id, now_ms)
}

/// Apply the trust gate, then read, parse, and verify before enabling.
///
/// [`crate::discovery::activation`] is the structural, explicitly unverified
/// path. This function is the HAL-02/HAL-03/HAL-05 path:
///
/// 1. absent or conflicting discovery is `Disabled` without any read;
/// 2. an untrusted workspace is `Inert` before the file is opened (HAL-12);
/// 3. only then is the file read, parsed, and verified;
/// 4. `Enabled` means the signature, project binding, and time window all pass.
///
/// A trusted file that fails verification returns the typed error rather than
/// an `Enabled` or a silently disabled result. A copied repository has a new
/// project id, so its copied file fails the binding check even with a valid
/// signature.
pub fn activation_verified<G: TrustGate + ?Sized>(
    discovery: Discovery,
    gate: &G,
    verifier: &Verifier,
    expected_project_id: &str,
    now_ms: i64,
) -> Result<Activation, ZeroError> {
    let file = match discovery {
        Discovery::Absent => return Ok(Activation::Disabled { reason: None }),
        Discovery::Conflict { reason, .. } => {
            return Ok(Activation::Disabled {
                reason: Some(reason),
            });
        }
        Discovery::Found(file) => file,
    };
    if !gate.trusted(file.root()) {
        return Ok(Activation::Inert {
            reason: UNTRUSTED_REASON.to_string(),
        });
    }
    verify_mode_file(&file, verifier, expected_project_id, now_ms)?;
    Ok(Activation::Enabled(file))
}

fn io_error(context: &str, path: &Path, error: io::Error) -> ZeroError {
    let code = match error.kind() {
        io::ErrorKind::NotFound => ErrorCode::NotFound,
        io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        _ => ErrorCode::Io,
    };
    ZeroError::new(code, format!("{context} {}: {error}", path.display()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{discover, TrustedRoots, UntrustedWorkspace, MODE_FILE_NAME};
    use ed25519_dalek::{Signer, SigningKey};
    use std::fs;
    use std::path::{Path, PathBuf};

    const PROJECT: &str = "prj_0123456789abcdef";
    const KEY_ID: &str = "user-halcyon-key";
    const NOW: i64 = 1_700_000_000_000;

    fn signing_key() -> SigningKey {
        // Deterministic throwaway key: tests only. This crate has no keygen or
        // signing API for production use.
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn other_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn base_document() -> ModeDocument {
        let mut flags = BTreeMap::new();
        flags.insert("halcyon.mode".to_string(), true);
        flags.insert("halcyon.todo_sync".to_string(), false);
        ModeDocument {
            version: MODE_DOCUMENT_VERSION,
            project_id: PROJECT.to_string(),
            issued_ms: NOW - 60_000,
            expires_ms: NOW + 3_600_000,
            flags,
            nonce: "nonce-0001".to_string(),
            key_id: KEY_ID.to_string(),
            signature: None,
        }
    }

    fn signature(document: &ModeDocument, key: &SigningKey) -> String {
        let bytes = canonical_bytes(document).expect("canonical bytes");
        B64.encode(key.sign(&bytes).to_bytes())
    }

    fn pin(key_id: &str, key: &SigningKey) -> PinnedKey {
        PinnedKey {
            key_id: key_id.to_string(),
            public_key_b64: B64.encode(key.verifying_key().to_bytes()),
        }
    }

    fn pin_set(key_id: &str, key: &SigningKey) -> PinSet {
        PinSet::new(vec![pin(key_id, key)]).expect("pin set")
    }

    fn assert_denied(result: Result<VerifiedMode, ZeroError>, needle: &str) {
        let error = result.expect_err("verification should fail");
        assert_eq!(error.code(), ErrorCode::PolicyDenied, "{}", error.message());
        assert!(
            error.message().contains(needle),
            "expected `{needle}` in `{}`",
            error.message()
        );
        // No key material or signature bytes in a reason.
        assert!(
            !error.message().contains("MCowBQYDK2Vw"),
            "{}",
            error.message()
        );
    }

    fn write_mode(dir: &Path, document: &ModeDocument) -> PathBuf {
        let path = dir.join(MODE_FILE_NAME);
        fs::write(&path, serde_json::to_vec(document).expect("json")).expect("write mode file");
        path
    }

    #[test]
    fn a_valid_document_and_pinned_key_verify() {
        let key = signing_key();
        let mut document = base_document();
        let signed = signature(&document, &key);
        document.signature = Some(signed.clone());
        let pins = pin_set(KEY_ID, &key);

        let mode = verify(&document, &signed, &pins, PROJECT, NOW).expect("valid document");

        assert_eq!(mode.version(), MODE_DOCUMENT_VERSION);
        assert_eq!(mode.project_id(), PROJECT);
        assert_eq!(mode.issued_ms(), document.issued_ms);
        assert_eq!(mode.expires_ms(), document.expires_ms);
        assert_eq!(mode.flags(), &document.flags);
        assert_eq!(mode.flag("halcyon.mode"), Some(true));
        assert_eq!(mode.flag("halcyon.epb"), None);
        assert_eq!(mode.nonce(), "nonce-0001");
        assert_eq!(mode.key_id(), KEY_ID);
        assert_eq!(mode.verified_at_ms(), NOW);
        assert!(!mode.is_expired_at(NOW));
        assert!(mode.is_expired_at(document.expires_ms));
    }

    #[test]
    fn a_tampered_field_fails() {
        let key = signing_key();
        let document = base_document();
        let signed = signature(&document, &key);
        let pins = pin_set(KEY_ID, &key);

        let mut tampered = document.clone();
        tampered.flags.insert("halcyon.epb".to_string(), true);
        assert_denied(
            verify(&tampered, &signed, &pins, PROJECT, NOW),
            "does not verify",
        );

        let mut tampered = document.clone();
        tampered.project_id = "prj_other".to_string();
        assert_denied(
            verify(&tampered, &signed, &pins, PROJECT, NOW),
            "does not verify",
        );

        let mut tampered = document.clone();
        tampered.expires_ms += 1;
        assert_denied(
            verify(&tampered, &signed, &pins, PROJECT, NOW),
            "does not verify",
        );

        let mut tampered = document.clone();
        tampered.nonce = "nonce-0002".to_string();
        assert_denied(
            verify(&tampered, &signed, &pins, PROJECT, NOW),
            "does not verify",
        );
    }

    #[test]
    fn an_unknown_or_wrong_key_id_fails() {
        let key = signing_key();
        let other = other_signing_key();
        let mut document = base_document();
        let signed = signature(&document, &key);

        // Unknown key id: nothing pinned under that name.
        let pins = pin_set(KEY_ID, &key);
        document.key_id = "not-pinned".to_string();
        assert_denied(
            verify(&document, &signed, &pins, PROJECT, NOW),
            "no pinned key",
        );

        // Known key id pointing at a different pinned key: signature fails.
        let mut document = base_document();
        document.key_id = "second-key".to_string();
        let signed_by_key = signature(&document, &key);
        let two_pins =
            PinSet::new(vec![pin(KEY_ID, &other), pin("second-key", &other)]).expect("pin set");
        assert_denied(
            verify(&document, &signed_by_key, &two_pins, PROJECT, NOW),
            "does not verify",
        );
    }

    #[test]
    fn an_expired_document_is_denied() {
        let key = signing_key();
        let mut document = base_document();
        document.issued_ms = NOW - 10_000;
        document.expires_ms = NOW - 1;
        let signed = signature(&document, &key);
        let pins = pin_set(KEY_ID, &key);

        assert_denied(verify(&document, &signed, &pins, PROJECT, NOW), "expired");
    }

    #[test]
    fn a_future_issued_document_is_denied() {
        let key = signing_key();
        let mut document = base_document();
        document.issued_ms = NOW + 120_000;
        document.expires_ms = NOW + 240_000;
        let signed = signature(&document, &key);
        let pins = pin_set(KEY_ID, &key);

        assert_denied(
            verify(&document, &signed, &pins, PROJECT, NOW),
            "not valid yet",
        );
    }

    #[test]
    fn clock_skew_is_configurable_and_bounded() {
        let key = signing_key();
        let pins = pin_set(KEY_ID, &key);
        const SKEW: i64 = 60_000;

        // 30 s in the future is inside a 60 s configured skew.
        let mut document = base_document();
        document.issued_ms = NOW + 30_000;
        document.expires_ms = NOW + 3_600_000;
        let signed = signature(&document, &key);
        assert!(
            verify_with_skew(&document, &signed, &pins, PROJECT, NOW, SKEW).is_ok(),
            "issued inside the configured skew"
        );

        // The default (zero) skew is strict.
        assert_denied(
            verify(&document, &signed, &pins, PROJECT, NOW),
            "not valid yet",
        );

        // 30 s past expiry is inside the default skew; 61 s is not.
        let mut document = base_document();
        document.issued_ms = NOW - 10 * 60_000;
        document.expires_ms = NOW - 30_000;
        let signed = signature(&document, &key);
        assert!(
            verify_with_skew(&document, &signed, &pins, PROJECT, NOW, SKEW).is_ok(),
            "expired inside the configured skew"
        );

        document.expires_ms = NOW - SKEW - 1_000;
        let signed = signature(&document, &key);
        assert_denied(
            verify_with_skew(&document, &signed, &pins, PROJECT, NOW, SKEW),
            "expired",
        );

        assert_eq!(
            Verifier::new(pins.clone())
                .with_clock_skew_ms(-1)
                .expect_err("negative skew")
                .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            Verifier::new(pins)
                .with_clock_skew_ms(MAX_CLOCK_SKEW_MS + 1)
                .expect_err("oversized skew")
                .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn a_copied_repository_needs_its_own_signed_file() {
        let key = signing_key();
        let mut document = base_document();
        let signed = signature(&document, &key);
        document.signature = Some(signed.clone());
        let pins = pin_set(KEY_ID, &key);

        // The original project verifies.
        assert!(verify(&document, &signed, &pins, PROJECT, NOW).is_ok());

        // A copy has a new project id: the copied, still-valid signature is
        // bound to the old id and must not enable the copy (HAL-05).
        let copied_project = "prj_copied_00112233445566";
        assert_denied(
            verify(&document, &signed, &pins, copied_project, NOW),
            "copied repository",
        );
    }

    #[test]
    fn duplicate_pins_are_rejected() {
        let key = signing_key();
        let duplicate = pin(KEY_ID, &key);

        let error = PinSet::new(vec![duplicate.clone(), duplicate]).expect_err("duplicate pins");

        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(
            error.message().contains("duplicate pinned key"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn malformed_pins_are_rejected() {
        let key = signing_key();
        let good = pin(KEY_ID, &key);

        let mut bad_base64 = good.clone();
        bad_base64.public_key_b64 = "not base64!".to_string();
        assert_eq!(
            PinSet::new(vec![bad_base64])
                .expect_err("bad base64")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut short_key = good.clone();
        short_key.public_key_b64 = B64.encode([1u8; PUBLIC_KEY_BYTES - 1]);
        assert_eq!(
            PinSet::new(vec![short_key]).expect_err("short key").code(),
            ErrorCode::InvalidInput
        );

        let mut non_ascii = good.clone();
        non_ascii.key_id = "clé".to_string();
        assert_eq!(
            PinSet::new(vec![non_ascii])
                .expect_err("non-ASCII id")
                .code(),
            ErrorCode::InvalidInput
        );

        let json = serde_json::json!({ "keys": [good] });
        let set = PinSet::from_json(json.to_string().as_bytes()).expect("json pin set");
        assert_eq!(set.keys().len(), 1);
    }

    #[test]
    fn a_pin_set_loads_from_a_user_config_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("halcyon-keys.json");
        let key = signing_key();
        let pins = pin_set(KEY_ID, &key);
        fs::write(&path, serde_json::to_vec(&pins).expect("json")).expect("write pins");

        let loaded = PinSet::load(&path).expect("load pins");
        assert_eq!(loaded, pins);
        assert_eq!(loaded.keys()[0].key_id, KEY_ID);

        let missing = dir.path().join("missing.json");
        assert_eq!(
            PinSet::load(&missing).expect_err("missing").code(),
            ErrorCode::NotFound
        );

        fs::write(&path, vec![b' '; MAX_PIN_FILE_BYTES + 1]).expect("oversized pins");
        assert_eq!(
            PinSet::load(&path).expect_err("oversized").code(),
            ErrorCode::LimitExceeded
        );
    }

    #[test]
    fn malformed_signatures_are_rejected() {
        let key = signing_key();
        let document = base_document();
        let pins = pin_set(KEY_ID, &key);

        let error = verify(&document, "not base64!", &pins, PROJECT, NOW).expect_err("bad base64");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("base64"), "{}", error.message());

        let short = B64.encode([0u8; SIGNATURE_BYTES - 1]);
        let error = verify(&document, &short, &pins, PROJECT, NOW).expect_err("short signature");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("64 bytes"), "{}", error.message());

        let long = B64.encode([0u8; SIGNATURE_BYTES + 1]);
        assert_eq!(
            verify(&document, &long, &pins, PROJECT, NOW)
                .expect_err("long signature")
                .code(),
            ErrorCode::InvalidInput
        );

        // Structurally 64 bytes but not a signature for this key.
        let random = B64.encode([0u8; SIGNATURE_BYTES]);
        assert_denied(
            verify(&document, &random, &pins, PROJECT, NOW),
            "does not verify",
        );
    }

    #[test]
    fn malformed_documents_are_rejected() {
        let key = signing_key();
        let pins = pin_set(KEY_ID, &key);
        let document = base_document();
        let signed = signature(&document, &key);

        let error = verify(
            &document,
            "A".repeat(MAX_SIGNATURE_B64_BYTES + 1).as_str(),
            &pins,
            PROJECT,
            NOW,
        )
        .expect_err("oversized signature");
        assert_eq!(error.code(), ErrorCode::InvalidInput);

        let missing_key_id =
            r#"{"version":1,"project_id":"p","issued_ms":1,"expires_ms":2,"flags":{},"nonce":"n"}"#;
        let error = ModeDocument::from_json_str(missing_key_id).expect_err("missing key_id");
        assert_eq!(error.code(), ErrorCode::InvalidInput);

        let wrong_type = r#"{"version":1,"project_id":"p","issued_ms":1,"expires_ms":2,"flags":[],"nonce":"n","key_id":"k"}"#;
        assert_eq!(
            ModeDocument::from_json_str(wrong_type)
                .expect_err("flags must be a map")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut non_ascii = document.clone();
        non_ascii.project_id = "prøject".to_string();
        assert_eq!(
            non_ascii.validate().expect_err("non-ASCII id").code(),
            ErrorCode::InvalidInput
        );

        let mut inverted = document.clone();
        inverted.issued_ms = inverted.expires_ms;
        assert_eq!(
            inverted.validate().expect_err("inverted window").code(),
            ErrorCode::InvalidInput
        );

        let mut version = document.clone();
        version.version = MODE_DOCUMENT_VERSION + 1;
        assert_eq!(
            version.validate().expect_err("version").code(),
            ErrorCode::InvalidInput
        );

        let mut unknown_field = serde_json::to_value(&document).expect("json");
        unknown_field["extra"] = serde_json::json!("ignored");
        let parsed =
            ModeDocument::from_json(serde_json::to_string(&unknown_field).unwrap().as_bytes())
                .expect("unknown fields are ignored");
        assert!(verify(&parsed, &signed, &pins, PROJECT, NOW).is_ok());

        let oversized = vec![b' '; MAX_MODE_DOCUMENT_BYTES + 1];
        assert_eq!(
            ModeDocument::from_json(&oversized)
                .expect_err("oversized")
                .code(),
            ErrorCode::LimitExceeded
        );
    }

    #[test]
    fn canonical_bytes_match_the_documented_layout() {
        let mut flags = BTreeMap::new();
        flags.insert("flags.a".to_string(), true);
        flags.insert("flags.b".to_string(), false);
        let document = ModeDocument {
            version: 1,
            project_id: "p".to_string(),
            issued_ms: 1,
            expires_ms: 2,
            flags,
            nonce: "n".to_string(),
            key_id: "k".to_string(),
            signature: None,
        };

        let mut expected = Vec::new();
        expected.extend_from_slice(CANONICAL_DOMAIN);
        expected.extend_from_slice(&1u16.to_le_bytes());
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(b"p");
        expected.extend_from_slice(&1i64.to_le_bytes());
        expected.extend_from_slice(&2i64.to_le_bytes());
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.extend_from_slice(&7u32.to_le_bytes());
        expected.extend_from_slice(b"flags.a");
        expected.push(1);
        expected.extend_from_slice(&7u32.to_le_bytes());
        expected.extend_from_slice(b"flags.b");
        expected.push(0);
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(b"n");
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(b"k");

        assert_eq!(canonical_bytes(&document).expect("canonical"), expected);
    }

    #[test]
    fn canonical_bytes_ignore_flag_order_and_the_signature() {
        let first = base_document();

        let mut second = base_document();
        // Rebuild the map by inserting in the opposite order; BTreeMap sorts.
        let mut flags = BTreeMap::new();
        for (key, value) in first.flags.iter().rev() {
            flags.insert(key.clone(), *value);
        }
        second.flags = flags;
        second.signature = Some("a-signature-is-not-signed".to_string());

        assert_eq!(
            canonical_bytes(&first).expect("canonical"),
            canonical_bytes(&second).expect("canonical")
        );

        // Fields are length-prefixed: shifting bytes across a boundary changes
        // the encoding.
        let mut left = base_document();
        left.project_id = "ab".to_string();
        left.nonce = "c".to_string();
        let mut right = base_document();
        right.project_id = "a".to_string();
        right.nonce = "bc".to_string();
        assert_ne!(
            canonical_bytes(&left).expect("canonical"),
            canonical_bytes(&right).expect("canonical")
        );
    }

    #[test]
    fn an_untrusted_workspace_never_reads_the_mode_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("project");
        fs::create_dir_all(&root).expect("project");
        // Deliberately not JSON: parsing would fail if the file were read.
        fs::write(root.join(MODE_FILE_NAME), b"{ not a mode document").expect("write");
        let key = signing_key();
        let verifier = Verifier::new(pin_set(KEY_ID, &key));
        let discovery = discover(&root, Some(dir.path())).expect("discovery");

        let inert = activation_verified(discovery, &UntrustedWorkspace, &verifier, PROJECT, NOW)
            .expect("untrusted is inert, not an error");

        assert!(inert.is_inert());
        assert!(!inert.is_enabled());
    }

    #[test]
    fn activation_enables_only_after_signature_binding_and_expiry_pass() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("project");
        fs::create_dir_all(&root).expect("project");
        let key = signing_key();
        let verifier = Verifier::new(pin_set(KEY_ID, &key));
        let gate = TrustedRoots::new([root.clone()]);

        let mut document = base_document();
        let signed = signature(&document, &key);
        document.signature = Some(signed);
        write_mode(&root, &document);
        let discovery = discover(&root, Some(dir.path())).expect("discovery");

        let enabled =
            activation_verified(discovery.clone(), &gate, &verifier, PROJECT, NOW).expect("verify");
        assert!(enabled.is_enabled());
        assert_eq!(
            enabled.mode_file().expect("enabled").root(),
            root.canonicalize().expect("canonical root").as_path()
        );

        let mode = verify_mode_file(enabled.mode_file().unwrap(), &verifier, PROJECT, NOW)
            .expect("verified mode");
        assert_eq!(mode.flag("halcyon.todo_sync"), Some(false));

        // Tampered after signing: trusted but denied, never Enabled.
        let mut tampered = document.clone();
        tampered.flags.insert("halcyon.joker".to_string(), true);
        write_mode(&root, &tampered);
        let error = activation_verified(discovery.clone(), &gate, &verifier, PROJECT, NOW)
            .expect_err("tampered document");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);

        // Valid signature, wrong project: a copy is denied.
        write_mode(&root, &document);
        let error = activation_verified(discovery.clone(), &gate, &verifier, "prj_other", NOW)
            .expect_err("copied repository");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("copied repository"));

        // Expired: denied even though the signature and binding hold.
        let mut expired = document.clone();
        expired.issued_ms = NOW - 10_000;
        expired.expires_ms = NOW - 1;
        let signed = signature(&expired, &key);
        expired.signature = Some(signed);
        write_mode(&root, &expired);
        let error = activation_verified(discovery.clone(), &gate, &verifier, PROJECT, NOW)
            .expect_err("expired");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
    }

    #[test]
    fn absent_or_conflicting_discovery_stays_disabled_without_verification() {
        let key = signing_key();
        let verifier = Verifier::new(pin_set(KEY_ID, &key));
        let gate = UntrustedWorkspace;

        let absent =
            activation_verified(Discovery::Absent, &gate, &verifier, PROJECT, NOW).expect("absent");
        assert!(absent.is_disabled());
        assert_eq!(absent.reason(), None);

        let conflict = Discovery::Conflict {
            candidates: Vec::new(),
            reason: "same-distance candidates".to_string(),
        };
        let disabled =
            activation_verified(conflict, &gate, &verifier, PROJECT, NOW).expect("conflict");
        assert!(disabled.is_disabled());
        assert_eq!(disabled.reason(), Some("same-distance candidates"));
    }

    #[test]
    fn a_mode_file_without_a_signature_cannot_enable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("project");
        fs::create_dir_all(&root).expect("project");
        let key = signing_key();
        let verifier = Verifier::new(pin_set(KEY_ID, &key));

        let mut document = base_document();
        document.signature = None;
        write_mode(&root, &document);
        let discovery = discover(&root, Some(dir.path())).expect("discovery");
        let file = discovery.mode_file().expect("discovered mode file");
        let error = verify_mode_file(file, &verifier, PROJECT, NOW).expect_err("no signature");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("signature"), "{}", error.message());
    }

    #[test]
    fn an_empty_pin_set_verifies_nothing() {
        let key = signing_key();
        let document = base_document();
        let signed = signature(&document, &key);

        assert_denied(
            verify(&document, &signed, &PinSet::empty(), PROJECT, NOW),
            "no pinned key",
        );
    }

    #[test]
    fn a_pin_set_deserialised_with_duplicates_is_refused_at_use() {
        let key = signing_key();
        let document = base_document();
        let signed = signature(&document, &key);
        let duplicated = pin(KEY_ID, &key);
        let json = serde_json::json!({ "keys": [duplicated, duplicated] });
        let pins: PinSet = serde_json::from_value(json).expect("direct deserialise");

        // `new` and `from_json` reject this earlier, but verification refuses
        // to pick a key even when the set was built around them.
        assert_denied(
            verify(&document, &signed, &pins, PROJECT, NOW),
            "more than one key",
        );
    }
}
