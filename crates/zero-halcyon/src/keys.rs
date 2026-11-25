//! Halcyon key tooling (HAL-03, HAL-04).
//!
//! Keygen, signing, pinning, rotation, revocation, and verification all pass
//! through one actor gate: the agent may verify a document but may never mint,
//! use, pin, rotate, or revoke a key (`zero.pol.denied`). No API defaults to a
//! user actor; every call names one.
//!
//! Private key bytes never leave this module through `Debug`, `Display`, an
//! error, or the pin file. The pin file holds public keys, revocation records,
//! and rotation records only. When a caller wants the private key at rest,
//! [`KeyPair::seal`] wraps it with Argon2id plus AES-256-GCM and
//! [`SealedKey::unseal`] opens it; a wrong passphrase or a tampered envelope is
//! a typed [`ErrorCode::TamperDetected`] error.
//!
//! Verification is still [`crate::verify`]: [`PinSet::verify`] delegates to it,
//! and the verifier rejects a revoked key id even while its pin record is still
//! present. Rotation unpins the old key and pins the new one, so only the new
//! key verifies afterwards; the old pin is not kept unless policy pins it again.

use std::fs;
use std::io::{self, Read};
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, ZeroError};

use crate::verify::{
    self, canonical_bytes, ModeDocument, PinSet, PinnedKey, VerifiedMode, MAX_MODE_FIELD_BYTES,
    MAX_PIN_FILE_BYTES,
};

/// Schema version of the [`PinFile`] document.
pub const PIN_FILE_SCHEMA: u16 = 1;

/// Schema version of the [`SealedKey`] envelope.
pub const SEALED_KEY_VERSION: u16 = 1;

/// Upper bound on a sealed private-key file.
pub const MAX_SEALED_KEY_BYTES: usize = 16 * 1024;

/// Number of hex characters of the public-key hash used in a derived key id.
///
/// 32 hex characters carry 128 bits, which is a collision-resistant short id.
pub const KEY_ID_HEX_CHARS: usize = 32;

/// Upper bound on a passphrase handed to Argon2id.
pub const MAX_PASSPHRASE_BYTES: usize = 1024;

const SEAL_KDF: &str = "argon2id";
const SEAL_SALT_BYTES: usize = 16;
const SEAL_NONCE_BYTES: usize = 12;
const SEAL_TAG_BYTES: usize = 16;
const SEAL_SECRET_BYTES: usize = 32;
const SEAL_AAD: &[u8] = b"zero.halcyon.sealed-key.v1\0";

/// Who is asking for a key operation.
///
/// There is no `Default`: a caller must state the actor, so nothing can
/// silently behave as the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Actor {
    /// The human user, the only actor allowed to mutate or sign.
    User,
    /// The agent. Verification only.
    Agent,
}

/// A key operation gated by [`authorize`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyAction {
    /// Mint a key pair.
    Keygen,
    /// Sign a mode document or unseal a private key.
    Sign,
    /// Pin a public key.
    Pin,
    /// Replace a pinned key, recording the rotation.
    Rotate,
    /// Mark a key id revoked.
    Revoke,
    /// Verify a signed document. Allowed to both actors.
    Verify,
}

impl KeyAction {
    /// Stable lower-case name used in denial messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            KeyAction::Keygen => "keygen",
            KeyAction::Sign => "sign",
            KeyAction::Pin => "pin",
            KeyAction::Rotate => "rotate",
            KeyAction::Revoke => "revoke",
            KeyAction::Verify => "verify",
        }
    }

    /// True for every action the agent may not perform.
    pub const fn user_only(self) -> bool {
        !matches!(self, KeyAction::Verify)
    }
}

/// The actor gate.
///
/// Keygen, sign, pin, rotate, and revoke are user-only and return
/// `zero.pol.denied` for an agent. Verify is allowed to both. Every public
/// mutating or signing API calls this first.
pub fn authorize(action: KeyAction, actor: Actor) -> Result<(), ZeroError> {
    match (action, actor) {
        (KeyAction::Verify, _) => Ok(()),
        (_, Actor::User) => Ok(()),
        (action, Actor::Agent) => Err(denied(format!(
            "the agent may not {} Halcyon keys; only the user can",
            action.as_str()
        ))),
    }
}

/// An Ed25519 key pair.
///
/// The private scalar is never printed, formatted, or serialised. The derived
/// key id is the first [`KEY_ID_HEX_CHARS`] hex characters of the blake3 hash of
/// the public key, prefixed with `halcyon-`, or a caller-supplied label.
pub struct KeyPair {
    signing: SigningKey,
    key_id: String,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl KeyPair {
    /// Mint a key pair. User-only.
    pub fn keygen(actor: Actor) -> Result<Self, ZeroError> {
        keygen(actor)
    }

    /// Mint a key pair whose key id is `label` instead of the derived hash.
    ///
    /// The label follows the mode-document identifier rule: visible ASCII
    /// without spaces, at most [`MAX_MODE_FIELD_BYTES`] bytes. User-only.
    pub fn with_label(actor: Actor, label: &str) -> Result<Self, ZeroError> {
        validate_key_id(label)?;
        let mut pair = keygen(actor)?;
        pair.key_id = label.to_string();
        Ok(pair)
    }

    /// Rebuild a pair from stored signing material. Private: only sealing and
    /// tests construct a pair from bytes.
    fn from_signing_key(signing: SigningKey, key_id: String) -> Self {
        Self { signing, key_id }
    }

    /// The identifier a mode document must name and a pin set must hold.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Base64 (`STANDARD`, padded) Ed25519 public key.
    pub fn public_key_b64(&self) -> String {
        B64.encode(self.signing.verifying_key().to_bytes())
    }

    /// The public half, ready to pin.
    pub fn pinned_key(&self) -> PinnedKey {
        PinnedKey {
            key_id: self.key_id.clone(),
            public_key_b64: self.public_key_b64(),
        }
    }

    /// Sign a mode document. User-only.
    pub fn sign_mode(
        &self,
        actor: Actor,
        document: &ModeDocument,
    ) -> Result<SignedMode, ZeroError> {
        sign_mode(actor, self, document)
    }

    /// Encrypt the private key at rest with an Argon2id-derived key and
    /// AES-256-GCM. User-only.
    pub fn seal(&self, actor: Actor, passphrase: &str) -> Result<SealedKey, ZeroError> {
        authorize(KeyAction::Sign, actor)?;
        validate_passphrase(passphrase)?;

        let salt = random_bytes::<SEAL_SALT_BYTES>()?;
        let nonce = random_bytes::<SEAL_NONCE_BYTES>()?;
        let key = derive_seal_key(passphrase, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| internal("the AES-256-GCM key is the wrong length"))?;

        let aad = seal_aad(&self.key_id);
        let mut secret = self.signing.to_bytes();
        let ciphertext = cipher.encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &secret,
                aad: &aad,
            },
        );
        secret.fill(0);
        let ciphertext =
            ciphertext.map_err(|_| internal("sealed key encryption failed"))?;

        Ok(SealedKey {
            version: SEALED_KEY_VERSION,
            kdf: SEAL_KDF.to_string(),
            key_id: self.key_id.clone(),
            salt_b64: B64.encode(salt),
            nonce_b64: B64.encode(nonce),
            ciphertext_b64: B64.encode(ciphertext),
        })
    }

    /// Open a sealed key. User-only.
    pub fn unseal(
        actor: Actor,
        passphrase: &str,
        sealed: &SealedKey,
    ) -> Result<Self, ZeroError> {
        sealed.unseal(actor, passphrase)
    }
}

/// Mint a key pair. See [`KeyPair::keygen`].
pub fn keygen(actor: Actor) -> Result<KeyPair, ZeroError> {
    authorize(KeyAction::Keygen, actor)?;
    let mut secret = [0u8; SEAL_SECRET_BYTES];
    getrandom::getrandom(&mut secret)
        .map_err(|error| internal(format!("cannot read random bytes: {error}")))?;
    let signing = SigningKey::from_bytes(&secret);
    secret.fill(0);
    let key_id = derived_key_id(&signing.verifying_key());
    Ok(KeyPair::from_signing_key(signing, key_id))
}

/// Sign one mode document with one key. User-only.
///
/// The returned document names the signing key: a caller-supplied `key_id` is
/// replaced, so a signature can never claim a key that did not produce it. The
/// signature covers [`canonical_bytes`], which excludes the signature itself;
/// the base64 signature is also stored on the returned document so writing it
/// to `.halcyon-mode` is one serialisation.
pub fn sign_mode(
    actor: Actor,
    keypair: &KeyPair,
    document: &ModeDocument,
) -> Result<SignedMode, ZeroError> {
    authorize(KeyAction::Sign, actor)?;
    let mut document = document.clone();
    document.key_id = keypair.key_id.clone();
    document.signature = None;
    let bytes = canonical_bytes(&document)?;
    let signature = keypair.signing.sign(&bytes);
    let signature_b64 = B64.encode(signature.to_bytes());
    document.signature = Some(signature_b64.clone());
    Ok(SignedMode {
        document,
        signature_b64,
    })
}

fn derived_key_id(public: &VerifyingKey) -> String {
    let hash = blake3::hash(&public.to_bytes()).to_hex();
    format!("halcyon-{}", &hash[..KEY_ID_HEX_CHARS])
}

/// A signed mode document and its detached base64 signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedMode {
    /// The document, with `key_id` set to the signing key and `signature`
    /// embedded for file output.
    pub document: ModeDocument,
    /// Standard padded base64 of the 64-byte Ed25519 signature.
    pub signature_b64: String,
}

impl SignedMode {
    /// Verify against a pin set with the default clock skew. Actor-gated but
    /// allowed to both users and agents.
    pub fn verify(
        &self,
        pins: &PinSet,
        expected_project_id: &str,
        now_ms: i64,
    ) -> Result<VerifiedMode, ZeroError> {
        self.verify_with_skew(
            pins,
            expected_project_id,
            now_ms,
            verify::DEFAULT_CLOCK_SKEW_MS,
        )
    }

    /// [`SignedMode::verify`] with an explicit clock skew.
    pub fn verify_with_skew(
        &self,
        pins: &PinSet,
        expected_project_id: &str,
        now_ms: i64,
        clock_skew_ms: i64,
    ) -> Result<VerifiedMode, ZeroError> {
        verify::verify_with_skew(
            &self.document,
            &self.signature_b64,
            pins,
            expected_project_id,
            now_ms,
            clock_skew_ms,
        )
    }

    /// Serialise the document (with the embedded signature) as JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, ZeroError> {
        Ok(serde_json::to_vec(&self.document)?)
    }
}

/// One revoked key id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedKey {
    /// The revoked key id.
    pub key_id: String,
    /// When the user revoked it, in milliseconds since the Unix epoch.
    pub at_ms: i64,
    /// Optional reason retained for audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One recorded rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationRecord {
    /// The key that was unpinned.
    pub from_key_id: String,
    /// The key that replaced it.
    pub to_key_id: String,
}

impl PinSet {
    /// Pin a public key. User-only.
    ///
    /// A revoked key id cannot be pinned again until [`PinSet::unrevoke`] runs
    /// explicitly; revocation is never silently cleared.
    pub fn pin(&mut self, actor: Actor, key: PinnedKey) -> Result<(), ZeroError> {
        authorize(KeyAction::Pin, actor)?;
        if self.is_revoked(&key.key_id) {
            return Err(denied(format!(
                "key `{}` is revoked; un-revoke it explicitly before pinning it again",
                key.key_id
            )));
        }
        if self.keys.iter().any(|pinned| pinned.key_id == key.key_id) {
            return Err(already_exists(format!(
                "key `{}` is already pinned",
                key.key_id
            )));
        }
        let mut next = self.clone();
        next.keys.push(key);
        next.validate()?;
        *self = next;
        Ok(())
    }

    /// Remove a pinned key. User-only.
    pub fn unpin(&mut self, actor: Actor, key_id: &str) -> Result<(), ZeroError> {
        authorize(KeyAction::Pin, actor)?;
        let position = self
            .keys
            .iter()
            .position(|pinned| pinned.key_id == key_id)
            .ok_or_else(|| not_found(format!("no pinned key `{key_id}`")))?;
        let mut next = self.clone();
        next.keys.remove(position);
        next.validate()?;
        *self = next;
        Ok(())
    }

    /// Atomically pin `new_keypair`, unpin `old_key_id`, and record the
    /// rotation. User-only.
    ///
    /// The replacement is applied only after every check passes; a rejected
    /// rotation leaves the set untouched. The old pin is removed, so the old
    /// key no longer verifies unless it is pinned again.
    pub fn rotate(
        &mut self,
        actor: Actor,
        old_key_id: &str,
        new_keypair: &KeyPair,
    ) -> Result<(), ZeroError> {
        authorize(KeyAction::Rotate, actor)?;
        let position = self
            .keys
            .iter()
            .position(|pinned| pinned.key_id == old_key_id)
            .ok_or_else(|| not_found(format!("no pinned key `{old_key_id}` to rotate")))?;
        let new_key_id = new_keypair.key_id();
        if new_key_id == old_key_id {
            return Err(invalid(
                "a rotation must name a different key than the one it replaces",
            ));
        }
        if self.is_revoked(new_key_id) {
            return Err(denied(format!(
                "key `{new_key_id}` is revoked; it cannot become the rotated-in key"
            )));
        }
        if self.keys.iter().any(|pinned| pinned.key_id == new_key_id) {
            return Err(already_exists(format!(
                "key `{new_key_id}` is already pinned"
            )));
        }

        let mut next = self.clone();
        next.keys[position] = new_keypair.pinned_key();
        next.rotations.push(RotationRecord {
            from_key_id: old_key_id.to_string(),
            to_key_id: new_key_id.to_string(),
        });
        next.validate()?;
        *self = next;
        Ok(())
    }

    /// Revoke a key id. User-only.
    ///
    /// The pin record, if any, is kept so verification refuses the key by
    /// revocation rather than by absence. Revoking an already revoked id is
    /// idempotent. Revocation is permanent for the id until an explicit
    /// [`PinSet::unrevoke`].
    pub fn revoke(&mut self, actor: Actor, key_id: &str, now_ms: i64) -> Result<(), ZeroError> {
        authorize(KeyAction::Revoke, actor)?;
        validate_key_id(key_id)?;
        if self.is_revoked(key_id) {
            return Ok(());
        }
        let mut next = self.clone();
        next.revoked.push(RevokedKey {
            key_id: key_id.to_string(),
            at_ms: now_ms,
            reason: None,
        });
        next.validate()?;
        *self = next;
        Ok(())
    }

    /// Remove a revocation so the key id can be pinned and verified again.
    /// User-only and explicit; nothing clears a revocation implicitly.
    pub fn unrevoke(&mut self, actor: Actor, key_id: &str) -> Result<(), ZeroError> {
        authorize(KeyAction::Revoke, actor)?;
        let position = self
            .revoked
            .iter()
            .position(|revoked| revoked.key_id == key_id)
            .ok_or_else(|| not_found(format!("key `{key_id}` is not revoked")))?;
        let mut next = self.clone();
        next.revoked.remove(position);
        next.validate()?;
        *self = next;
        Ok(())
    }

    /// The revocation records in order.
    pub fn revoked(&self) -> &[RevokedKey] {
        &self.revoked
    }

    /// True when `key_id` has a revocation record.
    pub fn is_revoked(&self, key_id: &str) -> bool {
        self.revoked
            .iter()
            .any(|revoked| revoked.key_id == key_id)
    }

    /// The rotation records in order.
    pub fn rotations(&self) -> &[RotationRecord] {
        &self.rotations
    }

    /// Verify a document against this set. Verify is allowed to both actors.
    pub fn verify(
        &self,
        actor: Actor,
        document: &ModeDocument,
        signature_b64: &str,
        expected_project_id: &str,
        now_ms: i64,
    ) -> Result<VerifiedMode, ZeroError> {
        authorize(KeyAction::Verify, actor)?;
        verify::verify(
            document,
            signature_b64,
            self,
            expected_project_id,
            now_ms,
        )
    }

    /// [`PinSet::verify`] with an explicit clock skew.
    pub fn verify_with_skew(
        &self,
        actor: Actor,
        document: &ModeDocument,
        signature_b64: &str,
        expected_project_id: &str,
        now_ms: i64,
        clock_skew_ms: i64,
    ) -> Result<VerifiedMode, ZeroError> {
        authorize(KeyAction::Verify, actor)?;
        verify::verify_with_skew(
            document,
            signature_b64,
            self,
            expected_project_id,
            now_ms,
            clock_skew_ms,
        )
    }

    /// Load a [`PinFile`] from disk and return its validated set.
    pub fn load_file(path: &Path) -> Result<Self, ZeroError> {
        PinFile::load(path)?.into_pin_set()
    }

    /// Write this set atomically as a [`PinFile`].
    pub fn save_atomic(&self, path: &Path) -> Result<(), ZeroError> {
        PinFile::from_pin_set(self).save_atomic(path)
    }
}

/// The user-scope pin document: pins, revocations, rotations.
///
/// This file never contains private key bytes. It is independent of any project
/// so a repository cannot pin a key for itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinFile {
    /// Schema version; must be [`PIN_FILE_SCHEMA`].
    pub schema: u16,
    /// Pinned public keys.
    #[serde(default)]
    pub pins: Vec<PinnedKey>,
    /// Revoked key ids.
    #[serde(default)]
    pub revoked: Vec<RevokedKey>,
    /// Recorded rotations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rotations: Vec<RotationRecord>,
}

impl PinFile {
    /// Build a document from an in-memory set.
    pub fn from_pin_set(set: &PinSet) -> Self {
        Self {
            schema: PIN_FILE_SCHEMA,
            pins: set.keys.clone(),
            revoked: set.revoked.clone(),
            rotations: set.rotations.clone(),
        }
    }

    /// Validate the schema and turn the document into a [`PinSet`].
    pub fn into_pin_set(self) -> Result<PinSet, ZeroError> {
        if self.schema != PIN_FILE_SCHEMA {
            return Err(ZeroError::new(
                ErrorCode::SchemaVersion,
                format!(
                    "pin file schema {} is unsupported; this build understands schema {PIN_FILE_SCHEMA}",
                    self.schema
                ),
            ));
        }
        let set = PinSet {
            keys: self.pins,
            revoked: self.revoked,
            rotations: self.rotations,
        };
        set.validate()?;
        Ok(set)
    }

    /// Parse a pin file from JSON bytes with a size bound and validation.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ZeroError> {
        if bytes.len() > MAX_PIN_FILE_BYTES {
            return Err(limit(format!(
                "pin file is {} bytes, above the {MAX_PIN_FILE_BYTES} byte limit",
                bytes.len()
            )));
        }
        let file: PinFile = serde_json::from_slice(bytes)
            .map_err(|error| invalid(format!("pin file does not match the schema: {error}")))?;
        file.clone().into_pin_set()?;
        Ok(file)
    }

    /// Load and validate a pin file from disk.
    pub fn load(path: &Path) -> Result<Self, ZeroError> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| io_error("cannot inspect the pin file", path, error))?;
        if !metadata.is_file() {
            return Err(invalid(format!("{} is not a regular file", path.display())));
        }
        if metadata.len() > MAX_PIN_FILE_BYTES as u64 {
            return Err(limit(format!(
                "pin file is {} bytes, above the {MAX_PIN_FILE_BYTES} byte limit",
                metadata.len()
            )));
        }
        let file =
            fs::File::open(path).map_err(|error| io_error("cannot open the pin file", path, error))?;
        let mut bytes = Vec::new();
        file.take(MAX_PIN_FILE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| io_error("cannot read the pin file", path, error))?;
        if bytes.len() > MAX_PIN_FILE_BYTES {
            return Err(limit(format!(
                "pin file grew past the {MAX_PIN_FILE_BYTES} byte limit while being read"
            )));
        }
        Self::from_json(&bytes)
    }

    /// Validate and write the file through a temporary and a rename.
    pub fn save_atomic(&self, path: &Path) -> Result<(), ZeroError> {
        self.clone().into_pin_set()?;
        let bytes = serde_json::to_vec_pretty(self)?;
        if bytes.len() > MAX_PIN_FILE_BYTES {
            return Err(limit(format!(
                "pin file is {} bytes, above the {MAX_PIN_FILE_BYTES} byte limit",
                bytes.len()
            )));
        }
        write_atomic(path, &bytes)
    }
}

/// A private key sealed with Argon2id and AES-256-GCM.
///
/// The envelope carries a random 16-byte salt, a random 12-byte nonce, and the
/// ciphertext. The key id is bound into the AEAD associated data, so editing it
/// also fails decryption.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedKey {
    version: u16,
    kdf: String,
    key_id: String,
    salt_b64: String,
    nonce_b64: String,
    ciphertext_b64: String,
}

impl std::fmt::Debug for SealedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedKey")
            .field("version", &self.version)
            .field("kdf", &self.kdf)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl SealedKey {
    /// The key id the envelope was sealed for.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The derivation function named by the envelope.
    pub fn kdf(&self) -> &str {
        &self.kdf
    }

    /// Check the envelope shape without touching the passphrase.
    pub fn validate(&self) -> Result<(), ZeroError> {
        if self.version != SEALED_KEY_VERSION {
            return Err(invalid(format!(
                "sealed key version {} is unsupported; this build understands version {SEALED_KEY_VERSION}",
                self.version
            )));
        }
        if self.kdf != SEAL_KDF {
            return Err(invalid(format!(
                "sealed key uses unsupported kdf `{}`",
                self.kdf
            )));
        }
        validate_key_id(&self.key_id)?;
        let salt = decode_field(&self.salt_b64, "salt")?;
        if salt.len() != SEAL_SALT_BYTES {
            return Err(invalid(format!(
                "sealed key salt must be {SEAL_SALT_BYTES} bytes"
            )));
        }
        let nonce = decode_field(&self.nonce_b64, "nonce")?;
        if nonce.len() != SEAL_NONCE_BYTES {
            return Err(invalid(format!(
                "sealed key nonce must be {SEAL_NONCE_BYTES} bytes"
            )));
        }
        let ciphertext = decode_field(&self.ciphertext_b64, "ciphertext")?;
        if ciphertext.len() != SEAL_SECRET_BYTES + SEAL_TAG_BYTES {
            return Err(invalid(format!(
                "sealed key ciphertext must be {} bytes",
                SEAL_SECRET_BYTES + SEAL_TAG_BYTES
            )));
        }
        Ok(())
    }

    /// Open the envelope. User-only.
    ///
    /// A wrong passphrase, a tampered ciphertext, a tampered key id, or
    /// malformed base64 fails as [`ErrorCode::TamperDetected`]; the message
    /// never contains key material.
    pub fn unseal(&self, actor: Actor, passphrase: &str) -> Result<KeyPair, ZeroError> {
        authorize(KeyAction::Sign, actor)?;
        validate_passphrase(passphrase)?;
        self.validate()?;

        let salt = decode_field(&self.salt_b64, "salt")?;
        let nonce = decode_field(&self.nonce_b64, "nonce")?;
        let ciphertext = decode_field(&self.ciphertext_b64, "ciphertext")?;
        let key = derive_seal_key(passphrase, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| internal("the AES-256-GCM key is the wrong length"))?;
        let aad = seal_aad(&self.key_id);
        let mut plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| tamper("wrong passphrase or the sealed key file was tampered with"))?;
        if plaintext.len() != SEAL_SECRET_BYTES {
            plaintext.fill(0);
            return Err(tamper("the sealed key plaintext has the wrong length"));
        }
        let mut secret = [0u8; SEAL_SECRET_BYTES];
        secret.copy_from_slice(&plaintext);
        plaintext.fill(0);
        let signing = SigningKey::from_bytes(&secret);
        secret.fill(0);
        Ok(KeyPair::from_signing_key(signing, self.key_id.clone()))
    }

    /// Parse an envelope from JSON bytes with a size bound and shape check.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ZeroError> {
        if bytes.len() > MAX_SEALED_KEY_BYTES {
            return Err(limit(format!(
                "sealed key is {} bytes, above the {MAX_SEALED_KEY_BYTES} byte limit",
                bytes.len()
            )));
        }
        let sealed: SealedKey = serde_json::from_slice(bytes)
            .map_err(|error| invalid(format!("sealed key does not match the schema: {error}")))?;
        sealed.validate()?;
        Ok(sealed)
    }

    /// Load a sealed key from disk.
    pub fn load(path: &Path) -> Result<Self, ZeroError> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| io_error("cannot inspect the sealed key", path, error))?;
        if !metadata.is_file() {
            return Err(invalid(format!("{} is not a regular file", path.display())));
        }
        if metadata.len() > MAX_SEALED_KEY_BYTES as u64 {
            return Err(limit(format!(
                "sealed key is {} bytes, above the {MAX_SEALED_KEY_BYTES} byte limit",
                metadata.len()
            )));
        }
        let file = fs::File::open(path)
            .map_err(|error| io_error("cannot open the sealed key", path, error))?;
        let mut bytes = Vec::new();
        file.take(MAX_SEALED_KEY_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| io_error("cannot read the sealed key", path, error))?;
        if bytes.len() > MAX_SEALED_KEY_BYTES {
            return Err(limit(format!(
                "sealed key grew past the {MAX_SEALED_KEY_BYTES} byte limit while being read"
            )));
        }
        Self::from_json(&bytes)
    }

    /// Validate and write the envelope through a temporary and a rename.
    pub fn save_atomic(&self, path: &Path) -> Result<(), ZeroError> {
        self.validate()?;
        let bytes = serde_json::to_vec_pretty(self)?;
        if bytes.len() > MAX_SEALED_KEY_BYTES {
            return Err(limit(format!(
                "sealed key is {} bytes, above the {MAX_SEALED_KEY_BYTES} byte limit",
                bytes.len()
            )));
        }
        write_atomic(path, &bytes)
    }
}

fn validate_key_id(value: &str) -> Result<(), ZeroError> {
    if value.is_empty() {
        return Err(invalid("key id must not be empty"));
    }
    if value.len() > MAX_MODE_FIELD_BYTES {
        return Err(invalid(format!(
            "key id is {} bytes, above the {MAX_MODE_FIELD_BYTES} byte limit",
            value.len()
        )));
    }
    if !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(invalid(
            "key id must be visible ASCII without spaces or control characters",
        ));
    }
    Ok(())
}

fn validate_passphrase(passphrase: &str) -> Result<(), ZeroError> {
    if passphrase.is_empty() {
        return Err(invalid("a passphrase must not be empty"));
    }
    if passphrase.len() > MAX_PASSPHRASE_BYTES {
        return Err(limit(format!(
            "passphrase is {} bytes, above the {MAX_PASSPHRASE_BYTES} byte limit",
            passphrase.len()
        )));
    }
    Ok(())
}

fn derive_seal_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], ZeroError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|error| internal(format!("argon2id key derivation failed: {error}")))?;
    Ok(key)
}

fn seal_aad(key_id: &str) -> Vec<u8> {
    let mut aad = SEAL_AAD.to_vec();
    aad.extend_from_slice(key_id.as_bytes());
    aad
}

fn decode_field(value: &str, field: &str) -> Result<Vec<u8>, ZeroError> {
    B64.decode(value).map_err(|_| {
        tamper(format!(
            "sealed key `{field}` is not valid standard base64"
        ))
    })
}

fn random_bytes<const N: usize>() -> Result<[u8; N], ZeroError> {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| internal(format!("cannot read random bytes: {error}")))?;
    Ok(bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ZeroError> {
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut file = fs::File::create(&tmp)
            .map_err(|error| io_error("cannot create the temporary file for", path, error))?;
        file.write_all(bytes)
            .map_err(|error| io_error("cannot write the temporary file for", path, error))?;
        file.sync_all()
            .map_err(|error| io_error("cannot sync the temporary file for", path, error))?;
    }
    fs::rename(&tmp, path).map_err(|error| io_error("cannot replace", path, error))
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

fn already_exists(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::AlreadyExists, message)
}

fn not_found(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::NotFound, message)
}

fn tamper(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::TamperDetected, message)
}

fn internal(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Internal, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::{MODE_DOCUMENT_VERSION, PUBLIC_KEY_BYTES};
    use std::collections::BTreeMap;
    use std::path::Path;

    const PROJECT: &str = "prj_0123456789abcdef";
    const NOW: i64 = 1_700_000_000_000;

    fn document() -> ModeDocument {
        let mut flags = BTreeMap::new();
        flags.insert("halcyon.mode".to_string(), true);
        ModeDocument {
            version: MODE_DOCUMENT_VERSION,
            project_id: PROJECT.to_string(),
            issued_ms: NOW - 60_000,
            expires_ms: NOW + 3_600_000,
            flags,
            nonce: "nonce-0001".to_string(),
            key_id: "caller-placeholder".to_string(),
            signature: None,
        }
    }

    fn pair(seed: u8, key_id: &str) -> KeyPair {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        KeyPair::from_signing_key(signing, key_id.to_string())
    }

    fn assert_code(result: Result<(), ZeroError>, code: ErrorCode) {
        let error = result.expect_err("the operation should fail");
        assert_eq!(error.code(), code, "{}", error.message());
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn scan_files(dir: &Path, needle_hex: &str, needle_b64: &str, secret: &[u8]) {
        for entry in fs::read_dir(dir).expect("read dir") {
            let path = entry.expect("entry").path();
            if !path.is_file() {
                continue;
            }
            let bytes = fs::read(&path).expect("read file");
            let text = String::from_utf8_lossy(&bytes);
            assert!(
                !text.contains(needle_hex),
                "private key hex leaked into {}",
                path.display()
            );
            assert!(
                !text.contains(needle_b64),
                "private key base64 leaked into {}",
                path.display()
            );
            assert!(
                !bytes.windows(secret.len()).any(|window| window == secret),
                "raw private key bytes leaked into {}",
                path.display()
            );
        }
    }

    #[test]
    fn keygen_sign_and_verify_round_trip() {
        let user = Actor::User;
        let keypair = keygen(user).expect("keygen");

        let mut pins = PinSet::empty();
        pins.pin(user, keypair.pinned_key()).expect("pin");

        let signed = sign_mode(user, &keypair, &document()).expect("sign");
        assert_eq!(signed.document.key_id, keypair.key_id());
        assert_eq!(signed.document.signature.as_deref(), Some(signed.signature_b64.as_str()));

        let verified = signed.verify(&pins, PROJECT, NOW).expect("verify");
        assert_eq!(verified.key_id(), keypair.key_id());
        assert_eq!(verified.flag("halcyon.mode"), Some(true));

        // The document written to a file verifies through the same path.
        let parsed = ModeDocument::from_json(&signed.to_json_bytes().expect("json")).expect("parse");
        let embedded = parsed.signature.as_deref().expect("embedded signature");
        let verified =
            verify::verify(&parsed, embedded, &pins, PROJECT, NOW).expect("file document");
        assert_eq!(verified.key_id(), keypair.key_id());

        // A non-canonical signature over the same fields is refused.
        let mut tampered = signed.clone();
        tampered.document.flags.insert("halcyon.epb".to_string(), true);
        let error = tampered.verify(&pins, PROJECT, NOW).expect_err("tampered");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
    }

    #[test]
    fn the_agent_is_denied_every_mutating_action_and_may_verify() {
        let user = Actor::User;
        let agent = Actor::Agent;
        let keypair = keygen(user).expect("keygen");
        let other = keygen(user).expect("second key");

        assert_code(authorize(KeyAction::Keygen, agent), ErrorCode::PolicyDenied);
        assert_code(authorize(KeyAction::Sign, agent), ErrorCode::PolicyDenied);
        assert_code(authorize(KeyAction::Pin, agent), ErrorCode::PolicyDenied);
        assert_code(authorize(KeyAction::Rotate, agent), ErrorCode::PolicyDenied);
        assert_code(authorize(KeyAction::Revoke, agent), ErrorCode::PolicyDenied);
        assert!(authorize(KeyAction::Verify, agent).is_ok());
        assert!(authorize(KeyAction::Verify, user).is_ok());

        assert_code(keygen(agent).map(|_| ()), ErrorCode::PolicyDenied);
        assert_code(
            sign_mode(agent, &keypair, &document()).map(|_| ()),
            ErrorCode::PolicyDenied,
        );

        let mut pins = PinSet::empty();
        assert_code(
            pins.pin(agent, keypair.pinned_key()),
            ErrorCode::PolicyDenied,
        );
        assert!(pins.keys().is_empty(), "a denied pin changed the set");

        pins.pin(user, keypair.pinned_key()).expect("user pin");
        assert_code(
            pins.rotate(agent, keypair.key_id(), &other),
            ErrorCode::PolicyDenied,
        );
        assert_code(
            pins.revoke(agent, keypair.key_id(), NOW),
            ErrorCode::PolicyDenied,
        );
        assert_code(pins.unpin(agent, keypair.key_id()), ErrorCode::PolicyDenied);
        assert_code(pins.unrevoke(agent, keypair.key_id()), ErrorCode::PolicyDenied);
        assert!(!pins.is_revoked(keypair.key_id()));
        assert_eq!(pins.keys().len(), 1);

        assert_code(
            keypair.seal(agent, "passphrase").map(|_| ()),
            ErrorCode::PolicyDenied,
        );
        let sealed = keypair.seal(user, "passphrase").expect("seal");
        assert_code(
            sealed.unseal(agent, "passphrase").map(|_| ()),
            ErrorCode::PolicyDenied,
        );

        // Verification is the one action the agent keeps.
        let signed = sign_mode(user, &keypair, &document()).expect("sign");
        let verified = pins
            .verify(agent, &signed.document, &signed.signature_b64, PROJECT, NOW)
            .expect("the agent may verify");
        assert_eq!(verified.key_id(), keypair.key_id());
    }

    #[test]
    fn a_wrong_passphrase_or_a_tampered_seal_is_typed() {
        let user = Actor::User;
        let keypair = keygen(user).expect("keygen");
        let sealed = keypair.seal(user, "correct horse battery staple").expect("seal");

        let restored = sealed
            .unseal(user, "correct horse battery staple")
            .expect("unseal");
        assert_eq!(restored.key_id(), keypair.key_id());
        assert_eq!(restored.public_key_b64(), keypair.public_key_b64());

        let error = sealed
            .unseal(user, "the wrong passphrase")
            .expect_err("wrong passphrase");
        assert_eq!(error.code(), ErrorCode::TamperDetected);
        assert!(
            error.message().contains("wrong passphrase"),
            "{}",
            error.message()
        );

        let mut tampered = sealed.clone();
        tampered.key_id = "some-other-key".to_string();
        assert_eq!(
            tampered.unseal(user, "correct horse battery staple").expect_err("key id tamper").code(),
            ErrorCode::TamperDetected
        );

        let mut tampered = sealed.clone();
        let first = tampered.ciphertext_b64.remove(0);
        tampered
            .ciphertext_b64
            .insert(0, if first == 'A' { 'B' } else { 'A' });
        assert_eq!(
            tampered
                .unseal(user, "correct horse battery staple")
                .expect_err("ciphertext tamper")
                .code(),
            ErrorCode::TamperDetected
        );

        assert_code(
            keypair.seal(user, "").map(|_| ()),
            ErrorCode::InvalidInput,
        );
        let long = "x".repeat(MAX_PASSPHRASE_BYTES + 1);
        assert_code(keypair.seal(user, &long).map(|_| ()), ErrorCode::LimitExceeded);
    }

    #[test]
    fn a_sealed_key_survives_a_file_round_trip() {
        let user = Actor::User;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("halcyon-key.sealed.json");
        let keypair = keygen(user).expect("keygen");

        keypair
            .seal(user, "passphrase")
            .expect("seal")
            .save_atomic(&path)
            .expect("save");
        let loaded = SealedKey::load(&path).expect("load");
        assert_eq!(loaded.key_id(), keypair.key_id());
        let restored = loaded.unseal(user, "passphrase").expect("unseal");
        assert_eq!(restored.public_key_b64(), keypair.public_key_b64());

        fs::write(&path, vec![b' '; MAX_SEALED_KEY_BYTES + 1]).expect("oversized");
        assert_eq!(
            SealedKey::load(&path).expect_err("oversized").code(),
            ErrorCode::LimitExceeded
        );
    }

    #[test]
    fn pin_unpin_rotate_and_revoke_persist() {
        let user = Actor::User;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("halcyon-keys.json");
        let old = keygen(user).expect("old key");
        let new = keygen(user).expect("new key");

        let mut pins = PinSet::empty();
        pins.pin(user, old.pinned_key()).expect("pin old");
        pins.save_atomic(&path).expect("save");
        assert_eq!(PinSet::load_file(&path).expect("load"), pins);

        let old_signed = sign_mode(user, &old, &document()).expect("sign old");
        pins.rotate(user, old.key_id(), &new).expect("rotate");
        pins.save_atomic(&path).expect("save rotation");
        let reloaded = PinSet::load_file(&path).expect("load rotation");
        assert_eq!(reloaded, pins);
        assert_eq!(reloaded.rotations().len(), 1);
        assert_eq!(reloaded.rotations()[0].from_key_id, old.key_id());
        assert_eq!(reloaded.rotations()[0].to_key_id, new.key_id());
        assert!(reloaded.keys().iter().all(|key| key.key_id != old.key_id()));
        assert!(reloaded.keys().iter().any(|key| key.key_id == new.key_id()));

        // The old key is unpinned, so it no longer verifies; the new key does.
        assert_eq!(
            old_signed
                .verify(&reloaded, PROJECT, NOW)
                .expect_err("old key unpinned")
                .code(),
            ErrorCode::PolicyDenied
        );
        let new_signed = sign_mode(user, &new, &document()).expect("sign new");
        assert!(new_signed.verify(&reloaded, PROJECT, NOW).is_ok());

        // Revocation persists and wins over the pin.
        pins.revoke(user, new.key_id(), NOW).expect("revoke");
        pins.save_atomic(&path).expect("save revoke");
        let reloaded = PinSet::load_file(&path).expect("load revoke");
        assert!(reloaded.is_revoked(new.key_id()));
        assert_eq!(reloaded.revoked()[0].at_ms, NOW);
        let error = new_signed
            .verify(&reloaded, PROJECT, NOW)
            .expect_err("revoked key");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("revoked"), "{}", error.message());

        // A revoked id cannot be re-pinned until the user un-revokes it.
        let mut reloaded = reloaded;
        assert_code(
            reloaded.pin(user, new.pinned_key()),
            ErrorCode::PolicyDenied,
        );
        reloaded.unpin(user, new.key_id()).expect("unpin revoked id");
        assert_code(
            reloaded.pin(user, new.pinned_key()),
            ErrorCode::PolicyDenied,
        );
        reloaded.unrevoke(user, new.key_id()).expect("un-revoke");
        reloaded.pin(user, new.pinned_key()).expect("pin after un-revoke");
        assert!(new_signed.verify(&reloaded, PROJECT, NOW).is_ok());

        reloaded.save_atomic(&path).expect("save final");
        assert_eq!(PinSet::load_file(&path).expect("load final"), reloaded);

        assert_code(reloaded.unpin(user, "never-pinned"), ErrorCode::NotFound);
        assert_code(reloaded.unrevoke(user, "never-revoked"), ErrorCode::NotFound);
    }

    #[test]
    fn a_revoked_key_is_rejected_even_while_pinned_and_the_pin_file_holds_no_secret() {
        let user = Actor::User;
        let dir = tempfile::tempdir().expect("tempdir");
        let keypair = keygen(user).expect("keygen");
        let signed = sign_mode(user, &keypair, &document()).expect("sign");
        let mut pins = PinSet::empty();
        pins.pin(user, keypair.pinned_key()).expect("pin");
        assert!(signed.verify(&pins, PROJECT, NOW).is_ok());

        pins.revoke(user, keypair.key_id(), NOW).expect("revoke");
        pins.revoke(user, keypair.key_id(), NOW + 1)
            .expect("revoke is idempotent");
        assert_eq!(pins.revoked().len(), 1);
        assert!(pins.keys().iter().any(|key| key.key_id == keypair.key_id()));

        let error = signed
            .verify(&pins, PROJECT, NOW)
            .expect_err("revoked but still pinned");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("revoked"), "{}", error.message());

        let path = dir.path().join("halcyon-keys.json");
        pins.save_atomic(&path).expect("save");
        let text = fs::read_to_string(&path).expect("read pin file");
        assert!(!text.contains("private"), "the pin file has a private field");

        let secret = keypair.signing.to_bytes();
        scan_files(dir.path(), &hex(&secret), &B64.encode(secret), &secret);
    }

    #[test]
    fn a_copied_repository_and_a_wrong_project_still_fail() {
        let user = Actor::User;
        let keypair = keygen(user).expect("keygen");
        let mut pins = PinSet::empty();
        pins.pin(user, keypair.pinned_key()).expect("pin");
        let signed = sign_mode(user, &keypair, &document()).expect("sign");

        assert!(signed.verify(&pins, PROJECT, NOW).is_ok());

        let error = signed
            .verify(&pins, "prj_copied_00112233445566", NOW)
            .expect_err("copied repository");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("copied repository"));
    }

    #[test]
    fn signing_does_not_change_the_canonical_bytes() {
        let user = Actor::User;
        let keypair = keygen(user).expect("keygen");
        let mut document = document();
        document.key_id = keypair.key_id().to_string();
        let before = canonical_bytes(&document).expect("canonical");

        let signed = sign_mode(user, &keypair, &document).expect("sign");
        let after = canonical_bytes(&signed.document).expect("canonical after");
        assert_eq!(before, after, "the signature must stay outside the signed bytes");
        assert_eq!(signed.document.signature.as_deref(), Some(signed.signature_b64.as_str()));
    }

    #[test]
    fn key_ids_are_stable_and_labels_are_honoured() {
        let user = Actor::User;
        let first = pair(7, "label-one");
        let second = pair(7, "label-one");
        assert_eq!(first.key_id(), "label-one");
        assert_eq!(first.key_id(), second.key_id());

        let derived = derived_key_id(&first.signing.verifying_key());
        assert_eq!(derived, derived_key_id(&first.signing.verifying_key()));
        assert_ne!(derived, derived_key_id(&pair(9, "label-two").signing.verifying_key()));
        assert!(derived.starts_with("halcyon-"));
        assert_eq!(derived.len(), "halcyon-".len() + KEY_ID_HEX_CHARS);

        let labelled = KeyPair::with_label(user, "user-halcyon-key").expect("label");
        assert_eq!(labelled.key_id(), "user-halcyon-key");
        assert_eq!(
            KeyPair::with_label(user, "two words")
                .expect_err("space in label")
                .code(),
            ErrorCode::InvalidInput
        );

        let sealed = first.seal(user, "passphrase").expect("seal");
        let restored = sealed.unseal(user, "passphrase").expect("unseal");
        assert_eq!(restored.key_id(), "label-one");
    }

    #[test]
    fn private_key_bytes_never_appear_in_debug_or_errors() {
        let user = Actor::User;
        let dir = tempfile::tempdir().expect("tempdir");
        let keypair = keygen(user).expect("keygen");
        let secret = keypair.signing.to_bytes();
        let secret_hex = hex(&secret);
        let secret_b64 = B64.encode(secret);

        let keypair_debug = format!("{keypair:?}");
        assert!(!keypair_debug.contains(&secret_hex));
        assert!(!keypair_debug.contains(&secret_b64));
        assert!(keypair_debug.contains(keypair.key_id()));

        let sealed = keypair.seal(user, "passphrase").expect("seal");
        let sealed_debug = format!("{sealed:?}");
        assert!(!sealed_debug.contains(&secret_hex));
        assert!(!sealed_debug.contains(&secret_b64));
        assert!(!format!("{sealed:?}").contains(&sealed.ciphertext_b64));

        let signed = sign_mode(user, &keypair, &document()).expect("sign");
        assert!(!format!("{signed:?}").contains(&secret_hex));

        let error = sealed.unseal(user, "wrong").expect_err("wrong passphrase");
        assert!(!error.message().contains(&secret_hex));
        assert!(!error.message().contains(&secret_b64));
        assert!(
            !error.message().contains(&B64.encode(keypair.signing.verifying_key().to_bytes())),
            "an error must not echo the public key either"
        );

        // Every file this slice can write: the pin file, the sealed envelope,
        // and the signed mode document. None may carry the private scalar.
        let mut pins = PinSet::empty();
        pins.pin(user, keypair.pinned_key()).expect("pin");
        pins.save_atomic(&dir.path().join("halcyon-keys.json"))
            .expect("save pins");
        sealed
            .save_atomic(&dir.path().join("halcyon-key.sealed.json"))
            .expect("save sealed");
        fs::write(
            dir.path().join("mode.json"),
            signed.to_json_bytes().expect("signed json"),
        )
        .expect("save signed document");
        scan_files(dir.path(), &secret_hex, &secret_b64, &secret);

        // Pinned key uses exactly 32 public bytes, never the private scalar.
        let pinned = keypair.pinned_key();
        let decoded = B64.decode(&pinned.public_key_b64).expect("public key");
        assert_eq!(decoded.len(), PUBLIC_KEY_BYTES);
        assert_ne!(decoded[..], secret[..]);
    }

    #[test]
    fn a_bad_schema_or_malformed_pin_file_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("halcyon-keys.json");
        fs::write(&path, br#"{"schema":99,"pins":[],"revoked":[]}"#).expect("write");
        assert_eq!(
            PinFile::load(&path).expect_err("bad schema").code(),
            ErrorCode::SchemaVersion
        );

        fs::write(&path, br#"{"schema":1,"pins":[],"revoked":[{"key_id":"k","at_ms":1},{"key_id":"k","at_ms":2}]}"#)
            .expect("write");
        assert_eq!(
            PinFile::load(&path).expect_err("duplicate revocation").code(),
            ErrorCode::InvalidInput
        );

        let mut pins = PinSet::empty();
        let keypair = keygen(Actor::User).expect("keygen");
        pins.pin(Actor::User, keypair.pinned_key()).expect("pin");
        assert_code(
            pins.pin(Actor::User, keypair.pinned_key()),
            ErrorCode::AlreadyExists,
        );
    }
}
