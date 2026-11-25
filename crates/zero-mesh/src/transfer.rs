//! End-to-end encrypted teleport transfer (T-TEL-03, TEL-03, TEL-06, TEL-09).
//!
//! [`seal_bundle`] turns a built [`Bundle`] into a [`SealedBundle`] that a relay
//! or any other transport can forward without holding a key: an X25519
//! ephemeral sender key, an ECDH shared secret with the recipient, HKDF-SHA256
//! into a per-bundle key, and ChaCha20-Poly1305 over the manifest and every
//! unique chunk. Each chunk uses a nonce derived from the bundle id and its
//! index, and binds the bundle id, the index, and the plaintext blake3 hash as
//! associated data. [`open_bundle_verified`] derives the same key, decrypts the
//! manifest and chunks, re-hashes every plaintext chunk, and runs the bundle's
//! own verification before returning a [`VerifiedTransfer`]. A wrong recipient,
//! a tampered tag, a changed hash, or a truncated envelope fails with a typed
//! error and never materializes a partial bundle.
//!
//! [`retain_until_verified`] is the TEL-06 retention policy: the source and the
//! staging target stay in place until verification succeeds, and the report
//! says whether cleanup is allowed. It never deletes anything by default;
//! [`retain_until_verified_with`] can remove the source only when the caller
//! explicitly opts in and verification succeeded. A failed transfer keeps both
//! sides for diagnosis.
//!
//! Cryptography is delegated to maintained RustCrypto crates: `x25519-dalek`
//! for the key agreement, `hkdf` + the workspace `sha2` for the KDF, and
//! `chacha20poly1305` for the AEAD. There is no hand-rolled cipher. The relay
//! sees hashes, sizes, ids, ciphertext, and nonces; it never sees a key or a
//! plaintext.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zero_types::{ErrorCode, ZeroError};
use zeroize::{Zeroize, Zeroizing};

use crate::bundle::{self, Bundle, BundleManifest, VerifyReport};

/// Transfer envelope schema this build reads and writes.
pub const TRANSFER_SCHEMA_VERSION: u32 = 1;

/// Length of an X25519 public or secret key, in bytes.
pub const X25519_KEY_BYTES: usize = 32;

/// Length of the per-bundle ChaCha20-Poly1305 key, in bytes.
pub const AEAD_KEY_BYTES: usize = 32;

/// Length of a ChaCha20-Poly1305 nonce, in bytes.
pub const AEAD_NONCE_BYTES: usize = 12;

/// Length of a ChaCha20-Poly1305 authentication tag, in bytes.
pub const AEAD_TAG_BYTES: usize = 16;

/// Length of a recipient id in hex characters (32 bytes).
pub const RECIPIENT_ID_HEX: usize = 64;

/// Domain separator for the recipient id.
pub const RECIPIENT_ID_DOMAIN: &[u8] = b"zero.teleport.transfer.recipient-id.v1\0";

/// Domain separator for the per-bundle AEAD key.
pub const TRANSFER_KEY_DOMAIN: &[u8] = b"zero.teleport.transfer.key.v1\0";

/// Domain separator for a per-chunk nonce.
pub const CHUNK_NONCE_DOMAIN: &[u8] = b"zero.teleport.transfer.nonce.chunk.v1\0";

/// Domain separator for the manifest nonce.
pub const MANIFEST_NONCE_DOMAIN: &[u8] = b"zero.teleport.transfer.nonce.manifest.v1\0";

/// Domain separator for a chunk's associated data.
pub const CHUNK_AAD_DOMAIN: &[u8] = b"zero.teleport.transfer.aad.chunk.v1\0";

/// Domain separator for the manifest's associated data.
pub const MANIFEST_AAD_DOMAIN: &[u8] = b"zero.teleport.transfer.aad.manifest.v1\0";

/// Largest sealed manifest plaintext: four times the canonical manifest cap.
///
/// The canonical manifest is capped at [`bundle::MAX_BUNDLE_MANIFEST_BYTES`];
/// JSON framing (field names, punctuation, repeated chunk keys) can be a few
/// times larger, so the encrypted form is capped more generously and the
/// canonical check still runs after decryption.
pub const MAX_SEALED_MANIFEST_PLAINTEXT_BYTES: usize = 4 * bundle::MAX_BUNDLE_MANIFEST_BYTES;

/// Most chunks a sealed envelope may declare.
pub const MAX_SEALED_CHUNKS: usize = bundle::MAX_TOTAL_CHUNKS as usize;

/// An X25519 public key a bundle is sealed for.
///
/// The key itself is public; [`Debug`] prints only the derived
/// [`recipient_id`](Self::recipient_id), so a log line never carries key bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct RecipientKey {
    public: [u8; X25519_KEY_BYTES],
}

impl RecipientKey {
    /// Build a recipient key from raw X25519 public bytes.
    pub fn from_public_bytes(public: [u8; X25519_KEY_BYTES]) -> Self {
        Self { public }
    }

    /// Parse a standard padded base64 X25519 public key.
    pub fn from_base64(text: &str) -> Result<Self> {
        let bytes = decode_b64(text, "recipient public key")?;
        let public: [u8; X25519_KEY_BYTES] = bytes.as_slice().try_into().map_err(|_| {
            invalid(format!(
                "recipient public key must be {X25519_KEY_BYTES} bytes"
            ))
        })?;
        Ok(Self { public })
    }

    /// The raw X25519 public bytes.
    pub fn public_bytes(&self) -> [u8; X25519_KEY_BYTES] {
        self.public
    }

    /// Standard padded base64 of the public key.
    pub fn public_b64(&self) -> String {
        B64.encode(self.public)
    }

    /// The lower-case hex recipient id derived from the public key.
    pub fn recipient_id(&self) -> String {
        recipient_id(&self.public)
    }
}

impl fmt::Debug for RecipientKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecipientKey")
            .field("recipient_id", &self.recipient_id())
            .finish()
    }
}

/// The recipient's X25519 secret key.
///
/// `StaticSecret` zeroizes its bytes on drop. There is no accessor for the raw
/// secret and [`Debug`] is redacted; a caller that persists the key must keep
/// it in the credential store, not in a log or a bundle.
pub struct RecipientSecret {
    secret: StaticSecret,
}

impl RecipientSecret {
    /// Generate a recipient key from the operating system's entropy.
    pub fn generate() -> Result<Self> {
        Ok(Self::from_seed(random_seed()?))
    }

    /// Build a recipient key from a 32-byte seed.
    pub fn from_seed(mut seed: [u8; X25519_KEY_BYTES]) -> Self {
        let secret = StaticSecret::from(seed);
        seed.zeroize();
        Self { secret }
    }

    /// The public half of this key.
    pub fn recipient_key(&self) -> RecipientKey {
        RecipientKey::from_public_bytes(self.public_bytes())
    }

    /// The raw X25519 public bytes.
    pub fn public_bytes(&self) -> [u8; X25519_KEY_BYTES] {
        PublicKey::from(&self.secret).to_bytes()
    }
}

impl fmt::Debug for RecipientSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecipientSecret(<redacted>)")
    }
}

/// An ephemeral X25519 sender key.
///
/// [`seal_bundle`] creates one per bundle and drops it immediately. The
/// deterministic constructor exists for tests and reproducible fixtures; a
/// production caller should use [`seal_bundle`] so the key is fresh. [`Debug`]
/// is redacted.
pub struct SenderSecret {
    secret: StaticSecret,
}

impl SenderSecret {
    /// Generate an ephemeral sender key from the operating system's entropy.
    pub fn generate() -> Result<Self> {
        Ok(Self::from_seed(random_seed()?))
    }

    /// Build an ephemeral sender key from a 32-byte seed.
    pub fn from_seed(mut seed: [u8; X25519_KEY_BYTES]) -> Self {
        let secret = StaticSecret::from(seed);
        seed.zeroize();
        Self { secret }
    }

    /// The X25519 public half that travels in the sealed envelope.
    pub fn ephemeral_public(&self) -> [u8; X25519_KEY_BYTES] {
        PublicKey::from(&self.secret).to_bytes()
    }
}

impl fmt::Debug for SenderSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SenderSecret(<redacted>)")
    }
}

/// One encrypted chunk.
///
/// `chunk_hash` and `bytes` are the plaintext blake3 digest and length; they
/// are public metadata (the relay can route without the key) and are checked
/// after decryption. `nonce` and `ciphertext` are standard padded base64.
/// [`Debug`] prints lengths, never the nonce or ciphertext.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedChunk {
    /// Lower-case hex blake3 digest of the plaintext chunk.
    pub chunk_hash: String,
    /// Plaintext chunk length in bytes.
    pub bytes: u64,
    /// Standard padded base64 96-bit nonce derived from the bundle and index.
    pub nonce: String,
    /// Standard padded base64 ChaCha20-Poly1305 ciphertext including its tag.
    pub ciphertext: String,
}

impl fmt::Debug for SealedChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedChunk")
            .field("chunk_hash", &self.chunk_hash)
            .field("bytes", &self.bytes)
            .field("nonce_len", &self.nonce.len())
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

/// An encrypted bundle: the encrypted manifest and every unique chunk.
///
/// The envelope carries no key and no plaintext. `bundle_id` and
/// `manifest_hash` identify the plaintext bundle; `ephemeral_public` is the
/// sender's one-use X25519 public key; `recipient_id` binds the envelope to one
/// recipient. [`Debug`] prints ids and lengths only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedBundle {
    /// Envelope schema version.
    pub schema_version: u32,
    /// Lower-case hex id of the plaintext bundle.
    pub bundle_id: String,
    /// Lower-case hex blake3 of the plaintext manifest's canonical bytes.
    pub manifest_hash: String,
    /// Lower-case hex recipient id.
    pub recipient_id: String,
    /// Standard padded base64 32-byte X25519 ephemeral public key.
    pub ephemeral_public: String,
    /// Standard padded base64 96-bit manifest nonce.
    pub manifest_nonce: String,
    /// Standard padded base64 encrypted manifest including its tag.
    pub manifest_ciphertext: String,
    /// Encrypted unique chunks, strictly ascending by `chunk_hash`.
    pub chunks: Vec<SealedChunk>,
    /// Logical bytes of every file in the plaintext manifest.
    pub plaintext_bytes: u64,
    /// Bytes of the unique plaintext chunks.
    pub stored_bytes: u64,
}

impl fmt::Debug for SealedBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedBundle")
            .field("schema_version", &self.schema_version)
            .field("bundle_id", &self.bundle_id)
            .field("manifest_hash", &self.manifest_hash)
            .field("recipient_id", &self.recipient_id)
            .field("ephemeral_public_len", &self.ephemeral_public.len())
            .field("manifest_nonce_len", &self.manifest_nonce.len())
            .field("manifest_ciphertext_len", &self.manifest_ciphertext.len())
            .field("chunks", &self.chunks.len())
            .field("plaintext_bytes", &self.plaintext_bytes)
            .field("stored_bytes", &self.stored_bytes)
            .finish()
    }
}

impl SealedBundle {
    /// Validate the envelope's shape without a key.
    ///
    /// This is the relay-side check: schema, hex ids, base64 lengths, chunk
    /// order, nonce uniqueness, declared sizes, and the bundle-wide caps. It
    /// never decrypts anything, so a corrupted chunk is only detected by
    /// [`open_bundle_verified`].
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != TRANSFER_SCHEMA_VERSION {
            return Err(ZeroError::new(
                ErrorCode::SchemaVersion,
                format!(
                    "transfer schema version {} is not supported; this build reads {TRANSFER_SCHEMA_VERSION}",
                    self.schema_version
                ),
            ));
        }
        validate_hex64(&self.bundle_id, "bundle id")?;
        validate_hex64(&self.manifest_hash, "manifest hash")?;
        validate_hex64(&self.recipient_id, "recipient id")?;

        let _ephemeral_public = decode_b64_exact(
            &self.ephemeral_public,
            X25519_KEY_BYTES,
            "ephemeral public key",
        )?;
        let manifest_nonce =
            decode_b64_exact(&self.manifest_nonce, AEAD_NONCE_BYTES, "manifest nonce")?;
        let manifest_ciphertext = decode_b64(&self.manifest_ciphertext, "manifest ciphertext")?;
        if manifest_ciphertext.len() <= AEAD_TAG_BYTES {
            return Err(tamper(
                "sealed manifest ciphertext is shorter than its authentication tag",
            ));
        }
        if manifest_ciphertext.len() > MAX_SEALED_MANIFEST_PLAINTEXT_BYTES + AEAD_TAG_BYTES {
            return Err(limit(format!(
                "sealed manifest ciphertext is {} bytes; the limit is {}",
                manifest_ciphertext.len(),
                MAX_SEALED_MANIFEST_PLAINTEXT_BYTES + AEAD_TAG_BYTES
            )));
        }

        if self.chunks.len() > MAX_SEALED_CHUNKS {
            return Err(limit(format!(
                "sealed envelope carries {} chunks; the limit is {MAX_SEALED_CHUNKS}",
                self.chunks.len()
            )));
        }

        let mut nonces: BTreeSet<[u8; AEAD_NONCE_BYTES]> = BTreeSet::new();
        let manifest_nonce: [u8; AEAD_NONCE_BYTES] = manifest_nonce
            .as_slice()
            .try_into()
            .expect("length checked by decode_b64_exact");
        nonces.insert(manifest_nonce);

        let mut stored_bytes = 0u64;
        let mut ciphertext_bytes = 0u64;
        let mut previous: Option<&str> = None;
        for chunk in &self.chunks {
            validate_hex64(&chunk.chunk_hash, "chunk hash")?;
            if chunk.bytes == 0 {
                return Err(invalid(format!(
                    "chunk `{}` declares an empty plaintext",
                    chunk.chunk_hash
                )));
            }
            if chunk.bytes > bundle::MAX_CHUNK_BYTES as u64 {
                return Err(limit(format!(
                    "chunk `{}` declares {} bytes; the limit is {}",
                    chunk.chunk_hash,
                    chunk.bytes,
                    bundle::MAX_CHUNK_BYTES
                )));
            }
            if let Some(previous) = previous {
                if previous >= chunk.chunk_hash.as_str() {
                    return Err(tamper(
                        "sealed chunks must be strictly ascending by hash with no duplicates",
                    ));
                }
            }
            previous = Some(&chunk.chunk_hash);

            let nonce = decode_b64_exact(&chunk.nonce, AEAD_NONCE_BYTES, "chunk nonce")?;
            let nonce: [u8; AEAD_NONCE_BYTES] = nonce
                .as_slice()
                .try_into()
                .expect("length checked by decode_b64_exact");
            if !nonces.insert(nonce) {
                return Err(tamper(format!(
                    "chunk `{}` reuses an AEAD nonce",
                    chunk.chunk_hash
                )));
            }

            let ciphertext = decode_b64(&chunk.ciphertext, "chunk ciphertext")?;
            let expected = chunk
                .bytes
                .checked_add(AEAD_TAG_BYTES as u64)
                .ok_or_else(|| limit("sealed chunk size overflows its counter"))?;
            if ciphertext.len() as u64 != expected {
                return Err(tamper(format!(
                    "chunk `{}` carries {} bytes but declares {} plus a {}-byte tag",
                    chunk.chunk_hash,
                    ciphertext.len(),
                    chunk.bytes,
                    AEAD_TAG_BYTES
                )));
            }
            stored_bytes = stored_bytes
                .checked_add(chunk.bytes)
                .ok_or_else(|| limit("sealed chunk bytes overflow their counter"))?;
            ciphertext_bytes = ciphertext_bytes
                .checked_add(ciphertext.len() as u64)
                .ok_or_else(|| limit("sealed ciphertext bytes overflow their counter"))?;
        }

        if stored_bytes > bundle::MAX_BUNDLE_BYTES {
            return Err(limit(format!(
                "sealed chunks total {stored_bytes} bytes; the limit is {}",
                bundle::MAX_BUNDLE_BYTES
            )));
        }
        if self.stored_bytes != stored_bytes {
            return Err(tamper(format!(
                "sealed envelope declares {} stored bytes but its chunks total {stored_bytes}",
                self.stored_bytes
            )));
        }
        if self.plaintext_bytes < stored_bytes {
            return Err(tamper(
                "sealed envelope declares fewer logical bytes than stored bytes",
            ));
        }
        let overhead = (self.chunks.len() as u64)
            .checked_mul(AEAD_TAG_BYTES as u64)
            .ok_or_else(|| limit("sealed tag overhead overflows its counter"))?;
        let max_ciphertext = bundle::MAX_BUNDLE_BYTES
            .checked_add(overhead)
            .ok_or_else(|| limit("sealed ciphertext bound overflows"))?;
        if ciphertext_bytes > max_ciphertext {
            return Err(limit(format!(
                "sealed ciphertext totals {ciphertext_bytes} bytes; the limit is {max_ciphertext}"
            )));
        }
        Ok(())
    }
}

/// A bundle that decrypted and verified end to end.
///
/// `verified_chunks` is the number of unique chunks re-hashed and checked
/// against the manifest; `manifest_hash` is the blake3 of the canonical
/// manifest. [`Debug`] delegates to [`Bundle`]'s size-only output.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedTransfer {
    /// The decrypted, verified bundle.
    pub bundle: Bundle,
    /// Unique chunks whose plaintext hash matched the manifest.
    pub verified_chunks: u64,
    /// Lower-case hex blake3 of the canonical manifest.
    pub manifest_hash: String,
}

impl VerifiedTransfer {
    /// The plaintext bundle id.
    pub fn bundle_id(&self) -> &str {
        &self.bundle.manifest.bundle_id
    }

    /// Re-run the in-memory bundle verification.
    pub fn verify_report(&self) -> Result<VerifyReport> {
        bundle::verify_bundle(&self.bundle)
    }
}

impl fmt::Debug for VerifiedTransfer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedTransfer")
            .field("bundle", &self.bundle)
            .field("verified_chunks", &self.verified_chunks)
            .field("manifest_hash", &self.manifest_hash)
            .finish()
    }
}

/// Transfer counts and bytes for a UI or a log. No key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferReport {
    /// Plaintext bundle id.
    pub bundle_id: String,
    /// Lower-case hex blake3 of the canonical manifest.
    pub manifest_hash: String,
    /// Recipient the envelope is sealed for.
    pub recipient_id: String,
    /// Unique chunks carried.
    pub chunks: u64,
    /// Logical bytes of every file.
    pub plaintext_bytes: u64,
    /// Bytes of the unique plaintext chunks.
    pub stored_bytes: u64,
    /// Ciphertext bytes on the wire, including tags and the manifest.
    pub ciphertext_bytes: u64,
}

/// Retention policy for [`retain_until_verified_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RetentionOptions {
    /// Remove the source directory after verification succeeds. Off by
    /// default; the helper never deletes anything unless this is set.
    pub cleanup_source: bool,
}

/// What the retention policy decided about the two paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionReport {
    /// The source directory considered.
    pub source_dir: PathBuf,
    /// The target or staging directory considered.
    pub target_dir: PathBuf,
    /// True when the source is still on disk.
    pub kept_source: bool,
    /// True when the target or staging directory is still on disk.
    pub kept_staging: bool,
    /// True only when verification succeeded and cleanup is permitted.
    pub can_cleanup: bool,
}

/// Seal `bundle` for `recipient` with a fresh ephemeral X25519 key.
///
/// The manifest and every unique chunk are encrypted; the returned
/// [`SealedBundle`] contains no key and no plaintext. The bundle is verified
/// in memory before it is sealed, so a corrupt chunk never enters an envelope.
pub fn seal_bundle(bundle: &Bundle, recipient: &RecipientKey) -> Result<SealedBundle> {
    let sender = SenderSecret::generate()?;
    seal_with_sender(bundle, recipient, &sender)
}

/// [`seal_bundle`] with a caller-supplied ephemeral seed.
///
/// This exists for deterministic tests and fixtures. Reusing a seed across
/// unrelated transfers weakens the ephemeral-key guarantee; production callers
/// should use [`seal_bundle`].
pub fn seal_bundle_with_seed(
    bundle: &Bundle,
    recipient: &RecipientKey,
    mut ephemeral_seed: [u8; X25519_KEY_BYTES],
) -> Result<SealedBundle> {
    let sender = SenderSecret::from_seed(ephemeral_seed);
    ephemeral_seed.zeroize();
    seal_with_sender(bundle, recipient, &sender)
}

fn seal_with_sender(
    bundle: &Bundle,
    recipient: &RecipientKey,
    sender: &SenderSecret,
) -> Result<SealedBundle> {
    let report = bundle::verify_bundle(bundle)?;
    if report.chunks > MAX_SEALED_CHUNKS as u64 {
        return Err(limit(format!(
            "bundle has {} unique chunks; the transfer limit is {MAX_SEALED_CHUNKS}",
            report.chunks
        )));
    }

    let manifest_hash = bundle::manifest_hash(&bundle.manifest)?;
    let bundle_id = bundle.manifest.bundle_id.clone();
    let bundle_id_raw = hex32(&bundle_id)?;
    let manifest_hash_raw = hex32(&manifest_hash)?;

    let ephemeral_public = sender.ephemeral_public();
    let recipient_public = recipient.public_bytes();
    let shared = sender
        .secret
        .diffie_hellman(&PublicKey::from(recipient_public));
    let crypto =
        TransferCrypto::derive(&shared, ephemeral_public, recipient_public, bundle_id_raw)?;
    drop(shared);

    let manifest_plaintext = serde_json::to_vec(&bundle.manifest)
        .map_err(|error| internal(format!("cannot encode the bundle manifest: {error}")))?;
    if manifest_plaintext.len() > MAX_SEALED_MANIFEST_PLAINTEXT_BYTES {
        return Err(limit(format!(
            "bundle manifest encodes to {} bytes; the transfer limit is {MAX_SEALED_MANIFEST_PLAINTEXT_BYTES}",
            manifest_plaintext.len()
        )));
    }
    let manifest_nonce = crypto.manifest_nonce()?;
    let manifest_aad = manifest_aad(&bundle_id_raw, &manifest_hash_raw);
    let manifest_ciphertext =
        crypto.encrypt(&manifest_nonce, &manifest_plaintext, &manifest_aad)?;

    let hashes = bundle.manifest.chunk_hashes();
    let mut chunks = Vec::with_capacity(hashes.len());
    let mut stored_bytes = 0u64;
    for (index, hash) in hashes.iter().enumerate() {
        let bytes = bundle
            .chunks
            .get(hash)
            .ok_or_else(|| tamper(format!("chunk `{hash}` is missing from the bundle")))?;
        if blake3::hash(bytes).to_hex().to_string() != *hash {
            return Err(tamper(format!(
                "chunk `{hash}` does not match its content hash"
            )));
        }
        let index =
            u64::try_from(index).map_err(|_| limit("bundle chunk index does not fit in a u64"))?;
        let nonce = crypto.chunk_nonce(index)?;
        let aad = chunk_aad(&bundle_id_raw, index, hash)?;
        let ciphertext = crypto.encrypt(&nonce, bytes, &aad)?;
        stored_bytes = stored_bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| limit("sealed chunk bytes overflow their counter"))?;
        chunks.push(SealedChunk {
            chunk_hash: hash.clone(),
            bytes: bytes.len() as u64,
            nonce: B64.encode(nonce),
            ciphertext: B64.encode(ciphertext),
        });
    }
    if stored_bytes != report.stored_bytes {
        return Err(internal(format!(
            "sealed chunks total {stored_bytes} bytes but verification reported {}",
            report.stored_bytes
        )));
    }

    Ok(SealedBundle {
        schema_version: TRANSFER_SCHEMA_VERSION,
        bundle_id,
        manifest_hash,
        recipient_id: recipient.recipient_id(),
        ephemeral_public: B64.encode(ephemeral_public),
        manifest_nonce: B64.encode(manifest_nonce),
        manifest_ciphertext: B64.encode(manifest_ciphertext),
        chunks,
        plaintext_bytes: bundle.manifest.total_bytes,
        stored_bytes,
    })
}

/// Decrypt and verify a sealed bundle, returning the plaintext [`Bundle`].
///
/// See [`open_bundle_verified`] for the verification evidence.
pub fn open_bundle(sealed: &SealedBundle, recipient: &RecipientSecret) -> Result<Bundle> {
    Ok(open_bundle_verified(sealed, recipient)?.bundle)
}

/// Decrypt and verify a sealed bundle, returning the evidence.
///
/// The checks run in this order and nothing is written to disk:
///
/// 1. the envelope's shape and caps ([`SealedBundle::validate`]);
/// 2. the envelope is for this recipient (`zero.pol.denied` otherwise);
/// 3. X25519 ECDH and the HKDF per-bundle key;
/// 4. the manifest decrypts, deserializes, and matches the declared bundle id
///    and manifest hash;
/// 5. the sealed chunk set and order match the manifest;
/// 6. each chunk nonce equals the derived nonce, the ciphertext authenticates,
///    and the plaintext blake3 matches the chunk hash;
/// 7. [`bundle::verify_bundle`] re-checks every file and chunk.
pub fn open_bundle_verified(
    sealed: &SealedBundle,
    recipient: &RecipientSecret,
) -> Result<VerifiedTransfer> {
    sealed.validate()?;

    let recipient_key = recipient.recipient_key();
    if sealed.recipient_id != recipient_key.recipient_id() {
        return Err(denied(format!(
            "this bundle is sealed for recipient `{}`, not `{}`",
            sealed.recipient_id,
            recipient_key.recipient_id()
        )));
    }

    let bundle_id_raw = hex32(&sealed.bundle_id)?;
    let manifest_hash_raw = hex32(&sealed.manifest_hash)?;
    let ephemeral_public = decode_b64_exact(
        &sealed.ephemeral_public,
        X25519_KEY_BYTES,
        "ephemeral public key",
    )?;
    let ephemeral_public: [u8; X25519_KEY_BYTES] = ephemeral_public
        .as_slice()
        .try_into()
        .expect("length checked by decode_b64_exact");

    let ephemeral = PublicKey::from(ephemeral_public);
    let shared = recipient.secret.diffie_hellman(&ephemeral);
    let crypto = TransferCrypto::derive(
        &shared,
        ephemeral_public,
        recipient.public_bytes(),
        bundle_id_raw,
    )?;
    drop(shared);

    let manifest_nonce =
        decode_b64_exact(&sealed.manifest_nonce, AEAD_NONCE_BYTES, "manifest nonce")?;
    let manifest_nonce: [u8; AEAD_NONCE_BYTES] = manifest_nonce
        .as_slice()
        .try_into()
        .expect("length checked by decode_b64_exact");
    let derived_manifest_nonce = crypto.manifest_nonce()?;
    if manifest_nonce != derived_manifest_nonce {
        return Err(tamper(
            "sealed manifest nonce does not match the derived nonce",
        ));
    }
    let manifest_aad = manifest_aad(&bundle_id_raw, &manifest_hash_raw);
    let manifest_ciphertext = decode_b64(&sealed.manifest_ciphertext, "manifest ciphertext")?;
    let manifest_plaintext =
        crypto.decrypt(&manifest_nonce, &manifest_ciphertext, &manifest_aad)?;
    let manifest: BundleManifest = serde_json::from_slice(&manifest_plaintext)
        .map_err(|_| tamper("sealed manifest is not a readable bundle manifest"))?;

    manifest.canonical_bytes()?;
    let computed_manifest_hash = bundle::manifest_hash(&manifest)?;
    if computed_manifest_hash != sealed.manifest_hash {
        return Err(tamper(format!(
            "decrypted manifest hashes to `{computed_manifest_hash}` but the envelope declares `{}`",
            sealed.manifest_hash
        )));
    }
    if manifest.bundle_id != sealed.bundle_id {
        return Err(tamper(format!(
            "decrypted manifest is bundle `{}` but the envelope declares `{}`",
            manifest.bundle_id, sealed.bundle_id
        )));
    }

    let expected = manifest.chunk_hashes();
    if expected.len() != sealed.chunks.len() {
        return Err(tamper(format!(
            "sealed envelope carries {} chunks but the manifest names {}",
            sealed.chunks.len(),
            expected.len()
        )));
    }
    let mut chunks = std::collections::BTreeMap::new();
    for (index, (hash, sealed_chunk)) in expected.iter().zip(sealed.chunks.iter()).enumerate() {
        if sealed_chunk.chunk_hash != *hash {
            return Err(tamper(format!(
                "sealed chunk {index} is `{}` but the manifest expects `{hash}`",
                sealed_chunk.chunk_hash
            )));
        }
        let index =
            u64::try_from(index).map_err(|_| limit("bundle chunk index does not fit in a u64"))?;
        let nonce = decode_b64_exact(&sealed_chunk.nonce, AEAD_NONCE_BYTES, "chunk nonce")?;
        let nonce: [u8; AEAD_NONCE_BYTES] = nonce
            .as_slice()
            .try_into()
            .expect("length checked by decode_b64_exact");
        let derived_nonce = crypto.chunk_nonce(index)?;
        if nonce != derived_nonce {
            return Err(tamper(format!(
                "chunk `{hash}` nonce does not match the derived nonce"
            )));
        }
        let aad = chunk_aad(&bundle_id_raw, index, hash)?;
        let ciphertext = decode_b64(&sealed_chunk.ciphertext, "chunk ciphertext")?;
        let plaintext = crypto.decrypt(&nonce, &ciphertext, &aad)?;
        if plaintext.len() as u64 != sealed_chunk.bytes {
            return Err(tamper(format!(
                "chunk `{hash}` decrypts to {} bytes but the envelope declares {}",
                plaintext.len(),
                sealed_chunk.bytes
            )));
        }
        let computed = blake3::hash(&plaintext).to_hex().to_string();
        if computed != *hash {
            return Err(tamper(format!(
                "chunk `{hash}` plaintext hashes to `{computed}`"
            )));
        }
        chunks.insert(hash.clone(), plaintext);
    }
    if chunks.len() != expected.len() {
        return Err(tamper("sealed chunk set does not match the manifest"));
    }

    let bundle = Bundle { manifest, chunks };
    let report = bundle::verify_bundle(&bundle)?;
    if sealed.plaintext_bytes != bundle.manifest.total_bytes {
        return Err(tamper(format!(
            "sealed envelope declares {} logical bytes but the manifest totals {}",
            sealed.plaintext_bytes, bundle.manifest.total_bytes
        )));
    }
    if sealed.stored_bytes != report.stored_bytes {
        return Err(tamper(format!(
            "sealed envelope declares {} stored bytes but verification reports {}",
            sealed.stored_bytes, report.stored_bytes
        )));
    }
    if report.chunks != expected.len() as u64 {
        return Err(internal(
            "bundle verification did not cover every sealed chunk",
        ));
    }

    Ok(VerifiedTransfer {
        bundle,
        verified_chunks: report.chunks,
        manifest_hash: report.manifest_hash,
    })
}

/// Counts and bytes for a sealed envelope and its verified bundle.
///
/// A mismatch between the two is `zero.fnd.invalid_input`; the report contains
/// hashes, ids, and sizes only, never a key.
pub fn transfer_report(
    sealed: &SealedBundle,
    verified: &VerifiedTransfer,
) -> Result<TransferReport> {
    sealed.validate()?;
    if sealed.bundle_id != verified.bundle.manifest.bundle_id {
        return Err(invalid(
            "the sealed envelope and the verified bundle name different bundles",
        ));
    }
    if sealed.manifest_hash != verified.manifest_hash {
        return Err(invalid(
            "the sealed envelope and the verified bundle carry different manifest hashes",
        ));
    }

    let mut ciphertext_bytes =
        decode_b64(&sealed.manifest_ciphertext, "manifest ciphertext")?.len() as u64;
    for chunk in &sealed.chunks {
        let ciphertext = decode_b64(&chunk.ciphertext, "chunk ciphertext")?;
        ciphertext_bytes = ciphertext_bytes
            .checked_add(ciphertext.len() as u64)
            .ok_or_else(|| limit("transfer ciphertext bytes overflow their counter"))?;
    }

    Ok(TransferReport {
        bundle_id: sealed.bundle_id.clone(),
        manifest_hash: sealed.manifest_hash.clone(),
        recipient_id: sealed.recipient_id.clone(),
        chunks: verified.verified_chunks,
        plaintext_bytes: verified.bundle.manifest.total_bytes,
        stored_bytes: verified.bundle.manifest.stats().stored_bytes,
        ciphertext_bytes,
    })
}

/// Retention policy: keep the source and staging until verification succeeds.
///
/// This function never deletes anything. `verified` is `None` for a failed or
/// unfinished transfer; the report then says the source and staging are kept
/// and that cleanup is not allowed. With `Some`, cleanup is allowed but still
/// not performed; use [`retain_until_verified_with`] to opt in.
pub fn retain_until_verified(
    source_dir: &Path,
    target_dir: &Path,
    verified: Option<&VerifiedTransfer>,
) -> RetentionReport {
    RetentionReport {
        source_dir: source_dir.to_path_buf(),
        target_dir: target_dir.to_path_buf(),
        kept_source: path_exists(source_dir),
        kept_staging: path_exists(target_dir),
        can_cleanup: verified.is_some(),
    }
}

/// Retention policy with an explicit cleanup decision.
///
/// A failed transfer always keeps both paths. A verified transfer permits
/// cleanup; when `options.cleanup_source` is set the source directory is
/// removed, but only after the safety checks below. The target is never
/// removed.
///
/// Cleanup is refused when the source is a symlink, is not a directory, has no
/// parent, is the same path as the target, or contains (or is contained by) the
/// verified target. The caller must pass the disposable transfer source, not a
/// live workspace; this helper does not replace the OS trash for user data.
pub fn retain_until_verified_with(
    source_dir: &Path,
    target_dir: &Path,
    verified: Option<&VerifiedTransfer>,
    options: RetentionOptions,
) -> Result<RetentionReport> {
    let mut report = RetentionReport {
        source_dir: source_dir.to_path_buf(),
        target_dir: target_dir.to_path_buf(),
        kept_source: path_exists(source_dir),
        kept_staging: path_exists(target_dir),
        can_cleanup: verified.is_some(),
    };
    if verified.is_none() || !options.cleanup_source {
        return Ok(report);
    }

    remove_verified_source(source_dir, target_dir)?;
    report.kept_source = path_exists(source_dir);
    report.kept_staging = path_exists(target_dir);
    Ok(report)
}

fn remove_verified_source(source_dir: &Path, target_dir: &Path) -> Result<()> {
    if source_dir.as_os_str().is_empty() {
        return Err(invalid("refusing to remove an empty source path"));
    }
    let source_metadata = fs::symlink_metadata(source_dir)
        .map_err(|error| io_error(format!("cannot inspect `{}`", source_dir.display()), error))?;
    if source_metadata.file_type().is_symlink() {
        return Err(denied(format!(
            "refusing to remove `{}`: the source is a symlink",
            source_dir.display()
        )));
    }
    if !source_metadata.is_dir() {
        return Err(invalid(format!(
            "refusing to remove `{}`: the source is not a directory",
            source_dir.display()
        )));
    }
    let target_metadata = fs::symlink_metadata(target_dir)
        .map_err(|error| io_error(format!("cannot inspect `{}`", target_dir.display()), error))?;
    if target_metadata.file_type().is_symlink() || !target_metadata.is_dir() {
        return Err(invalid(format!(
            "refusing to remove `{}`: the verified target `{}` is not a directory",
            source_dir.display(),
            target_dir.display()
        )));
    }

    let source = fs::canonicalize(source_dir)
        .map_err(|error| io_error(format!("cannot resolve `{}`", source_dir.display()), error))?;
    let target = fs::canonicalize(target_dir)
        .map_err(|error| io_error(format!("cannot resolve `{}`", target_dir.display()), error))?;
    if source == target {
        return Err(denied(format!(
            "refusing to remove `{}`: source and target are the same directory",
            source_dir.display()
        )));
    }
    if target.starts_with(&source) {
        return Err(denied(format!(
            "refusing to remove `{}`: it contains the verified target",
            source_dir.display()
        )));
    }
    if source.starts_with(&target) {
        return Err(denied(format!(
            "refusing to remove `{}`: it is inside the verified target",
            source_dir.display()
        )));
    }
    if source.parent().is_none() {
        return Err(denied(format!(
            "refusing to remove `{}`: it is a filesystem root",
            source_dir.display()
        )));
    }

    fs::remove_dir_all(source_dir)
        .map_err(|error| io_error(format!("cannot remove `{}`", source_dir.display()), error))
}

struct TransferCrypto {
    hkdf: Hkdf<Sha256>,
    key: Zeroizing<[u8; AEAD_KEY_BYTES]>,
    bundle_id: [u8; 32],
}

impl TransferCrypto {
    fn derive(
        shared: &SharedSecret,
        ephemeral_public: [u8; X25519_KEY_BYTES],
        recipient_public: [u8; X25519_KEY_BYTES],
        bundle_id: [u8; 32],
    ) -> Result<Self> {
        if !shared.was_contributory() {
            return Err(denied(
                "the X25519 key agreement produced a non-contributory shared secret",
            ));
        }
        let mut salt = [0u8; X25519_KEY_BYTES * 2];
        salt[..X25519_KEY_BYTES].copy_from_slice(&ephemeral_public);
        salt[X25519_KEY_BYTES..].copy_from_slice(&recipient_public);
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
        salt.zeroize();

        let mut info = Vec::with_capacity(TRANSFER_KEY_DOMAIN.len() + bundle_id.len());
        info.extend_from_slice(TRANSFER_KEY_DOMAIN);
        info.extend_from_slice(&bundle_id);
        let mut key = Zeroizing::new([0u8; AEAD_KEY_BYTES]);
        hkdf.expand(&info, &mut *key)
            .map_err(|_| internal("cannot derive the per-bundle transfer key"))?;
        info.zeroize();
        Ok(Self {
            hkdf,
            key,
            bundle_id,
        })
    }

    fn chunk_nonce(&self, index: u64) -> Result<[u8; AEAD_NONCE_BYTES]> {
        let mut info = Vec::with_capacity(CHUNK_NONCE_DOMAIN.len() + 32 + 8);
        info.extend_from_slice(CHUNK_NONCE_DOMAIN);
        info.extend_from_slice(&self.bundle_id);
        info.extend_from_slice(&index.to_be_bytes());
        let mut nonce = [0u8; AEAD_NONCE_BYTES];
        self.hkdf
            .expand(&info, &mut nonce)
            .map_err(|_| internal("cannot derive a chunk nonce"))?;
        info.zeroize();
        Ok(nonce)
    }

    fn manifest_nonce(&self) -> Result<[u8; AEAD_NONCE_BYTES]> {
        let mut info = Vec::with_capacity(MANIFEST_NONCE_DOMAIN.len() + 32);
        info.extend_from_slice(MANIFEST_NONCE_DOMAIN);
        info.extend_from_slice(&self.bundle_id);
        let mut nonce = [0u8; AEAD_NONCE_BYTES];
        self.hkdf
            .expand(&info, &mut nonce)
            .map_err(|_| internal("cannot derive the manifest nonce"))?;
        info.zeroize();
        Ok(nonce)
    }

    fn encrypt(
        &self,
        nonce: &[u8; AEAD_NONCE_BYTES],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(&*self.key)
            .map_err(|_| internal("cannot initialise ChaCha20-Poly1305"))?;
        cipher
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| internal("ChaCha20-Poly1305 encryption failed"))
    }

    fn decrypt(
        &self,
        nonce: &[u8; AEAD_NONCE_BYTES],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(&*self.key)
            .map_err(|_| internal("cannot initialise ChaCha20-Poly1305"))?;
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| {
                tamper("transfer authentication failed: the ciphertext, tag, associated data, or key is wrong")
            })
    }
}

fn recipient_id(public: &[u8; X25519_KEY_BYTES]) -> String {
    let mut preimage = Vec::with_capacity(RECIPIENT_ID_DOMAIN.len() + public.len());
    preimage.extend_from_slice(RECIPIENT_ID_DOMAIN);
    preimage.extend_from_slice(public);
    blake3::hash(&preimage).to_hex().to_string()
}

fn manifest_aad(bundle_id: &[u8; 32], manifest_hash: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(MANIFEST_AAD_DOMAIN.len() + 64);
    aad.extend_from_slice(MANIFEST_AAD_DOMAIN);
    aad.extend_from_slice(bundle_id);
    aad.extend_from_slice(manifest_hash);
    aad
}

fn chunk_aad(bundle_id: &[u8; 32], index: u64, hash: &str) -> Result<Vec<u8>> {
    let hash = hex32(hash)?;
    let mut aad = Vec::with_capacity(CHUNK_AAD_DOMAIN.len() + 32 + 8 + 32);
    aad.extend_from_slice(CHUNK_AAD_DOMAIN);
    aad.extend_from_slice(bundle_id);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&hash);
    Ok(aad)
}

fn random_seed() -> Result<[u8; X25519_KEY_BYTES]> {
    let mut seed = [0u8; X25519_KEY_BYTES];
    getrandom::getrandom(&mut seed)
        .map_err(|error| internal(format!("cannot read random bytes: {error}")))?;
    Ok(seed)
}

fn path_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn decode_b64(text: &str, field: &str) -> Result<Vec<u8>> {
    B64.decode(text.trim())
        .map_err(|_| invalid(format!("{field} is not valid base64")))
}

fn decode_b64_exact(text: &str, length: usize, field: &str) -> Result<Vec<u8>> {
    let bytes = decode_b64(text, field)?;
    if bytes.len() != length {
        return Err(invalid(format!(
            "{field} must be {length} bytes, not {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn validate_hex64(value: &str, field: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!(
            "{field} must be 64 lower-case hex characters"
        )));
    }
    Ok(())
}

fn hex32(value: &str) -> Result<[u8; 32]> {
    validate_hex64(value, "identifier")?;
    let bytes = value.as_bytes();
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        let high = hex_nibble(bytes[index * 2])?;
        let low = hex_nibble(bytes[index * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(invalid("identifier is not lower-case hex")),
    }
}

fn denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyDenied, message)
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn tamper(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::TamperDetected, message)
}

fn limit(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

fn internal(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Internal, message)
}

fn io_error(message: impl Into<String>, error: std::io::Error) -> ZeroError {
    ZeroError::new(ErrorCode::Internal, format!("{}: {error}", message.into()))
}

type Result<T, E = ZeroError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{build, ChunkConfig, Excluded};
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    const NOW: i64 = 1_700_000_000_000;
    const RECIPIENT_SEED: [u8; 32] = [0x11; 32];
    const EPHEMERAL_SEED: [u8; 32] = [0x22; 32];

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|index| (index % 251) as u8).collect()
    }

    fn file_map(entries: &[(&str, Vec<u8>)]) -> BTreeMap<String, Vec<u8>> {
        entries
            .iter()
            .map(|(path, bytes)| ((*path).to_string(), bytes.clone()))
            .collect()
    }

    fn sample_bundle() -> Bundle {
        build(
            file_map(&[
                ("docs/notes.bin", pattern(2500)),
                ("empty.txt", Vec::new()),
                ("src/main.rs", b"fn main() {}\n".to_vec()),
            ]),
            Vec::<Excluded>::new(),
            ChunkConfig {
                chunk_bytes: 512,
                max_chunks: 4096,
            },
            NOW,
        )
        .expect("sample bundle")
    }

    fn uniform_bundle() -> Bundle {
        build(
            file_map(&[("data.bin", pattern(2048))]),
            Vec::<Excluded>::new(),
            ChunkConfig {
                chunk_bytes: 512,
                max_chunks: 64,
            },
            NOW,
        )
        .expect("uniform bundle")
    }

    fn recipient() -> RecipientSecret {
        RecipientSecret::from_seed(RECIPIENT_SEED)
    }

    fn sealed(bundle: &Bundle) -> SealedBundle {
        seal_bundle_with_seed(bundle, &recipient().recipient_key(), EPHEMERAL_SEED)
            .expect("seal bundle")
    }

    fn flip_b64(text: &str) -> String {
        let mut bytes = B64.decode(text).expect("base64");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        B64.encode(bytes)
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn derive_test_key(bundle: &Bundle) -> [u8; 32] {
        let recipient = recipient();
        let sender = StaticSecret::from(EPHEMERAL_SEED);
        let recipient_public = recipient.public_bytes();
        let shared = sender.diffie_hellman(&PublicKey::from(recipient_public));
        let ephemeral_public = PublicKey::from(&sender).to_bytes();
        let mut salt = [0u8; 64];
        salt[..32].copy_from_slice(&ephemeral_public);
        salt[32..].copy_from_slice(&recipient_public);
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
        let bundle_id = hex32(&bundle.manifest.bundle_id).expect("bundle id");
        let mut info = Vec::new();
        info.extend_from_slice(TRANSFER_KEY_DOMAIN);
        info.extend_from_slice(&bundle_id);
        let mut key = [0u8; 32];
        hkdf.expand(&info, &mut key).expect("derive key");
        key
    }

    #[test]
    fn seal_and_open_round_trip_is_byte_identical() {
        let bundle = sample_bundle();
        let envelope = sealed(&bundle);
        assert!(envelope.chunks.len() >= 3);

        let opened = open_bundle(&envelope, &recipient()).expect("open");
        assert_eq!(opened.manifest, bundle.manifest);
        assert_eq!(opened.chunks, bundle.chunks);

        let verified = open_bundle_verified(&envelope, &recipient()).expect("verify");
        assert_eq!(verified.bundle, bundle);
        assert_eq!(verified.verified_chunks, bundle.chunks.len() as u64);
        assert_eq!(
            verified.manifest_hash,
            crate::bundle::manifest_hash(&bundle.manifest).expect("manifest hash")
        );

        let json = serde_json::to_string(&envelope).expect("json");
        assert!(!json.contains("fn main"));
        assert!(!json.contains("pattern"));
    }

    #[test]
    fn an_empty_bundle_round_trips() {
        let bundle = build(
            BTreeMap::new(),
            Vec::<Excluded>::new(),
            ChunkConfig::default(),
            NOW,
        )
        .expect("empty bundle");
        let envelope = sealed(&bundle);
        assert!(envelope.chunks.is_empty());
        assert_eq!(envelope.plaintext_bytes, 0);
        assert_eq!(envelope.stored_bytes, 0);
        assert_eq!(open_bundle(&envelope, &recipient()).expect("open"), bundle);
    }

    #[test]
    fn a_wrong_recipient_key_is_refused() {
        let bundle = sample_bundle();
        let envelope = sealed(&bundle);
        let other = RecipientSecret::from_seed([0x33; 32]);
        let error = open_bundle(&envelope, &other).expect_err("wrong recipient");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("sealed for recipient"));
        assert!(open_bundle_verified(&envelope, &other).is_err());
    }

    #[test]
    fn tampered_ciphertext_or_tag_is_refused() {
        let bundle = sample_bundle();

        let mut tag = sealed(&bundle);
        tag.chunks[0].ciphertext = flip_b64(&tag.chunks[0].ciphertext);
        assert_eq!(
            open_bundle(&tag, &recipient())
                .expect_err("tampered tag")
                .code(),
            ErrorCode::TamperDetected
        );

        let mut body = sealed(&bundle);
        let mut bytes = B64.decode(&body.chunks[1].ciphertext).expect("base64");
        bytes[0] ^= 0x80;
        body.chunks[1].ciphertext = B64.encode(bytes);
        assert_eq!(
            open_bundle(&body, &recipient())
                .expect_err("tampered body")
                .code(),
            ErrorCode::TamperDetected
        );

        let mut manifest = sealed(&bundle);
        manifest.manifest_ciphertext = flip_b64(&manifest.manifest_ciphertext);
        assert_eq!(
            open_bundle(&manifest, &recipient())
                .expect_err("tampered manifest")
                .code(),
            ErrorCode::TamperDetected
        );

        let mut nonce = sealed(&bundle);
        nonce.chunks[0].nonce = B64.encode([0u8; AEAD_NONCE_BYTES]);
        assert_eq!(
            open_bundle(&nonce, &recipient())
                .expect_err("changed nonce")
                .code(),
            ErrorCode::TamperDetected
        );
    }

    #[test]
    fn a_truncated_or_missing_chunk_is_refused() {
        let bundle = sample_bundle();

        let mut missing = sealed(&bundle);
        missing.chunks.pop();
        assert_eq!(
            open_bundle(&missing, &recipient())
                .expect_err("missing chunk")
                .code(),
            ErrorCode::TamperDetected
        );

        let mut truncated = sealed(&bundle);
        let bytes = B64.decode(&truncated.chunks[0].ciphertext).expect("base64");
        truncated.chunks[0].ciphertext = B64.encode(&bytes[..bytes.len() - 1]);
        assert_eq!(
            truncated.validate().expect_err("truncated chunk").code(),
            ErrorCode::TamperDetected
        );
        assert_eq!(
            open_bundle(&truncated, &recipient())
                .expect_err("truncated chunk")
                .code(),
            ErrorCode::TamperDetected
        );

        let mut extra = sealed(&bundle);
        let duplicate = extra.chunks[0].clone();
        extra.chunks.push(duplicate);
        assert_eq!(
            extra.validate().expect_err("duplicate chunk").code(),
            ErrorCode::TamperDetected
        );
    }

    #[test]
    fn a_manifest_hash_or_bundle_id_mismatch_is_refused() {
        let bundle = sample_bundle();

        let mut wrong_hash = sealed(&bundle);
        wrong_hash.manifest_hash = "0".repeat(64);
        assert_eq!(
            open_bundle(&wrong_hash, &recipient())
                .expect_err("manifest hash")
                .code(),
            ErrorCode::TamperDetected
        );

        let mut wrong_id = sealed(&bundle);
        wrong_id.bundle_id = "0".repeat(64);
        assert_eq!(
            open_bundle(&wrong_id, &recipient())
                .expect_err("bundle id")
                .code(),
            ErrorCode::TamperDetected
        );
    }

    #[test]
    fn nonces_are_unique_per_chunk_and_derived_deterministically() {
        let bundle = uniform_bundle();
        let first = sealed(&bundle);
        assert!(first.chunks.len() >= 4);

        let mut nonces = BTreeSet::new();
        for chunk in &first.chunks {
            assert!(nonces.insert(chunk.nonce.clone()), "nonce reused");
        }
        assert!(!nonces.contains(&first.manifest_nonce));

        let second = seal_bundle_with_seed(&bundle, &recipient().recipient_key(), EPHEMERAL_SEED)
            .expect("seal again");
        assert_eq!(first, second, "the same seed is reproducible");

        let other = build(
            file_map(&[("other.bin", pattern(2048))]),
            Vec::<Excluded>::new(),
            ChunkConfig {
                chunk_bytes: 512,
                max_chunks: 64,
            },
            NOW + 1,
        )
        .expect("other bundle");
        let other = seal_bundle_with_seed(&other, &recipient().recipient_key(), EPHEMERAL_SEED)
            .expect("seal other");
        assert_ne!(first.chunks[0].nonce, other.chunks[0].nonce);
    }

    #[test]
    fn aad_binding_refuses_a_reordered_chunk() {
        let bundle = uniform_bundle();
        let mut envelope = sealed(&bundle);
        assert_eq!(envelope.chunks[0].bytes, envelope.chunks[1].bytes);

        let first = envelope.chunks[0].ciphertext.clone();
        envelope.chunks[0].ciphertext = envelope.chunks[1].ciphertext.clone();
        envelope.chunks[1].ciphertext = first;
        assert!(envelope.validate().is_ok());
        assert_eq!(
            open_bundle(&envelope, &recipient())
                .expect_err("swapped ciphertexts")
                .code(),
            ErrorCode::TamperDetected
        );

        let mut swapped = sealed(&bundle);
        swapped.chunks.swap(0, 1);
        assert_eq!(
            open_bundle(&swapped, &recipient())
                .expect_err("swapped order")
                .code(),
            ErrorCode::TamperDetected
        );
    }

    #[test]
    fn a_wrong_plaintext_hash_is_refused() {
        let bundle = sample_bundle();
        let mut envelope = sealed(&bundle);
        envelope.chunks[0].chunk_hash = "0".repeat(64);
        assert_eq!(
            open_bundle(&envelope, &recipient())
                .expect_err("wrong hash")
                .code(),
            ErrorCode::TamperDetected
        );
    }

    #[test]
    fn a_corrupted_chunk_fails_verification() {
        let bundle = uniform_bundle();
        let mut envelope = sealed(&bundle);
        envelope.chunks[2].ciphertext = flip_b64(&envelope.chunks[2].ciphertext);

        let target = TempDir::new().expect("target");
        let error = open_bundle_verified(&envelope, &recipient())
            .expect_err("a corrupted chunk fails verification");
        assert_eq!(error.code(), ErrorCode::TamperDetected);
        assert_eq!(
            fs::read_dir(target.path()).expect("read target").count(),
            0,
            "a failed open must not materialize anything"
        );
    }

    #[test]
    fn debug_and_errors_never_expose_key_material() {
        let bundle = sample_bundle();
        let envelope = sealed(&bundle);
        let key = derive_test_key(&bundle);
        let key_hex = hex_encode(&key);
        let key_b64 = B64.encode(key);

        let debug = format!("{envelope:?}");
        assert!(!debug.contains(&key_hex), "{debug}");
        assert!(!debug.contains(&key_b64), "{debug}");
        assert!(!debug.contains(&hex_encode(&RECIPIENT_SEED)), "{debug}");
        assert!(!debug.contains(&hex_encode(&EPHEMERAL_SEED)), "{debug}");
        assert!(!debug.contains("fn main"), "{debug}");
        assert!(debug.contains(&bundle.manifest.bundle_id));

        let json = serde_json::to_string(&envelope).expect("json");
        assert!(!json.contains(&key_hex), "{json}");
        assert!(!json.contains(&hex_encode(&RECIPIENT_SEED)), "{json}");
        assert!(!json.contains("fn main"), "{json}");

        let recipient_debug = format!("{:?}", recipient());
        assert!(recipient_debug.contains("redacted"));
        assert!(!recipient_debug.contains(&hex_encode(&RECIPIENT_SEED)));

        let sender_debug = format!("{:?}", SenderSecret::from_seed(EPHEMERAL_SEED));
        assert!(sender_debug.contains("redacted"));
        assert!(!sender_debug.contains(&hex_encode(&EPHEMERAL_SEED)));

        let wrong = RecipientSecret::from_seed([0x33; 32]);
        let error = open_bundle(&envelope, &wrong).expect_err("wrong recipient");
        assert!(!error.message().contains(&key_hex));
        assert!(!error.message().contains(&hex_encode(&RECIPIENT_SEED)));
        assert!(!error.message().contains("fn main"));
    }

    #[test]
    fn sealed_envelopes_survive_serde_without_plaintext() {
        let bundle = sample_bundle();
        let envelope = sealed(&bundle);
        let json = serde_json::to_string(&envelope).expect("serialise");
        assert!(!json.contains("fn main"));
        assert!(!json.contains("\"plaintext\""));
        assert!(!json.contains("manifest_plaintext"));
        assert!(!json.contains("shared_secret"));
        assert!(!json.contains("\"key\""));

        let restored: SealedBundle = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(restored, envelope);
        assert_eq!(open_bundle(&restored, &recipient()).expect("open"), bundle);
    }

    #[test]
    fn recipient_keys_round_trip_through_base64_and_ids() {
        let recipient = RecipientSecret::from_seed(RECIPIENT_SEED);
        let key = recipient.recipient_key();
        let parsed = RecipientKey::from_base64(&key.public_b64()).expect("parse");
        assert_eq!(parsed, key);
        assert_eq!(parsed.recipient_id(), key.recipient_id());
        assert_eq!(parsed.recipient_id().len(), RECIPIENT_ID_HEX);
        assert_eq!(
            RecipientKey::from_base64("not-base64")
                .expect_err("bad base64")
                .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            RecipientKey::from_base64(&B64.encode([0u8; 3]))
                .expect_err("short key")
                .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn transfer_report_counts_chunks_and_bytes_without_keys() {
        let bundle = uniform_bundle();
        let envelope = sealed(&bundle);
        let verified = open_bundle_verified(&envelope, &recipient()).expect("verify");
        let report = transfer_report(&envelope, &verified).expect("report");
        assert_eq!(report.bundle_id, bundle.manifest.bundle_id);
        assert_eq!(report.manifest_hash, verified.manifest_hash);
        assert_eq!(report.recipient_id, envelope.recipient_id);
        assert_eq!(report.chunks, bundle.chunks.len() as u64);
        assert_eq!(report.plaintext_bytes, bundle.manifest.total_bytes);
        assert_eq!(report.stored_bytes, bundle.stats().stored_bytes);
        assert!(report.ciphertext_bytes > report.stored_bytes);
        assert!(!format!("{report:?}").contains(&hex_encode(&derive_test_key(&bundle))));

        let other = open_bundle_verified(&sealed(&sample_bundle()), &recipient()).expect("verify");
        assert_eq!(
            transfer_report(&envelope, &other)
                .expect_err("mismatched pair")
                .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn schema_limits_and_nonce_reuse_are_typed() {
        let bundle = uniform_bundle();

        let mut schema = sealed(&bundle);
        schema.schema_version = 2;
        assert_eq!(
            schema.validate().expect_err("schema").code(),
            ErrorCode::SchemaVersion
        );

        let mut empty = sealed(&bundle);
        empty.chunks[0].bytes = 0;
        assert_eq!(
            empty.validate().expect_err("empty chunk").code(),
            ErrorCode::InvalidInput
        );

        let mut oversized = sealed(&bundle);
        oversized.chunks[0].bytes = bundle::MAX_CHUNK_BYTES as u64 + 1;
        assert_eq!(
            oversized.validate().expect_err("oversized chunk").code(),
            ErrorCode::LimitExceeded
        );

        let mut reuse = sealed(&bundle);
        reuse.chunks[1].nonce = reuse.chunks[0].nonce.clone();
        assert_eq!(
            reuse.validate().expect_err("nonce reuse").code(),
            ErrorCode::TamperDetected
        );

        let mut unordered = sealed(&bundle);
        unordered.chunks[1].chunk_hash = unordered.chunks[0].chunk_hash.clone();
        assert_eq!(
            unordered.validate().expect_err("chunk order").code(),
            ErrorCode::TamperDetected
        );
    }

    #[test]
    fn retention_keeps_source_on_failure_and_permits_cleanup_only_after_verify() {
        let root = TempDir::new().expect("root");
        let source = root.path().join("source");
        let target = root.path().join("target");
        fs::create_dir(&source).expect("source");
        fs::write(source.join("bundle.json"), b"sealed").expect("source file");
        fs::create_dir(&target).expect("target");
        fs::write(target.join("file.txt"), b"restored").expect("target file");

        let failed = retain_until_verified(&source, &target, None);
        assert!(failed.kept_source);
        assert!(failed.kept_staging);
        assert!(!failed.can_cleanup);
        assert!(source.exists());
        assert!(target.exists());

        let bundle = sample_bundle();
        let verified = open_bundle_verified(&sealed(&bundle), &recipient()).expect("verify");

        let after = retain_until_verified(&source, &target, Some(&verified));
        assert!(after.kept_source);
        assert!(after.kept_staging);
        assert!(after.can_cleanup);
        assert!(source.exists());
        assert!(target.exists());

        let failed_cleanup = retain_until_verified_with(
            &source,
            &target,
            None,
            RetentionOptions {
                cleanup_source: true,
            },
        )
        .expect("failure policy");
        assert!(!failed_cleanup.can_cleanup);
        assert!(failed_cleanup.kept_source);
        assert!(source.exists());

        let cleaned = retain_until_verified_with(
            &source,
            &target,
            Some(&verified),
            RetentionOptions {
                cleanup_source: true,
            },
        )
        .expect("verified cleanup");
        assert!(cleaned.can_cleanup);
        assert!(!cleaned.kept_source);
        assert!(cleaned.kept_staging);
        assert!(!source.exists());
        assert!(target.exists());
    }

    #[test]
    fn cleanup_refuses_a_nested_or_identical_target() {
        let root = TempDir::new().expect("root");
        let source = root.path().join("source");
        let target = source.join("target");
        fs::create_dir_all(&target).expect("nested dirs");
        fs::write(target.join("file.txt"), b"restored").expect("target file");

        let bundle = sample_bundle();
        let verified = open_bundle_verified(&sealed(&bundle), &recipient()).expect("verify");
        let options = RetentionOptions {
            cleanup_source: true,
        };

        let error = retain_until_verified_with(&source, &target, Some(&verified), options)
            .expect_err("nested target");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(source.exists());

        let error = retain_until_verified_with(&source, &source, Some(&verified), options)
            .expect_err("same path");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(source.exists());
    }
}
