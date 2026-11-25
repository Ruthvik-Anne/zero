//! Vault ciphertext over teleport (T-TEL-07, TEL-07, SEC-11).
//!
//! [`seal_vault`] turns opaque vault bytes into a [`VaultEnvelope`]: an
//! Argon2id-derived AES-256-GCM ciphertext with a random salt, a random
//! 96-bit nonce, and an associated-data block that authenticates the KDF
//! parameters and carries a passphrase key check. The envelope has no
//! plaintext field, no key field, and no accessor that decrypts without an
//! [`UnlockRequest`].
//!
//! [`unlock_vault`] enforces the TEL-07 rule: **one unlock per transfer**. An
//! [`UnlockState`] records each envelope id that has been unlocked, and a
//! second unlock of the same envelope is refused with `zero.pol.denied` even
//! when the passphrase is correct. A missing, empty, expired, or incorrect
//! unlock returns `zero.pol.ask` and no plaintext, so the target can never
//! decrypt silently. A damaged ciphertext or a damaged associated-data body is
//! `zero.tru.tamper`.
//!
//! [`wrap_for_transfer`] moves only the envelope through the existing
//! [`transfer`](crate::transfer) seal: the relay sees a `SealedBundle` of
//! envelope ciphertext, never the vault bytes and never the passphrase.
//! [`receive`] opens that sealed bundle with the recipient secret and then
//! performs the same single unlock.
//!
//! `zero-mesh` depends on `zero-secrets` for the vault format but not for a
//! key: the vault bytes are opaque here, and this module never reads a tag,
//! a scope, or a value out of them.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, ZeroError};
use zeroize::Zeroizing;

use crate::bundle::{self, ChunkConfig, Excluded};
use crate::transfer::{
    open_bundle_verified, seal_bundle, RecipientKey, RecipientSecret, SealedBundle,
    VerifiedTransfer,
};

/// Vault envelope schema this build reads and writes.
pub const VAULT_SCHEMA_VERSION: u32 = 1;

/// Length of the AES-256-GCM key, in bytes.
pub const VAULT_KEY_BYTES: usize = 32;

/// Length of the AES-256-GCM nonce, in bytes.
pub const VAULT_NONCE_BYTES: usize = 12;

/// Length of the AES-256-GCM authentication tag, in bytes.
pub const VAULT_TAG_BYTES: usize = 16;

/// Length of the random Argon2id salt, in bytes.
pub const VAULT_SALT_BYTES: usize = 16;

/// Domain separator for the associated data.
pub const VAULT_AAD_DOMAIN: &[u8] = b"zero.teleport.vault.aad.v1\0";

/// Domain separator for the envelope id.
pub const VAULT_ENVELOPE_ID_DOMAIN: &[u8] = b"zero.teleport.vault.envelope-id.v1\0";

/// Largest vault plaintext this module will seal or open.
pub const MAX_VAULT_BYTES: usize = 64 * 1024 * 1024;

/// Default Argon2id memory cost, in KiB (19 MiB, the OWASP baseline).
pub const DEFAULT_M_COST: u32 = 19_456;

/// Default Argon2id time cost.
pub const DEFAULT_T_COST: u32 = 2;

/// Default Argon2id parallelism.
pub const DEFAULT_P_COST: u32 = 1;

/// Longest transfer approval this module accepts.
pub const MAX_APPROVAL_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// Longest approval label, in bytes.
pub const MAX_APPROVAL_ID_BYTES: usize = 128;

/// File name the envelope travels under inside the transfer bundle.
pub const VAULT_ENVELOPE_FILE: &str = "vault.envelope.json";

/// Argon2id cost parameters for [`seal_vault_with_kdf`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfOptions {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Time cost (iterations).
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub p_cost: u32,
}

impl Default for KdfOptions {
    fn default() -> Self {
        Self {
            m_cost: DEFAULT_M_COST,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }
}

/// The Argon2id parameters recorded in the envelope.
///
/// The salt is public; the passphrase and the derived key are not part of this
/// type. [`Debug`] prints the cost parameters and the salt length only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfParams {
    /// Random salt, 16 bytes for a sealed envelope.
    pub salt: Vec<u8>,
    /// Argon2id memory cost in KiB.
    pub m_cost: u32,
    /// Argon2id time cost.
    pub t_cost: u32,
    /// Argon2id parallelism.
    pub p_cost: u32,
}

impl fmt::Debug for KdfParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KdfParams")
            .field("algorithm", &"argon2id")
            .field("salt_len", &self.salt.len())
            .field("m_cost", &self.m_cost)
            .field("t_cost", &self.t_cost)
            .field("p_cost", &self.p_cost)
            .finish()
    }
}

/// The encrypted vault that travels between devices.
///
/// Only `ciphertext` carries vault content, and it is AES-256-GCM ciphertext
/// including its authentication tag. `aad` is
/// `VAULT_AAD_DOMAIN || key_check`, where `key_check` is the second half of the
/// Argon2id output; it lets an unlock tell a wrong passphrase (a prompt) from a
/// damaged ciphertext (tamper). There is no plaintext field and no key field,
/// and [`Debug`] prints lengths and the envelope id only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultEnvelope {
    /// Envelope schema version.
    pub schema_version: u32,
    /// AES-256-GCM ciphertext including its 16-byte tag.
    pub ciphertext: Vec<u8>,
    /// The Argon2id parameters, including the random salt.
    pub kdf: KdfParams,
    /// The random 96-bit AES-GCM nonce.
    pub nonce: Vec<u8>,
    /// Associated data: the domain separator followed by the passphrase check.
    pub aad: Vec<u8>,
    /// Caller clock, milliseconds since the epoch.
    pub created_ms: i64,
}

impl VaultEnvelope {
    /// The lower-case hex id of this envelope.
    ///
    /// The id covers the schema, clock, KDF parameters, nonce, associated data,
    /// and ciphertext. A new seal (new salt and nonce) therefore has a new id,
    /// which is the boundary for the one-unlock rule.
    pub fn envelope_id(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(VAULT_ENVELOPE_ID_DOMAIN);
        hasher.update(&self.schema_version.to_be_bytes());
        hasher.update(&self.created_ms.to_be_bytes());
        hasher.update(&self.kdf.salt);
        hasher.update(&self.kdf.m_cost.to_be_bytes());
        hasher.update(&self.kdf.t_cost.to_be_bytes());
        hasher.update(&self.kdf.p_cost.to_be_bytes());
        hasher.update(&self.nonce);
        hasher.update(&self.aad);
        hasher.update(&self.ciphertext);
        hasher.finalize().to_hex().to_string()
    }

    /// The ciphertext length on the wire, including the tag.
    pub fn ciphertext_bytes(&self) -> usize {
        self.ciphertext.len()
    }

    /// Validate the envelope shape without a passphrase or a key.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != VAULT_SCHEMA_VERSION {
            return Err(ZeroError::new(
                ErrorCode::SchemaVersion,
                format!(
                    "vault envelope schema version {} is not supported; this build reads {VAULT_SCHEMA_VERSION}",
                    self.schema_version
                ),
            ));
        }
        if self.kdf.salt.len() < 8 || self.kdf.salt.len() > 64 {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                "vault KDF salt must be between 8 and 64 bytes",
            ));
        }
        Params::new(self.kdf.m_cost, self.kdf.t_cost, self.kdf.p_cost, Some(64)).map_err(|_| {
            ZeroError::new(ErrorCode::InvalidInput, "vault KDF parameters are invalid")
        })?;
        if self.nonce.len() != VAULT_NONCE_BYTES {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                format!("vault nonce must be {VAULT_NONCE_BYTES} bytes"),
            ));
        }
        let expected_aad = VAULT_AAD_DOMAIN.len() + VAULT_KEY_BYTES;
        if self.aad.len() != expected_aad || !self.aad.starts_with(VAULT_AAD_DOMAIN) {
            return Err(tamper("vault associated data has an unexpected shape"));
        }
        if self.ciphertext.len() <= VAULT_TAG_BYTES {
            return Err(tamper(
                "vault ciphertext is shorter than its authentication tag",
            ));
        }
        if self.ciphertext.len() > MAX_VAULT_BYTES + VAULT_TAG_BYTES {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "vault ciphertext is {} bytes; the limit is {}",
                    self.ciphertext.len(),
                    MAX_VAULT_BYTES + VAULT_TAG_BYTES
                ),
            ));
        }
        Ok(())
    }

    fn key_check(&self) -> &[u8] {
        &self.aad[VAULT_AAD_DOMAIN.len()..]
    }
}

impl fmt::Debug for VaultEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultEnvelope")
            .field("schema_version", &self.schema_version)
            .field("envelope_id", &self.envelope_id())
            .field("ciphertext_len", &self.ciphertext.len())
            .field("kdf", &self.kdf)
            .field("nonce_len", &self.nonce.len())
            .field("aad_len", &self.aad.len())
            .field("created_ms", &self.created_ms)
            .finish()
    }
}

/// A decrypted vault that is zeroized when dropped.
///
/// There is no `Debug` output for the bytes. The caller must consume the value
/// deliberately with [`bytes`](Self::bytes) or [`into_bytes`](Self::into_bytes).
pub struct UnlockedVault {
    envelope_id: String,
    plaintext: Zeroizing<Vec<u8>>,
}

impl UnlockedVault {
    /// The envelope this plaintext came from.
    pub fn envelope_id(&self) -> &str {
        &self.envelope_id
    }

    /// The decrypted vault bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.plaintext
    }

    /// The decrypted vault bytes, still zeroized on drop.
    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.plaintext
    }

    /// The plaintext length in bytes.
    pub fn len(&self) -> usize {
        self.plaintext.len()
    }

    /// Whether the decrypted vault is empty.
    pub fn is_empty(&self) -> bool {
        self.plaintext.is_empty()
    }
}

impl fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("envelope_id", &self.envelope_id)
            .field("bytes_len", &self.plaintext.len())
            .finish()
    }
}

/// A host-issued capability to unlock one envelope without re-entering the
/// passphrase.
///
/// It holds the derived key in a [`Zeroizing`] buffer, is not `Clone`, and has
/// no `Serialize` implementation, so the key cannot be written to a log, a
/// bundle, or an envelope through this type. It is bound to exactly one
/// envelope id and carries a caller-clock expiry. [`Debug`] prints the ids and
/// expiry only.
pub struct TransferApproval {
    approval_id: String,
    envelope_id: String,
    expires_ms: i64,
    key: Zeroizing<[u8; VAULT_KEY_BYTES]>,
}

impl TransferApproval {
    /// The caller-supplied approval label.
    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }

    /// The envelope this approval is bound to.
    pub fn envelope_id(&self) -> &str {
        &self.envelope_id
    }

    /// The caller-clock expiry.
    pub fn expires_ms(&self) -> i64 {
        self.expires_ms
    }
}

impl fmt::Debug for TransferApproval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransferApproval")
            .field("approval_id", &self.approval_id)
            .field("envelope_id", &self.envelope_id)
            .field("expires_ms", &self.expires_ms)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// What unlocks the vault.
///
/// `Passphrase` is the target's re-entry. `ApprovedTransfer` names an approval
/// previously registered with [`UnlockState::register_approval`]; the approval
/// must be bound to this envelope and must not have expired. The passphrase
/// string is zeroized after the attempt; [`Debug`] never prints it.
pub enum UnlockRequest {
    /// Re-enter the vault passphrase on the target.
    Passphrase(String),
    /// Use an approval issued for this envelope.
    ApprovedTransfer {
        /// The approval label registered with the unlock state.
        approval_id: String,
    },
}

impl UnlockRequest {
    /// Build a passphrase request.
    pub fn passphrase(passphrase: impl Into<String>) -> Self {
        Self::Passphrase(passphrase.into())
    }

    /// Build an approved-transfer request.
    pub fn approved_transfer(approval_id: impl Into<String>) -> Self {
        Self::ApprovedTransfer {
            approval_id: approval_id.into(),
        }
    }
}

impl fmt::Debug for UnlockRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Passphrase(_) => f.write_str("Passphrase(<redacted>)"),
            Self::ApprovedTransfer { approval_id } => f
                .debug_struct("ApprovedTransfer")
                .field("approval_id", approval_id)
                .finish(),
        }
    }
}

/// Tracks the one-unlock-per-transfer rule and the approvals a target holds.
///
/// The state is a value; the caller keeps it for the lifetime of the transfer.
/// It records only envelope ids and approvals, never plaintext or a passphrase.
#[derive(Default)]
pub struct UnlockState {
    consumed: BTreeSet<String>,
    approvals: BTreeMap<String, TransferApproval>,
}

impl UnlockState {
    /// A fresh target-side state with nothing unlocked.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an approval issued by [`issue_approval`].
    ///
    /// A duplicate label is refused so one label never silently shadows
    /// another.
    pub fn register_approval(&mut self, approval: TransferApproval) -> Result<()> {
        if self.approvals.contains_key(&approval.approval_id) {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                format!("approval `{}` is already registered", approval.approval_id),
            ));
        }
        self.approvals
            .insert(approval.approval_id.clone(), approval);
        Ok(())
    }

    /// Whether this envelope has already been unlocked.
    pub fn is_consumed(&self, envelope_id: &str) -> bool {
        self.consumed.contains(envelope_id)
    }

    /// How many envelopes this state has unlocked.
    pub fn consumed_count(&self) -> usize {
        self.consumed.len()
    }

    /// Unlock an envelope once. See [`unlock_vault`].
    pub fn unlock(
        &mut self,
        envelope: &VaultEnvelope,
        request: UnlockRequest,
        now_ms: i64,
    ) -> Result<UnlockedVault> {
        unlock_vault(self, envelope, request, now_ms)
    }
}

/// Seal opaque vault bytes under `passphrase` with Argon2id and AES-256-GCM.
///
/// A fresh 16-byte salt and 96-bit nonce come from the operating system's
/// entropy. The derived key is split: the first half encrypts, the second half
/// is the key check embedded in the associated data. The plaintext and the
/// derived key are zeroized before the call returns; the caller's input buffer
/// is the caller's responsibility.
pub fn seal_vault(
    plaintext_vault_bytes: &[u8],
    passphrase: &str,
    now_ms: i64,
) -> Result<VaultEnvelope> {
    seal_vault_with_kdf(
        plaintext_vault_bytes,
        passphrase,
        now_ms,
        KdfOptions::default(),
    )
}

/// [`seal_vault`] with explicit Argon2id cost parameters.
///
/// Use this for tests and for a caller with a documented cost policy. The salt
/// and nonce are still fresh for every call.
pub fn seal_vault_with_kdf(
    plaintext_vault_bytes: &[u8],
    passphrase: &str,
    now_ms: i64,
    kdf: KdfOptions,
) -> Result<VaultEnvelope> {
    if passphrase.is_empty() {
        return Err(ZeroError::new(
            ErrorCode::InvalidInput,
            "a vault passphrase must not be empty",
        ));
    }
    if plaintext_vault_bytes.len() > MAX_VAULT_BYTES {
        return Err(ZeroError::new(
            ErrorCode::LimitExceeded,
            format!(
                "vault is {} bytes; the limit is {MAX_VAULT_BYTES}",
                plaintext_vault_bytes.len()
            ),
        ));
    }
    Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(64))
        .map_err(|_| ZeroError::new(ErrorCode::InvalidInput, "vault KDF parameters are invalid"))?;

    let mut salt = vec![0u8; VAULT_SALT_BYTES];
    getrandom::getrandom(&mut salt)
        .map_err(|error| internal(format!("cannot read the vault salt: {error}")))?;
    let params = KdfParams {
        salt: salt.clone(),
        m_cost: kdf.m_cost,
        t_cost: kdf.t_cost,
        p_cost: kdf.p_cost,
    };

    let mut nonce = [0u8; VAULT_NONCE_BYTES];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| internal(format!("cannot read the vault nonce: {error}")))?;

    let derived = derive_key(passphrase.as_bytes(), &params)?;
    let mut aad = Vec::with_capacity(VAULT_AAD_DOMAIN.len() + VAULT_KEY_BYTES);
    aad.extend_from_slice(VAULT_AAD_DOMAIN);
    aad.extend_from_slice(&derived.check);
    let ciphertext = encrypt(&derived.enc, &nonce, plaintext_vault_bytes, &aad)?;

    Ok(VaultEnvelope {
        schema_version: VAULT_SCHEMA_VERSION,
        ciphertext,
        kdf: params,
        nonce: nonce.to_vec(),
        aad,
        created_ms: now_ms,
    })
}

/// Issue a one-envelope approval without moving a serialized key.
///
/// The function re-derives the key from `passphrase`, so a wrong passphrase is
/// `zero.pol.ask` and no approval is produced. The returned value is kept in
/// memory and registered with the target's [`UnlockState`]; it is a bearer
/// capability for this envelope until its caller-clock expiry and must travel
/// only through the authenticated channel, never through a log.
pub fn issue_approval(
    envelope: &VaultEnvelope,
    passphrase: &str,
    approval_id: impl Into<String>,
    now_ms: i64,
    ttl_ms: i64,
) -> Result<TransferApproval> {
    envelope.validate()?;
    let approval_id = approval_id.into();
    if approval_id.is_empty() || approval_id.len() > MAX_APPROVAL_ID_BYTES {
        return Err(ZeroError::new(
            ErrorCode::InvalidInput,
            format!("an approval id must be 1..={MAX_APPROVAL_ID_BYTES} bytes"),
        ));
    }
    if approval_id.chars().any(char::is_control) {
        return Err(ZeroError::new(
            ErrorCode::InvalidInput,
            "an approval id must not contain control characters",
        ));
    }
    if ttl_ms <= 0 || ttl_ms > MAX_APPROVAL_TTL_MS {
        return Err(ZeroError::new(
            ErrorCode::InvalidInput,
            format!("an approval ttl must be 1..={MAX_APPROVAL_TTL_MS} ms"),
        ));
    }
    if passphrase.is_empty() {
        return Err(prompt_required(
            "the vault is locked; a passphrase is required to approve its transfer",
        ));
    }
    let derived = derive_key(passphrase.as_bytes(), &envelope.kdf)?;
    if !constant_time_eq(&derived.check, envelope.key_check()) {
        return Err(prompt_required(
            "the passphrase is not the one for this vault; prompt the user to re-enter it",
        ));
    }
    let expires_ms = now_ms
        .checked_add(ttl_ms)
        .ok_or_else(|| ZeroError::new(ErrorCode::LimitExceeded, "approval expiry overflows"))?;
    Ok(TransferApproval {
        approval_id,
        envelope_id: envelope.envelope_id(),
        expires_ms,
        key: derived.enc,
    })
}

/// Unlock a vault envelope exactly once.
///
/// Order of checks:
///
/// 1. the envelope shape ([`VaultEnvelope::validate`]);
/// 2. this state has not already unlocked this envelope id
///    (`zero.pol.denied`, the one-unlock rule);
/// 3. the request resolves to a key: a passphrase is derived with Argon2id and
///    checked against the envelope's key check; an approval must be registered,
///    bound to this envelope, and unexpired;
/// 4. a wrong, empty, or missing secret is `zero.pol.ask` and no plaintext;
/// 5. AES-256-GCM authenticates the ciphertext and associated data
///    (`zero.tru.tamper` on failure);
/// 6. the envelope id is marked consumed and the plaintext is returned.
pub fn unlock_vault(
    state: &mut UnlockState,
    envelope: &VaultEnvelope,
    request: UnlockRequest,
    now_ms: i64,
) -> Result<UnlockedVault> {
    envelope.validate()?;
    let envelope_id = envelope.envelope_id();
    if state.consumed.contains(&envelope_id) {
        return Err(ZeroError::new(
            ErrorCode::PolicyDenied,
            "this vault envelope was already unlocked; one unlock is allowed per transfer",
        ));
    }

    let mut approval_to_remove: Option<String> = None;
    let key: Zeroizing<[u8; VAULT_KEY_BYTES]> = match request {
        UnlockRequest::Passphrase(passphrase) => {
            let passphrase = Zeroizing::new(passphrase);
            if passphrase.is_empty() {
                return Err(prompt_required(
                    "the vault is locked; a passphrase is required to unlock it",
                ));
            }
            let derived = derive_key(passphrase.as_bytes(), &envelope.kdf)?;
            if !constant_time_eq(&derived.check, envelope.key_check()) {
                return Err(prompt_required(
                    "the passphrase is not the one for this vault; prompt the user to re-enter it",
                ));
            }
            derived.enc
        }
        UnlockRequest::ApprovedTransfer { approval_id } => {
            let approval = state.approvals.get(&approval_id).ok_or_else(|| {
                prompt_required(
                    "an approval is required to unlock this vault; prompt the user or register a transfer approval",
                )
            })?;
            if approval.envelope_id != envelope_id {
                return Err(ZeroError::new(
                    ErrorCode::PolicyDenied,
                    "this approval is bound to a different vault envelope",
                ));
            }
            if now_ms >= approval.expires_ms {
                return Err(ZeroError::new(
                    ErrorCode::ApprovalExpired,
                    "the transfer approval expired; request a fresh approval",
                ));
            }
            approval_to_remove = Some(approval_id);
            Zeroizing::new(*approval.key)
        }
    };

    let nonce: [u8; VAULT_NONCE_BYTES] = envelope
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| tamper("vault nonce has the wrong length"))?;
    let plaintext = decrypt(&key, &nonce, &envelope.ciphertext, &envelope.aad)?;

    state.consumed.insert(envelope_id.clone());
    if let Some(approval_id) = approval_to_remove {
        state.approvals.remove(&approval_id);
    }
    Ok(UnlockedVault {
        envelope_id,
        plaintext: Zeroizing::new(plaintext),
    })
}

/// The vault envelope inside a sealed transfer.
///
/// [`Debug`] prints the envelope id and the sealed envelope's redacted summary;
/// there is no accessor for vault plaintext and no passphrase field.
pub struct SealedVault {
    envelope_id: String,
    sealed: SealedBundle,
}

impl SealedVault {
    /// The id of the envelope this sealed transfer carries.
    pub fn envelope_id(&self) -> &str {
        &self.envelope_id
    }

    /// The sealed transfer envelope a relay forwards.
    pub fn sealed(&self) -> &SealedBundle {
        &self.sealed
    }

    /// Ciphertext bytes on the wire (the JSON form of the sealed envelope).
    pub fn sealed_bytes(&self) -> Result<u64> {
        let encoded = serde_json::to_vec(&self.sealed)
            .map_err(|error| internal(format!("cannot size the sealed vault: {error}")))?;
        Ok(encoded.len() as u64)
    }
}

impl fmt::Debug for SealedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedVault")
            .field("envelope_id", &self.envelope_id)
            .field("sealed", &self.sealed)
            .finish()
    }
}

/// Wrap a vault envelope for a recipient with the existing transfer seal.
///
/// The envelope is serialized into one bundle file and sealed as a normal
/// `SealedBundle`. The relay sees only ciphertext and metadata; the passphrase
/// never enters the bundle, the envelope, or the report.
pub fn wrap_for_transfer(
    envelope: &VaultEnvelope,
    recipient: &RecipientKey,
) -> Result<SealedVault> {
    envelope.validate()?;
    let encoded = serde_json::to_vec(envelope)
        .map_err(|error| internal(format!("cannot encode the vault envelope: {error}")))?;
    let mut files = BTreeMap::new();
    files.insert(VAULT_ENVELOPE_FILE.to_string(), encoded);
    let bundle = bundle::build(
        files,
        Vec::<Excluded>::new(),
        ChunkConfig::default(),
        envelope.created_ms,
    )?;
    let sealed = seal_bundle(&bundle, recipient)?;
    Ok(SealedVault {
        envelope_id: envelope.envelope_id(),
        sealed,
    })
}

/// Recover the envelope from a sealed transfer without unlocking it.
///
/// The bundle is verified first. The transfer must contain exactly one file,
/// the envelope must validate, and its derived id must equal the id the
/// transfer was wrapped with; anything else is `zero.tru.tamper`.
pub fn unwrap_envelope(sealed: &SealedVault, recipient: &RecipientSecret) -> Result<VaultEnvelope> {
    let verified = open_bundle_verified(&sealed.sealed, recipient)?;
    if verified.bundle.manifest.files.len() != 1
        || !verified
            .bundle
            .manifest
            .files
            .contains_key(VAULT_ENVELOPE_FILE)
    {
        return Err(tamper(
            "a sealed vault must carry exactly one vault envelope file",
        ));
    }
    let envelope = decode_envelope(&verified)?;
    envelope.validate()?;
    if envelope.envelope_id() != sealed.envelope_id {
        return Err(tamper(
            "the sealed vault does not carry the envelope it names",
        ));
    }
    Ok(envelope)
}

/// Receive a sealed vault and unlock it once.
///
/// The transfer is opened with the recipient secret; the relay never holds
/// this secret and never sees the passphrase. The one-unlock and prompt rules
/// are exactly [`unlock_vault`]'s.
pub fn receive(
    state: &mut UnlockState,
    sealed: &SealedVault,
    recipient: &RecipientSecret,
    request: UnlockRequest,
    now_ms: i64,
) -> Result<UnlockedVault> {
    let envelope = unwrap_envelope(sealed, recipient)?;
    unlock_vault(state, &envelope, request, now_ms)
}

/// Counts for a UI or a log: no plaintext, no passphrase, no key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultTransferReport {
    /// The envelope that travelled.
    pub envelope_id: String,
    /// Ciphertext bytes on the wire, including transfer framing.
    pub sealed_bytes: u64,
    /// Whether the target unlocked the vault in this transfer.
    pub unlocked: bool,
}

/// Build a report for a sealed vault.
pub fn vault_transfer_report(sealed: &SealedVault, unlocked: bool) -> Result<VaultTransferReport> {
    Ok(VaultTransferReport {
        envelope_id: sealed.envelope_id.clone(),
        sealed_bytes: sealed.sealed_bytes()?,
        unlocked,
    })
}

struct DerivedKey {
    enc: Zeroizing<[u8; VAULT_KEY_BYTES]>,
    check: [u8; VAULT_KEY_BYTES],
}

fn derive_key(passphrase: &[u8], kdf: &KdfParams) -> Result<DerivedKey> {
    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(64))
        .map_err(|_| ZeroError::new(ErrorCode::InvalidInput, "vault KDF parameters are invalid"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0u8; 64]);
    argon
        .hash_password_into(passphrase, &kdf.salt, &mut *output)
        .map_err(|_| internal("Argon2id could not derive the vault key"))?;
    let mut enc = Zeroizing::new([0u8; VAULT_KEY_BYTES]);
    enc.copy_from_slice(&output[..VAULT_KEY_BYTES]);
    let mut check = [0u8; VAULT_KEY_BYTES];
    check.copy_from_slice(&output[VAULT_KEY_BYTES..]);
    Ok(DerivedKey { enc, check })
}

fn encrypt(
    key: &[u8; VAULT_KEY_BYTES],
    nonce: &[u8; VAULT_NONCE_BYTES],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| internal("cannot initialise AES-256-GCM"))?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| internal("AES-256-GCM encryption failed"))
}

fn decrypt(
    key: &[u8; VAULT_KEY_BYTES],
    nonce: &[u8; VAULT_NONCE_BYTES],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| internal("cannot initialise AES-256-GCM"))?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| {
            tamper("vault authentication failed: the ciphertext, associated data, or key is wrong")
        })
}

fn decode_envelope(verified: &VerifiedTransfer) -> Result<VaultEnvelope> {
    let entry = verified
        .bundle
        .manifest
        .files
        .get(VAULT_ENVELOPE_FILE)
        .ok_or_else(|| tamper("the sealed vault has no envelope file"))?;
    let mut bytes = Vec::with_capacity(entry.bytes as usize);
    for chunk in &entry.chunks {
        let piece = verified
            .bundle
            .chunks
            .get(&chunk.hash)
            .ok_or_else(|| tamper(format!("vault chunk `{}` is missing", chunk.hash)))?;
        bytes.extend_from_slice(piece);
    }
    serde_json::from_slice(&bytes).map_err(|_| tamper("the sealed vault envelope is not readable"))
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

fn prompt_required(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyAskRequired, message)
}

fn tamper(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::TamperDetected, message)
}

fn internal(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Internal, message)
}

type Result<T, E = ZeroError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer::RecipientSecret;

    const NOW: i64 = 1_700_000_000_000;
    const PASS: &str = "correct horse battery staple";
    const PLAINTEXT: &[u8] = b"{\"OPENAI_KEY\":\"sk-vault-plaintext-marker\"}";

    fn cheap_kdf() -> KdfOptions {
        // Test-only costs keep the suite fast; production uses `Default`.
        KdfOptions {
            m_cost: 256,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn sealed() -> VaultEnvelope {
        seal_vault_with_kdf(PLAINTEXT, PASS, NOW, cheap_kdf()).expect("seal")
    }

    fn recipient() -> RecipientSecret {
        RecipientSecret::from_seed([0x44; 32])
    }

    #[test]
    fn seal_and_unlock_round_trip_returns_the_bytes() {
        let envelope = sealed();
        assert_eq!(envelope.schema_version, VAULT_SCHEMA_VERSION);
        assert_eq!(envelope.nonce.len(), VAULT_NONCE_BYTES);
        assert_eq!(envelope.kdf.salt.len(), VAULT_SALT_BYTES);
        assert_eq!(
            envelope.ciphertext_bytes(),
            PLAINTEXT.len() + VAULT_TAG_BYTES
        );
        assert!(!envelope.ciphertext.starts_with(PLAINTEXT));
        assert_eq!(envelope.envelope_id().len(), 64);
        assert_eq!(envelope.envelope_id(), envelope.envelope_id());

        let mut state = UnlockState::new();
        let unlocked = state
            .unlock(&envelope, UnlockRequest::passphrase(PASS), NOW)
            .expect("unlock");
        assert_eq!(unlocked.bytes(), PLAINTEXT);
        assert_eq!(unlocked.envelope_id(), envelope.envelope_id());
        assert_eq!(unlocked.len(), PLAINTEXT.len());
        assert!(!unlocked.is_empty());
        assert_eq!(state.consumed_count(), 1);
    }

    #[test]
    fn a_wrong_passphrase_is_a_prompt_and_returns_no_plaintext() {
        let envelope = sealed();
        let mut state = UnlockState::new();
        let error = state
            .unlock(&envelope, UnlockRequest::passphrase("wrong"), NOW)
            .expect_err("wrong passphrase");
        assert_eq!(error.code(), ErrorCode::PolicyAskRequired);
        assert!(!error.message().contains(PASS));
        assert!(!error.message().contains("sk-vault"));
        assert_eq!(
            state.consumed_count(),
            0,
            "a failed attempt is not an unlock"
        );

        // The envelope is still locked and the right passphrase still works.
        let unlocked = state
            .unlock(&envelope, UnlockRequest::passphrase(PASS), NOW)
            .expect("right passphrase");
        assert_eq!(unlocked.bytes(), PLAINTEXT);
    }

    #[test]
    fn a_second_unlock_is_refused_even_with_the_right_passphrase() {
        // T-TEL-07 done criterion: the target prompts once and cannot decrypt
        // silently.
        let envelope = sealed();
        let mut state = UnlockState::new();
        state
            .unlock(&envelope, UnlockRequest::passphrase(PASS), NOW)
            .expect("first unlock");
        let error = state
            .unlock(&envelope, UnlockRequest::passphrase(PASS), NOW)
            .expect_err("second unlock");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(state.is_consumed(&envelope.envelope_id()));

        // A second unlock through an approval is refused by the same rule.
        let approval = issue_approval(&envelope, PASS, "ap-second", NOW, 60_000).expect("approval");
        let mut other = UnlockState::new();
        other.register_approval(approval).expect("register");
        other
            .unlock(
                &envelope,
                UnlockRequest::approved_transfer("ap-second"),
                NOW,
            )
            .expect("approved unlock");
        assert_eq!(
            other
                .unlock(&envelope, UnlockRequest::passphrase(PASS), NOW)
                .expect_err("one unlock per envelope")
                .code(),
            ErrorCode::PolicyDenied
        );
    }

    #[test]
    fn a_tampered_ciphertext_is_refused_as_tamper() {
        let mut envelope = sealed();
        let last = envelope.ciphertext.len() - 1;
        envelope.ciphertext[last] ^= 0x01;
        let mut state = UnlockState::new();
        let error = state
            .unlock(&envelope, UnlockRequest::passphrase(PASS), NOW)
            .expect_err("tampered ciphertext");
        assert_eq!(error.code(), ErrorCode::TamperDetected);
        assert_eq!(state.consumed_count(), 0);
    }

    #[test]
    fn approved_transfer_requires_a_matching_binding() {
        let envelope = sealed();
        let other = seal_vault_with_kdf(b"other vault", "another passphrase", NOW, cheap_kdf())
            .expect("other envelope");

        // An approval bound to another envelope is refused.
        let foreign = issue_approval(&other, "another passphrase", "ap-foreign", NOW, 60_000)
            .expect("foreign approval");
        let mut state = UnlockState::new();
        state.register_approval(foreign).expect("register");
        assert_eq!(
            state
                .unlock(
                    &envelope,
                    UnlockRequest::approved_transfer("ap-foreign"),
                    NOW
                )
                .expect_err("approval for another envelope")
                .code(),
            ErrorCode::PolicyDenied
        );

        // An unknown approval label asks for a real unlock.
        assert_eq!(
            state
                .unlock(
                    &envelope,
                    UnlockRequest::approved_transfer("ap-missing"),
                    NOW
                )
                .expect_err("unknown approval")
                .code(),
            ErrorCode::PolicyAskRequired
        );

        // A matching approval unlocks once.
        let approval = issue_approval(&envelope, PASS, "ap-match", NOW, 60_000).expect("approval");
        let mut state = UnlockState::new();
        state.register_approval(approval).expect("register");
        let unlocked = state
            .unlock(&envelope, UnlockRequest::approved_transfer("ap-match"), NOW)
            .expect("approved unlock");
        assert_eq!(unlocked.bytes(), PLAINTEXT);
        assert_eq!(
            state
                .unlock(&envelope, UnlockRequest::approved_transfer("ap-match"), NOW)
                .expect_err("approval is one use")
                .code(),
            ErrorCode::PolicyDenied
        );
    }

    #[test]
    fn an_expired_approval_is_refused() {
        let envelope = sealed();
        let approval = issue_approval(&envelope, PASS, "ap-expired", NOW, 1_000).expect("approval");
        let mut state = UnlockState::new();
        state.register_approval(approval).expect("register");
        assert_eq!(
            state
                .unlock(
                    &envelope,
                    UnlockRequest::approved_transfer("ap-expired"),
                    NOW + 1_000,
                )
                .expect_err("expired approval")
                .code(),
            ErrorCode::ApprovalExpired
        );
        assert_eq!(state.consumed_count(), 0);

        // One millisecond earlier the same approval is still valid.
        let unlocked = state
            .unlock(
                &envelope,
                UnlockRequest::approved_transfer("ap-expired"),
                NOW + 999,
            )
            .expect("live approval");
        assert_eq!(unlocked.bytes(), PLAINTEXT);
    }

    #[test]
    fn ciphertext_travels_through_transfer_sealing_and_stays_opaque() {
        let envelope = sealed();
        let recipient_secret = recipient();
        let sealed_vault =
            wrap_for_transfer(&envelope, &recipient_secret.recipient_key()).expect("wrap");
        assert_eq!(sealed_vault.envelope_id(), envelope.envelope_id());

        // The relay-visible envelope carries no plaintext and no passphrase.
        let json = serde_json::to_string(sealed_vault.sealed()).expect("sealed json");
        assert!(!json.contains("sk-vault-plaintext-marker"));
        assert!(!json.contains(PASS));
        assert!(!json.contains("OPENAI_KEY"));

        // The envelope is recoverable only with the recipient secret.
        let recovered = unwrap_envelope(&sealed_vault, &recipient_secret).expect("unwrap");
        assert_eq!(recovered, envelope);

        let mut state = UnlockState::new();
        let unlocked = receive(
            &mut state,
            &sealed_vault,
            &recipient_secret,
            UnlockRequest::passphrase(PASS),
            NOW,
        )
        .expect("receive");
        assert_eq!(unlocked.bytes(), PLAINTEXT);

        let report = vault_transfer_report(&sealed_vault, true).expect("report");
        assert_eq!(report.envelope_id, envelope.envelope_id());
        assert!(report.unlocked);
        assert!(report.sealed_bytes > envelope.ciphertext_bytes() as u64);
        let report_json = serde_json::to_string(&report).expect("report json");
        assert!(!report_json.contains(PASS));
        assert!(!report_json.contains("sk-vault"));

        // A corrupted sealed chunk fails before any unlock.
        let mut broken =
            wrap_for_transfer(&sealed(), &recipient_secret.recipient_key()).expect("wrap again");
        broken.sealed = {
            let mut sealed = broken.sealed.clone();
            sealed.chunks[0].ciphertext = flip_b64(&sealed.chunks[0].ciphertext);
            sealed
        };
        let mut other = UnlockState::new();
        assert_eq!(
            receive(
                &mut other,
                &broken,
                &recipient_secret,
                UnlockRequest::passphrase(PASS),
                NOW
            )
            .expect_err("corrupted transfer")
            .code(),
            ErrorCode::TamperDetected
        );
        assert_eq!(other.consumed_count(), 0);
    }

    #[test]
    fn debug_and_errors_never_expose_plaintext_or_keys() {
        let envelope = sealed();
        let mut state = UnlockState::new();
        let unlocked = state
            .unlock(&envelope, UnlockRequest::passphrase(PASS), NOW)
            .expect("unlock");

        let envelope_debug = format!("{envelope:?}");
        assert!(envelope_debug.contains(&envelope.envelope_id()));
        assert!(!envelope_debug.contains(PASS));
        assert!(!envelope_debug.contains("sk-vault-plaintext-marker"));

        let unlocked_debug = format!("{unlocked:?}");
        assert!(!unlocked_debug.contains(PASS));
        assert!(!unlocked_debug.contains("sk-vault-plaintext-marker"));

        let request_debug = format!("{:?}", UnlockRequest::passphrase(PASS));
        assert!(request_debug.contains("redacted"));
        assert!(!request_debug.contains(PASS));

        let approval = issue_approval(&envelope, PASS, "ap-debug", NOW, 1_000).expect("approval");
        let approval_debug = format!("{approval:?}");
        assert!(!approval_debug.contains(PASS));
        assert!(!approval_debug.contains("sk-vault"));
        assert!(approval_debug.contains("redacted"));

        let error = state
            .unlock(&envelope, UnlockRequest::passphrase("wrong"), NOW)
            .expect_err("wrong passphrase");
        assert!(!error.message().contains(PASS));
        assert!(!error.message().contains("sk-vault"));

        let json = serde_json::to_string(&envelope).expect("envelope json");
        assert!(!json.contains("\"plaintext\""));
        assert!(!json.contains("\"key\""));
        assert!(!json.contains(PASS));
        assert!(!json.contains("sk-vault-plaintext-marker"));
    }

    #[test]
    fn a_new_envelope_allows_a_new_single_unlock() {
        let first = sealed();
        let second = sealed();
        assert_ne!(
            first.envelope_id(),
            second.envelope_id(),
            "a fresh salt and nonce give a new envelope id"
        );

        let mut state = UnlockState::new();
        state
            .unlock(&first, UnlockRequest::passphrase(PASS), NOW)
            .expect("first envelope");
        let unlocked = state
            .unlock(&second, UnlockRequest::passphrase(PASS), NOW)
            .expect("new envelope has a new unlock");
        assert_eq!(unlocked.bytes(), PLAINTEXT);
        assert_eq!(
            state
                .unlock(&second, UnlockRequest::passphrase(PASS), NOW)
                .expect_err("second envelope is single use too")
                .code(),
            ErrorCode::PolicyDenied
        );
    }

    #[test]
    fn unlock_requests_are_validated_and_the_passphrase_is_moved_in() {
        assert_eq!(
            seal_vault_with_kdf(PLAINTEXT, "", NOW, cheap_kdf())
                .expect_err("empty passphrase on seal")
                .code(),
            ErrorCode::InvalidInput
        );

        let envelope = sealed();
        let mut state = UnlockState::new();
        assert_eq!(
            state
                .unlock(&envelope, UnlockRequest::passphrase(""), NOW)
                .expect_err("empty unlock")
                .code(),
            ErrorCode::PolicyAskRequired
        );

        // The passphrase is owned by the request and moved into the unlock,
        // where it is zeroized best-effort. A string copy made by the caller
        // before this point (or by the OS) cannot be cleared here.
        let request = UnlockRequest::Passphrase(PASS.to_string());
        let unlocked = state
            .unlock(&envelope, request, NOW)
            .expect("owned passphrase");
        assert_eq!(unlocked.bytes(), PLAINTEXT);
    }

    #[test]
    fn envelope_shape_bounds_are_typed() {
        let mut envelope = sealed();

        let mut schema = envelope.clone();
        schema.schema_version = 2;
        assert_eq!(
            schema.validate().expect_err("schema").code(),
            ErrorCode::SchemaVersion
        );

        let mut nonce = envelope.clone();
        nonce.nonce.pop();
        assert_eq!(
            nonce.validate().expect_err("nonce").code(),
            ErrorCode::InvalidInput
        );

        let mut salt = envelope.clone();
        salt.kdf.salt.truncate(4);
        assert_eq!(
            salt.validate().expect_err("salt").code(),
            ErrorCode::InvalidInput
        );

        let mut aad = envelope.clone();
        aad.aad.push(0);
        assert_eq!(
            aad.validate().expect_err("aad").code(),
            ErrorCode::TamperDetected
        );

        let mut short = envelope.clone();
        short.ciphertext.truncate(VAULT_TAG_BYTES);
        assert_eq!(
            short.validate().expect_err("short ciphertext").code(),
            ErrorCode::TamperDetected
        );

        envelope.created_ms = NOW + 1;
        assert!(envelope.validate().is_ok(), "the clock is not a secret");
    }

    fn flip_b64(text: &str) -> String {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        let mut bytes = B64.decode(text).expect("base64");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        B64.encode(bytes)
    }
}
