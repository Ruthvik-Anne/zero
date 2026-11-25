//! Atomic signed updates and rollback (T-INST-04).
//!
//! Requirements: INST-04 (install lock and clean temporary directories are the
//! installer's responsibility; this module owns staging cleanup), INST-08
//! (install, update atomically and signed with rollback), and INST-10 (upgrade
//! from a local signed package).
//!
//! # What an update is here
//!
//! A real release ships a `.tar.gz` or `.zip` archive. This crate has no
//! archive dependency by design (`no new dependencies`), so the archive reader
//! is modelled as an in-memory file tree: [`UpdatePayload`] is a sorted map from
//! a relative `/`-separated path to the exact file bytes. Decoding a real
//! archive into that tree is installer work; everything after decoding —
//! signature and digest checks, path safety, staging, atomic swap, health check,
//! and rollback — is implemented and tested here.
//!
//! The signed manifest from [`crate::packaging`] is the source of truth:
//!
//! - the manifest's Ed25519 signature binds the version, target, and the
//!   artifact SHA-256 and size;
//! - [`UpdatePayload::sha256`] is a canonical digest over the tree, so an
//!   archive reader that decodes different bytes is refused.
//!
//! # Apply sequence
//!
//! 1. Re-check the verified payload (paths, bounds, digest).
//! 2. Refuse a staging directory owned by another version; clean a stale one
//!    for the same version.
//! 3. Probe free space through the injected [`DiskProbe`].
//! 4. Stage every file under `staging_root/<version>` with `create_new`, then
//!    read every staged file back and compare its hash.
//! 5. Snapshot the current install into
//!    `install_root/.backup-<old_version>-<now_ms>`, including a hash manifest.
//! 6. Swap each file with write-temp + rename, then write the version file.
//! 7. Re-hash the installed tree and run the injected [`HealthCheck`].
//!
//! Any failure after the snapshot restores the backup and returns an error
//! whose [`UpdateError::rollback_state`] says so. [`rollback`] performs the same
//! restore explicitly from an [`UpdateReport`].
//!
//! # Bounds and safety
//!
//! Every path must be relative, use `/`, and contain only normal components
//! (no `..`, `.`, empty part, drive prefix, control character, trailing dot or
//! space, or reserved Windows device name). Limits: [`MAX_UPDATE_FILES`],
//! [`MAX_UPDATE_FILE_BYTES`], and [`MAX_UPDATE_BYTES`]. The module has no
//! network or shell surface.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::packaging::{self, PackagingErrorKind, SignedRelease, SUPPORTED_TARGETS};

/// Schema version of the backup manifest this module writes.
pub const UPDATE_SCHEMA_VERSION: u32 = 1;

/// Version file written into the install root after a successful swap.
pub const VERSION_FILE: &str = ".zero-version";

/// Prefix of a snapshot directory inside the install root.
pub const BACKUP_DIR_PREFIX: &str = ".backup-";

/// Marker file that records which version a staging directory belongs to.
pub const STAGING_MARKER: &str = ".zero-staging";

/// The backup hash manifest inside a snapshot directory.
pub const BACKUP_MANIFEST: &str = "manifest.json";

/// Upper bound on files in one update payload.
pub const MAX_UPDATE_FILES: usize = 8192;
/// Upper bound on one payload file.
pub const MAX_UPDATE_FILE_BYTES: u64 = 32 * 1024 * 1024;
/// Upper bound on the whole payload, decompressed.
pub const MAX_UPDATE_BYTES: u64 = 256 * 1024 * 1024;
/// Upper bound on one relative path.
pub const MAX_PATH_BYTES: usize = 512;
/// Upper bound on path depth.
pub const MAX_PATH_DEPTH: usize = 32;
/// Upper bound on a backup manifest file.
pub const MAX_BACKUP_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
/// Extra free space demanded beyond the staged payload and the snapshot.
pub const DISK_HEADROOM_BYTES: u64 = 64 * 1024;

const MAX_VERSION_BYTES: usize = 64;
const TEMP_PREFIX: &str = ".zero-update.tmp-";

/// Why an update was refused or failed. Kinds are stable strings for logs and
/// tests; they are local to the update path and are not part of the
/// `zero-types` error taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateErrorKind {
    ArtifactInvalid,
    SignatureInvalid,
    ManifestInvalid,
    WrongTarget,
    DowngradeRefused,
    VersionInvalid,
    PathEscape,
    LimitExceeded,
    StagingConflict,
    DiskSpace,
    HealthCheck,
    Io,
    Json,
    RollbackFailed,
}

impl UpdateErrorKind {
    /// Stable kind string, e.g. `downgrade_refused`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArtifactInvalid => "artifact_invalid",
            Self::SignatureInvalid => "signature_invalid",
            Self::ManifestInvalid => "manifest_invalid",
            Self::WrongTarget => "wrong_target",
            Self::DowngradeRefused => "downgrade_refused",
            Self::VersionInvalid => "version_invalid",
            Self::PathEscape => "path_escape",
            Self::LimitExceeded => "limit_exceeded",
            Self::StagingConflict => "staging_conflict",
            Self::DiskSpace => "disk_space",
            Self::HealthCheck => "health_check",
            Self::Io => "io",
            Self::Json => "json",
            Self::RollbackFailed => "rollback_failed",
        }
    }
}

/// What happened to the previous installation when an error was returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackState {
    /// The failure happened before any file was swapped.
    NotNeeded,
    /// The snapshot was restored; the tree is back to its pre-update bytes.
    RolledBack,
    /// The restore itself failed. The message names the reason.
    RollbackFailed(String),
}

impl RollbackState {
    /// Whether the previous tree is known to be restored.
    pub fn restored(&self) -> bool {
        matches!(self, Self::RolledBack)
    }
}

/// A typed update error with a kind, a message that never contains key
/// material, and the rollback outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateError {
    kind: UpdateErrorKind,
    message: String,
    rollback: RollbackState,
}

impl UpdateError {
    /// Build an error. Public so an injected [`HealthCheck`] or [`DiskProbe`]
    /// can report its own failure in the shared type.
    pub fn new(kind: UpdateErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            rollback: RollbackState::NotNeeded,
        }
    }

    fn with_rollback(
        kind: UpdateErrorKind,
        message: impl Into<String>,
        rollback: RollbackState,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            rollback,
        }
    }

    /// The stable error kind.
    pub fn kind(&self) -> UpdateErrorKind {
        self.kind
    }

    /// The stable kind string, e.g. `path_escape`.
    pub fn code(&self) -> &'static str {
        self.kind.as_str()
    }

    /// The human-readable message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// What happened to the previous installation.
    pub fn rollback_state(&self) -> &RollbackState {
        &self.rollback
    }
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "zero.update.{}: {}", self.kind.as_str(), self.message)
    }
}

impl std::error::Error for UpdateError {}

impl From<std::io::Error> for UpdateError {
    fn from(error: std::io::Error) -> Self {
        Self::new(UpdateErrorKind::Io, error.to_string())
    }
}

impl From<serde_json::Error> for UpdateError {
    fn from(error: serde_json::Error) -> Self {
        Self::new(UpdateErrorKind::Json, error.to_string())
    }
}

type Result<T> = std::result::Result<T, UpdateError>;

fn map_packaging(error: packaging::PackagingError) -> UpdateError {
    let kind = match error.kind() {
        PackagingErrorKind::InvalidSignature => UpdateErrorKind::SignatureInvalid,
        PackagingErrorKind::InvalidArtifact => UpdateErrorKind::ArtifactInvalid,
        PackagingErrorKind::UnsupportedTarget => UpdateErrorKind::WrongTarget,
        PackagingErrorKind::LimitExceeded => UpdateErrorKind::LimitExceeded,
        PackagingErrorKind::Json => UpdateErrorKind::Json,
        _ => UpdateErrorKind::ManifestInvalid,
    };
    UpdateError::new(kind, format!("release manifest: {}", error.message()))
}

/// The decoded update tree: relative path to exact file bytes.
///
/// Insertion validates the path and the size bounds, so a constructed payload
/// is always safe to materialise. [`Self::sha256`] is the canonical digest the
/// signed manifest's artifact entry must name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdatePayload {
    files: BTreeMap<String, Vec<u8>>,
}

impl UpdatePayload {
    /// An empty payload.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert one file. The path is validated and the size bounds apply.
    pub fn insert(&mut self, path: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Result<()> {
        let path = path.into();
        validate_relative_path(&path)?;
        let bytes = bytes.into();
        let bytes_len = bytes.len() as u64;
        if bytes_len > MAX_UPDATE_FILE_BYTES {
            return Err(UpdateError::new(
                UpdateErrorKind::LimitExceeded,
                format!(
                    "payload file `{path}` is {bytes_len} bytes, above the {MAX_UPDATE_FILE_BYTES} byte file limit"
                ),
            ));
        }
        if self.files.len() >= MAX_UPDATE_FILES && !self.files.contains_key(&path) {
            return Err(UpdateError::new(
                UpdateErrorKind::LimitExceeded,
                format!("payload has more than {MAX_UPDATE_FILES} files"),
            ));
        }
        let previous = self.files.insert(path.clone(), bytes);
        if let Err(error) = self.check_total() {
            self.files.remove(&path);
            if let Some(previous) = previous {
                self.files.insert(path, previous);
            }
            return Err(error);
        }
        Ok(())
    }

    /// The bytes of one file.
    pub fn get(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(Vec::as_slice)
    }

    /// Number of files.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether the payload has no files.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Sorted `(path, bytes)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.files
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
    }

    /// Sum of every file's size.
    pub fn total_bytes(&self) -> u64 {
        self.files.values().map(|bytes| bytes.len() as u64).sum()
    }

    /// Canonical digest: a domain tag, the file count, then each path and file
    /// length-prefixed little-endian, in sorted path order.
    pub fn sha256(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"zero.update.payload\0v1\0");
        hasher.update((self.files.len() as u64).to_le_bytes());
        for (path, bytes) in &self.files {
            hasher.update((path.len() as u64).to_le_bytes());
            hasher.update(path.as_bytes());
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }
        hex(&hasher.finalize())
    }

    /// Validate every path and the total size bound.
    pub fn validate(&self) -> Result<()> {
        if self.files.len() > MAX_UPDATE_FILES {
            return Err(UpdateError::new(
                UpdateErrorKind::LimitExceeded,
                format!(
                    "payload has {} files, above the {MAX_UPDATE_FILES} file limit",
                    self.files.len()
                ),
            ));
        }
        for (path, bytes) in &self.files {
            validate_relative_path(path)?;
            let len = bytes.len() as u64;
            if len > MAX_UPDATE_FILE_BYTES {
                return Err(UpdateError::new(
                    UpdateErrorKind::LimitExceeded,
                    format!(
                        "payload file `{path}` is {len} bytes, above the {MAX_UPDATE_FILE_BYTES} byte file limit"
                    ),
                ));
            }
        }
        self.check_total()
    }

    fn check_total(&self) -> Result<()> {
        let total = self.total_bytes();
        if total > MAX_UPDATE_BYTES {
            return Err(UpdateError::new(
                UpdateErrorKind::LimitExceeded,
                format!("payload is {total} bytes, above the {MAX_UPDATE_BYTES} byte update limit"),
            ));
        }
        Ok(())
    }
}

/// A signed release plus the decoded file tree it describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateArtifact {
    /// The signed release manifest (INST-02).
    pub release: SignedRelease,
    /// The decoded archive contents.
    pub payload: UpdatePayload,
}

impl UpdateArtifact {
    /// Pair a signed release with its decoded tree.
    pub fn new(release: SignedRelease, payload: UpdatePayload) -> Self {
        Self { release, payload }
    }
}

/// The facts a caller must supply to accept an update.
#[derive(Debug, Clone, Copy)]
pub struct UpdatePolicy<'a> {
    /// The platform of this installation. A manifest without an artifact for
    /// this target is refused.
    pub expected_target: &'a str,
    /// The installed version, from [`current_version`]. Used for the downgrade
    /// rule.
    pub current_version: Option<&'a str>,
    /// Permit a version that sorts before the installed one (INST-10 local
    /// rollback packages are the usual reason).
    pub allow_downgrade: bool,
}

/// A signature- and digest-checked update, ready to stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedUpdate {
    version: String,
    target: String,
    channel: String,
    manifest_hash: String,
    payload_sha256: String,
    files: BTreeMap<String, Vec<u8>>,
}

impl VerifiedUpdate {
    /// The release version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The platform triple the artifact was built for.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The release channel (`stable` or `beta`).
    pub fn channel(&self) -> &str {
        &self.channel
    }

    /// SHA-256 of the manifest's canonical bytes, from packaging.
    pub fn manifest_hash(&self) -> &str {
        &self.manifest_hash
    }

    /// The canonical payload digest the signature covers.
    pub fn payload_sha256(&self) -> &str {
        &self.payload_sha256
    }

    /// Sorted `(path, bytes)` pairs.
    pub fn files(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.files
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
    }

    /// The bytes of one file.
    pub fn file(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(Vec::as_slice)
    }

    /// Number of files.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Sum of every file's size.
    pub fn total_bytes(&self) -> u64 {
        self.files.values().map(|bytes| bytes.len() as u64).sum()
    }
}

/// Verify signature, target, digest, bounds, and the downgrade rule.
///
/// Uses the public key embedded in the installer (INST-02). The checks run in
/// this order: payload shape, manifest shape, target, digest and size,
/// signature, then version order. Nothing touches the filesystem.
pub fn verify_update(
    artifact: &UpdateArtifact,
    policy: &UpdatePolicy<'_>,
) -> Result<VerifiedUpdate> {
    let key = packaging::embedded_public_key().map_err(map_packaging)?;
    verify_update_with_key(artifact, policy, &key)
}

/// [`verify_update`] with an explicit public key, for a mirrored or test key.
pub fn verify_update_with_key(
    artifact: &UpdateArtifact,
    policy: &UpdatePolicy<'_>,
    public_key: &VerifyingKey,
) -> Result<VerifiedUpdate> {
    artifact.payload.validate()?;
    artifact.release.validate().map_err(map_packaging)?;

    let manifest = &artifact.release.manifest;
    if !SUPPORTED_TARGETS.contains(&policy.expected_target) {
        return Err(UpdateError::new(
            UpdateErrorKind::WrongTarget,
            format!(
                "expected target `{}` is not one of the six release targets",
                policy.expected_target
            ),
        ));
    }
    let artifact_entry = manifest
        .artifacts
        .iter()
        .find(|entry| entry.target == policy.expected_target)
        .ok_or_else(|| {
            UpdateError::new(
                UpdateErrorKind::WrongTarget,
                format!(
                    "release {} has no artifact for target `{}`",
                    manifest.version, policy.expected_target
                ),
            )
        })?;

    let payload_sha256 = artifact.payload.sha256();
    if artifact_entry.sha256 != payload_sha256 {
        return Err(UpdateError::new(
            UpdateErrorKind::ArtifactInvalid,
            format!(
                "payload digest {payload_sha256} does not match the signed digest {}",
                artifact_entry.sha256
            ),
        ));
    }
    let payload_bytes = artifact.payload.total_bytes();
    if artifact_entry.bytes != payload_bytes {
        return Err(UpdateError::new(
            UpdateErrorKind::ArtifactInvalid,
            format!(
                "payload size {payload_bytes} does not match the signed size {}",
                artifact_entry.bytes
            ),
        ));
    }

    packaging::verify_signed(&artifact.release, public_key).map_err(map_packaging)?;

    if let Some(current) = policy.current_version {
        if !is_valid_version(current) {
            return Err(UpdateError::new(
                UpdateErrorKind::VersionInvalid,
                "the installed version is not a valid release version",
            ));
        }
        if compare_versions(&manifest.version, current) == std::cmp::Ordering::Less
            && !policy.allow_downgrade
        {
            return Err(UpdateError::new(
                UpdateErrorKind::DowngradeRefused,
                format!(
                    "release {} sorts before the installed version {current}; pass allow_downgrade to install it deliberately",
                    manifest.version
                ),
            ));
        }
    }

    Ok(VerifiedUpdate {
        version: manifest.version.clone(),
        target: artifact_entry.target.clone(),
        channel: manifest.channel.clone(),
        manifest_hash: manifest.manifest_hash(),
        payload_sha256,
        files: artifact.payload.files.clone(),
    })
}

/// Compare two release versions.
///
/// The numeric core (`major.minor.patch`) is compared segment by segment;
/// a missing segment is zero. A pre-release suffix (`-beta.1`) sorts before the
/// same core without one, and its dot-separated identifiers compare
/// numerically when both are digits, otherwise lexically, with a numeric
/// identifier below a textual one. Build metadata (`+...`) is ignored. A
/// segment that is not numeric is compared as text, so unusual but validated
/// versions still have a total order.
pub fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    let (left_core, left_pre) = split_version(left);
    let (right_core, right_pre) = split_version(right);

    let left_parts: Vec<&str> = left_core.split('.').collect();
    let right_parts: Vec<&str> = right_core.split('.').collect();
    let depth = left_parts.len().max(right_parts.len());
    for index in 0..depth {
        let left = left_parts.get(index).copied().unwrap_or("0");
        let right = right_parts.get(index).copied().unwrap_or("0");
        let ordering = compare_identifier(left, right);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }

    match (left_pre, right_pre) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(left), Some(right)) => {
            let left: Vec<&str> = left.split('.').collect();
            let right: Vec<&str> = right.split('.').collect();
            for index in 0..left.len().min(right.len()) {
                let ordering = compare_identifier(left[index], right[index]);
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
            left.len().cmp(&right.len())
        }
    }
}

fn split_version(version: &str) -> (&str, Option<&str>) {
    let end = version.find(['-', '+']).unwrap_or(version.len());
    let core = &version[..end];
    let rest = &version[end..];
    let prerelease = rest.strip_prefix('-');
    (core, prerelease)
}

fn compare_identifier(left: &str, right: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (left.parse::<u64>(), right.parse::<u64>()) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        (Ok(_), Err(_)) => Ordering::Less,
        (Err(_), Ok(_)) => Ordering::Greater,
        (Err(_), Err(_)) => left.cmp(right),
    }
}

/// Read the installed version from the version file.
///
/// Returns `None` when the file is absent. An empty or unsafe value is refused
/// rather than trusted.
pub fn current_version(install_root: impl AsRef<Path>) -> Result<Option<String>> {
    let path = install_root.as_ref().join(VERSION_FILE);
    match fs::read_to_string(&path) {
        Ok(text) => {
            let version = text.trim();
            if !is_valid_version(version) {
                return Err(UpdateError::new(
                    UpdateErrorKind::VersionInvalid,
                    format!(
                        "version file {} is not a valid release version",
                        path.display()
                    ),
                ));
            }
            Ok(Some(version.to_string()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// A health check run after the swap and before the update is accepted.
///
/// A real installer starts the new binary with `--version` or opens its local
/// API. The injected check runs after the module's own hash verification; any
/// error triggers the rollback path.
pub trait HealthCheck {
    /// Check the freshly swapped installation.
    fn healthy(&self, install_root: &Path) -> Result<()>;
}

/// A free-space probe. Real installers inject a platform probe; the default
/// declines to guess.
pub trait DiskProbe {
    /// Free bytes available under `path`.
    fn free_bytes(&self, path: &Path) -> Result<u64>;
}

/// A hook called immediately before each file swap, for progress reporting and
/// for fault injection in tests.
pub trait SwapHook {
    /// Called with the index in sorted path order, the relative path, and the
    /// install root. An error aborts the swap and triggers rollback.
    fn before_swap(&self, index: usize, relative: &str, install_root: &Path) -> Result<()>;
}

/// The default health check: no extra check beyond the module's hash pass.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoHealthCheck;

impl HealthCheck for NoHealthCheck {
    fn healthy(&self, _install_root: &Path) -> Result<()> {
        Ok(())
    }
}

/// The default disk probe. It cannot ask the OS without a platform syscall, so
/// it reports an unbounded disk; installers inject a real probe.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnrestrictedDisk;

impl DiskProbe for UnrestrictedDisk {
    fn free_bytes(&self, _path: &Path) -> Result<u64> {
        Ok(u64::MAX)
    }
}

/// The default swap hook: do nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSwapHook;

impl SwapHook for NoSwapHook {
    fn before_swap(&self, _index: usize, _relative: &str, _install_root: &Path) -> Result<()> {
        Ok(())
    }
}

/// Optional seams for [`apply_update_with`].
#[derive(Clone, Copy)]
pub struct ApplyOptions<'a> {
    /// Extra health check after the module's own hash verification.
    pub health: Option<&'a dyn HealthCheck>,
    /// Free-space probe.
    pub disk: Option<&'a dyn DiskProbe>,
    /// Per-file swap hook.
    pub swap_hook: Option<&'a dyn SwapHook>,
    /// Remove `staging_root/<version>` after success. Defaults to true.
    pub cleanup_staging: bool,
}

impl Default for ApplyOptions<'_> {
    fn default() -> Self {
        Self {
            health: None,
            disk: None,
            swap_hook: None,
            cleanup_staging: true,
        }
    }
}

/// The outcome of a successful apply. Retained so [`rollback`] can restore the
/// snapshot later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateReport {
    /// The installation that was updated.
    pub install_root: PathBuf,
    /// The staging directory that held the verified files.
    pub staging_dir: PathBuf,
    /// The snapshot directory inside the install root.
    pub backup_dir: PathBuf,
    /// The version before the update, when a version file existed.
    pub from_version: Option<String>,
    /// The version now installed.
    pub to_version: String,
    /// The caller-provided timestamp used in the snapshot name.
    pub applied_ms: u64,
    /// Files written by the swap (payload paths plus the version file).
    pub files: Vec<String>,
    /// Bytes written by the swap, excluding the snapshot.
    pub bytes_written: u64,
}

/// Apply a verified update with the default seams.
pub fn apply_update(
    verified: &VerifiedUpdate,
    install_root: impl AsRef<Path>,
    staging_root: impl AsRef<Path>,
    now_ms: u64,
) -> Result<UpdateReport> {
    apply_update_with(
        verified,
        install_root,
        staging_root,
        now_ms,
        &ApplyOptions::default(),
    )
}

/// Apply a verified update.
///
/// The install root must exist or be creatable. The staging root must be
/// absolute, outside the install root, and not inside it. On any failure after
/// the snapshot, the previous tree is restored and the returned error reports
/// [`RollbackState::RolledBack`] (or [`RollbackState::RollbackFailed`] with the
/// reason).
pub fn apply_update_with(
    verified: &VerifiedUpdate,
    install_root: impl AsRef<Path>,
    staging_root: impl AsRef<Path>,
    now_ms: u64,
    options: &ApplyOptions<'_>,
) -> Result<UpdateReport> {
    let install_root = install_root.as_ref();
    let staging_root = staging_root.as_ref();
    if !install_root.is_absolute() || !staging_root.is_absolute() {
        return Err(UpdateError::new(
            UpdateErrorKind::PathEscape,
            "install and staging roots must be absolute paths",
        ));
    }
    if staging_root.starts_with(install_root) || install_root.starts_with(staging_root) {
        return Err(UpdateError::new(
            UpdateErrorKind::StagingConflict,
            "the staging root must be outside the install root and must not contain it",
        ));
    }

    verify_verified_update(verified)?;

    fs::create_dir_all(install_root)?;
    let from_version = current_version(install_root)?;
    let existing = collect_files(install_root)?;
    let existing_bytes = existing.iter().map(|(_, size)| size).sum::<u64>();

    let needed = verified
        .total_bytes()
        .checked_add(existing_bytes)
        .and_then(|value| value.checked_add(DISK_HEADROOM_BYTES))
        .ok_or_else(|| {
            UpdateError::new(
                UpdateErrorKind::LimitExceeded,
                "update size overflows the disk-space calculation",
            )
        })?;
    let free = match options.disk {
        Some(probe) => probe.free_bytes(install_root)?,
        None => UnrestrictedDisk.free_bytes(install_root)?,
    };
    if free < needed {
        return Err(UpdateError::new(
            UpdateErrorKind::DiskSpace,
            format!("update needs {needed} bytes but only {free} are available"),
        ));
    }

    let stage_dir = staging_root.join(&verified.version);
    prepare_staging(&stage_dir, &verified.version)?;
    if let Err(error) = stage_files(verified, &stage_dir) {
        let _ = fs::remove_dir_all(&stage_dir);
        return Err(error);
    }
    if let Err(error) = verify_staged(verified, &stage_dir) {
        let _ = fs::remove_dir_all(&stage_dir);
        return Err(error);
    }

    let snapshot = match create_snapshot(install_root, &existing, from_version.as_deref(), now_ms) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let _ = fs::remove_dir_all(&stage_dir);
            return Err(error);
        }
    };

    let mut written = Vec::new();
    let swap = perform_swap(verified, install_root, options, &mut written);
    if let Err(error) = swap {
        let state = match restore_snapshot(install_root, &snapshot, &written) {
            Ok(()) => RollbackState::RolledBack,
            Err(restore) => RollbackState::RollbackFailed(restore.message().to_string()),
        };
        let _ = fs::remove_dir_all(&stage_dir);
        let suffix = if state.restored() {
            "; the pre-update snapshot was restored"
        } else {
            "; rollback failed, the snapshot is kept for manual recovery"
        };
        return Err(UpdateError::with_rollback(
            error.kind(),
            format!("{}{suffix}", error.message()),
            state,
        ));
    }

    if options.cleanup_staging {
        let _ = fs::remove_dir_all(&stage_dir);
    }

    Ok(UpdateReport {
        install_root: install_root.to_path_buf(),
        staging_dir: stage_dir,
        backup_dir: snapshot.dir,
        from_version,
        to_version: verified.version.clone(),
        applied_ms: now_ms,
        files: written,
        bytes_written: verified.total_bytes(),
    })
}

/// Restore the snapshot named by a report.
///
/// Files present before the update are restored and re-hashed; files the update
/// introduced (and the version file) are removed when they were not in the
/// snapshot. The snapshot directory is kept for inspection. The staging
/// directory is removed.
pub fn rollback(report: &UpdateReport) -> Result<()> {
    let backup_dir = &report.backup_dir;
    let name = backup_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            UpdateError::new(
                UpdateErrorKind::PathEscape,
                "the backup directory has no usable name",
            )
        })?;
    if !name.starts_with(BACKUP_DIR_PREFIX)
        || !backup_dir.starts_with(&report.install_root)
        || backup_dir.as_path() == report.install_root.as_path()
    {
        return Err(UpdateError::new(
            UpdateErrorKind::PathEscape,
            "the backup directory is not a snapshot inside the install root",
        ));
    }

    let manifest = read_backup_manifest(backup_dir)?;
    if manifest.version != report.from_version {
        return Err(UpdateError::new(
            UpdateErrorKind::VersionInvalid,
            format!(
                "snapshot version {:?} does not match the report's from_version {:?}",
                manifest.version, report.from_version
            ),
        ));
    }
    let snapshot = Snapshot {
        dir: backup_dir.clone(),
        manifest,
    };
    restore_snapshot(&report.install_root, &snapshot, &report.files)?;
    let _ = fs::remove_dir_all(&report.staging_dir);
    Ok(())
}

fn verify_verified_update(verified: &VerifiedUpdate) -> Result<()> {
    if verified.files.len() > MAX_UPDATE_FILES {
        return Err(UpdateError::new(
            UpdateErrorKind::LimitExceeded,
            format!(
                "verified update has {} files, above the {MAX_UPDATE_FILES} file limit",
                verified.files.len()
            ),
        ));
    }
    let mut total = 0u64;
    let mut hasher = Sha256::new();
    hasher.update(b"zero.update.payload\0v1\0");
    hasher.update((verified.files.len() as u64).to_le_bytes());
    for (path, bytes) in &verified.files {
        validate_relative_path(path)?;
        let len = bytes.len() as u64;
        if len > MAX_UPDATE_FILE_BYTES {
            return Err(UpdateError::new(
                UpdateErrorKind::LimitExceeded,
                format!(
                    "verified file `{path}` is {len} bytes, above the {MAX_UPDATE_FILE_BYTES} byte file limit"
                ),
            ));
        }
        total = total.checked_add(len).ok_or_else(|| {
            UpdateError::new(
                UpdateErrorKind::LimitExceeded,
                "verified update size overflows",
            )
        })?;
        hasher.update((path.len() as u64).to_le_bytes());
        hasher.update(path.as_bytes());
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    if total > MAX_UPDATE_BYTES {
        return Err(UpdateError::new(
            UpdateErrorKind::LimitExceeded,
            format!("verified update is {total} bytes, above the {MAX_UPDATE_BYTES} byte limit"),
        ));
    }
    if hex(&hasher.finalize()) != verified.payload_sha256 {
        return Err(UpdateError::new(
            UpdateErrorKind::ArtifactInvalid,
            "the verified payload no longer matches its recorded digest",
        ));
    }
    Ok(())
}

fn prepare_staging(stage_dir: &Path, version: &str) -> Result<()> {
    if stage_dir.exists() {
        if !stage_dir.is_dir() {
            return Err(UpdateError::new(
                UpdateErrorKind::StagingConflict,
                format!("staging path {} is not a directory", stage_dir.display()),
            ));
        }
        let marker = stage_dir.join(STAGING_MARKER);
        match fs::read_to_string(&marker) {
            Ok(text) if text.trim() == version => {
                fs::remove_dir_all(stage_dir)?;
            }
            Ok(_) => {
                return Err(UpdateError::new(
                    UpdateErrorKind::StagingConflict,
                    format!(
                        "staging directory {} belongs to another version",
                        stage_dir.display()
                    ),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(UpdateError::new(
                    UpdateErrorKind::StagingConflict,
                    format!(
                        "staging directory {} exists without a version marker",
                        stage_dir.display()
                    ),
                ));
            }
            Err(error) => return Err(error.into()),
        }
    }
    fs::create_dir_all(stage_dir)?;
    write_synced(
        &stage_dir.join(STAGING_MARKER),
        format!("{version}\n").as_bytes(),
    )
}

fn stage_files(verified: &VerifiedUpdate, stage_dir: &Path) -> Result<()> {
    for (path, bytes) in verified.files() {
        let relative = relative_path(path)?;
        let target = stage_dir.join(relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        write_new_synced(&target, bytes)?;
    }
    Ok(())
}

fn verify_staged(verified: &VerifiedUpdate, stage_dir: &Path) -> Result<()> {
    for (path, expected) in verified.files() {
        let target = stage_dir.join(relative_path(path)?);
        let actual = fs::read(&target)?;
        if actual != expected {
            return Err(UpdateError::new(
                UpdateErrorKind::ArtifactInvalid,
                format!("staged file `{path}` does not match the verified payload"),
            ));
        }
    }
    Ok(())
}

fn perform_swap(
    verified: &VerifiedUpdate,
    install_root: &Path,
    options: &ApplyOptions<'_>,
    written: &mut Vec<String>,
) -> Result<()> {
    for (index, (path, bytes)) in verified.files().enumerate() {
        if let Some(hook) = options.swap_hook {
            hook.before_swap(index, path, install_root)?;
        }
        let target = install_root.join(relative_path(path)?);
        write_atomic(&target, bytes)?;
        written.push(path.to_string());
    }

    let version_bytes = format!("{}\n", verified.version);
    write_atomic(&install_root.join(VERSION_FILE), version_bytes.as_bytes())?;
    written.push(VERSION_FILE.to_string());

    verify_installed(verified, install_root)?;

    if let Some(health) = options.health {
        health.healthy(install_root)?;
    }
    Ok(())
}

fn verify_installed(verified: &VerifiedUpdate, install_root: &Path) -> Result<()> {
    for (path, expected) in verified.files() {
        let target = install_root.join(relative_path(path)?);
        let actual = fs::read(&target)?;
        if actual != expected {
            return Err(UpdateError::new(
                UpdateErrorKind::HealthCheck,
                format!("installed file `{path}` does not match the verified payload"),
            ));
        }
    }
    let version = current_version(install_root)?;
    if version.as_deref() != Some(verified.version.as_str()) {
        return Err(UpdateError::new(
            UpdateErrorKind::HealthCheck,
            format!(
                "version file reads {:?} after installing {}",
                version, verified.version
            ),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupFile {
    path: String,
    sha256: String,
    bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupManifest {
    schema_version: u32,
    version: Option<String>,
    created_ms: u64,
    files: Vec<BackupFile>,
}

#[derive(Debug, Clone)]
struct Snapshot {
    dir: PathBuf,
    manifest: BackupManifest,
}

fn create_snapshot(
    install_root: &Path,
    existing: &[(String, u64)],
    version: Option<&str>,
    now_ms: u64,
) -> Result<Snapshot> {
    let dir = unique_backup_dir(install_root, version, now_ms)?;
    let built = build_snapshot(&dir, install_root, existing, version, now_ms);
    if built.is_err() {
        let _ = fs::remove_dir_all(&dir);
    }
    built
}

fn build_snapshot(
    dir: &Path,
    install_root: &Path,
    existing: &[(String, u64)],
    version: Option<&str>,
    now_ms: u64,
) -> Result<Snapshot> {
    fs::create_dir_all(dir)?;

    let mut files = Vec::with_capacity(existing.len());
    for (path, _) in existing {
        let relative = relative_path(path)?;
        let source = install_root.join(&relative);
        let destination = dir.join(&relative);
        let (bytes, sha256) = copy_with_hash(&source, &destination)?;
        files.push(BackupFile {
            path: path.clone(),
            sha256,
            bytes,
        });
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));

    let manifest = BackupManifest {
        schema_version: UPDATE_SCHEMA_VERSION,
        version: version.map(str::to_string),
        created_ms: now_ms,
        files,
    };
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    write_atomic(&dir.join(BACKUP_MANIFEST), &bytes)?;
    Ok(Snapshot {
        dir: dir.to_path_buf(),
        manifest,
    })
}

fn unique_backup_dir(install_root: &Path, version: Option<&str>, now_ms: u64) -> Result<PathBuf> {
    let label = match version {
        Some(version) if is_valid_version(version) => version,
        _ => "unknown",
    };
    let base = format!("{BACKUP_DIR_PREFIX}{label}-{now_ms}");
    for suffix in 0..64 {
        let name = if suffix == 0 {
            base.clone()
        } else {
            format!("{base}-{suffix}")
        };
        let candidate = install_root.join(name);
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(UpdateError::new(
        UpdateErrorKind::StagingConflict,
        "too many snapshots for this version and timestamp",
    ))
}

fn read_backup_manifest(dir: &Path) -> Result<BackupManifest> {
    let path = dir.join(BACKUP_MANIFEST);
    let metadata = fs::metadata(&path)?;
    if metadata.len() > MAX_BACKUP_MANIFEST_BYTES {
        return Err(UpdateError::new(
            UpdateErrorKind::LimitExceeded,
            format!(
                "backup manifest is {} bytes, above the {MAX_BACKUP_MANIFEST_BYTES} byte limit",
                metadata.len()
            ),
        ));
    }
    let bytes = fs::read(&path)?;
    let manifest: BackupManifest = serde_json::from_slice(&bytes)?;
    if manifest.schema_version != UPDATE_SCHEMA_VERSION {
        return Err(UpdateError::new(
            UpdateErrorKind::ManifestInvalid,
            format!(
                "backup manifest schema {} is not the supported schema {UPDATE_SCHEMA_VERSION}",
                manifest.schema_version
            ),
        ));
    }
    let mut seen = BTreeSet::new();
    for file in &manifest.files {
        validate_relative_path(&file.path)?;
        if !seen.insert(file.path.as_str()) {
            return Err(UpdateError::new(
                UpdateErrorKind::ManifestInvalid,
                format!("backup manifest repeats `{}`", file.path),
            ));
        }
    }
    Ok(manifest)
}

fn restore_snapshot(install_root: &Path, snapshot: &Snapshot, written: &[String]) -> Result<()> {
    let mut restored = BTreeSet::new();
    for file in &snapshot.manifest.files {
        let relative = relative_path(&file.path)?;
        let source = snapshot.dir.join(&relative);
        let target = install_root.join(&relative);
        restore_copy(&source, &target, file).map_err(|error| {
            UpdateError::new(
                UpdateErrorKind::RollbackFailed,
                format!(
                    "restored file `{}` does not match the snapshot manifest: {}",
                    file.path,
                    error.message()
                ),
            )
        })?;
        restored.insert(file.path.as_str());
    }

    let mut seen = BTreeSet::new();
    for path in written {
        if !seen.insert(path.as_str()) {
            continue;
        }
        if restored.contains(path.as_str()) {
            continue;
        }
        let target = install_root.join(relative_path(path)?);
        match fs::remove_file(&target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }

    match snapshot.manifest.version.as_deref() {
        Some(version) => {
            let actual = current_version(install_root)?;
            if actual.as_deref() != Some(version) {
                return Err(UpdateError::new(
                    UpdateErrorKind::RollbackFailed,
                    format!("version file reads {actual:?} after restoring {version}"),
                ));
            }
        }
        None => {
            let version_path = install_root.join(VERSION_FILE);
            match fs::remove_file(&version_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

fn collect_files(root: &Path) -> Result<Vec<(String, u64)>> {
    let mut out = Vec::new();
    if !root.exists() {
        return Ok(out);
    }
    if !root.is_dir() {
        return Err(UpdateError::new(
            UpdateErrorKind::PathEscape,
            format!("install root {} is not a directory", root.display()),
        ));
    }
    collect_into(root, root, &mut out)?;
    out.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(out)
}

fn collect_into(root: &Path, directory: &Path, out: &mut Vec<(String, u64)>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(UpdateError::new(
                UpdateErrorKind::PathEscape,
                format!(
                    "install tree contains the symlink {}",
                    entry.path().display()
                ),
            ));
        }
        let path = entry.path();
        let file_name = entry.file_name();
        let file_name = file_name.to_str().ok_or_else(|| {
            UpdateError::new(
                UpdateErrorKind::PathEscape,
                format!("install tree contains a non-UTF-8 name: {}", path.display()),
            )
        })?;
        if file_name.starts_with(TEMP_PREFIX) {
            continue;
        }
        let relative = relative_key(root, &path)?;
        if file_type.is_dir() {
            if relative.starts_with(BACKUP_DIR_PREFIX) && !relative.contains('/') {
                continue;
            }
            collect_into(root, &path, out)?;
        } else if file_type.is_file() {
            out.push((relative, entry.metadata()?.len()));
        } else {
            return Err(UpdateError::new(
                UpdateErrorKind::PathEscape,
                format!("install tree contains a special file: {}", path.display()),
            ));
        }
    }
    Ok(())
}

fn relative_key(root: &Path, path: &Path) -> Result<String> {
    let relative = path.strip_prefix(root).map_err(|_| {
        UpdateError::new(
            UpdateErrorKind::PathEscape,
            format!("{} is outside the install root", path.display()),
        )
    })?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(name) => match name.to_str() {
                Some(name) => parts.push(name.to_string()),
                None => {
                    return Err(UpdateError::new(
                        UpdateErrorKind::PathEscape,
                        format!("{} has a non-UTF-8 name", path.display()),
                    ));
                }
            },
            _ => {
                return Err(UpdateError::new(
                    UpdateErrorKind::PathEscape,
                    format!("{} is not a plain relative path", path.display()),
                ));
            }
        }
    }
    Ok(parts.join("/"))
}

fn relative_path(key: &str) -> Result<PathBuf> {
    validate_relative_path(key)?;
    let mut out = PathBuf::new();
    for part in key.split('/') {
        out.push(part);
    }
    Ok(out)
}

fn validate_relative_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(path_error("a payload path must not be empty"));
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(UpdateError::new(
            UpdateErrorKind::LimitExceeded,
            format!("payload path is longer than {MAX_PATH_BYTES} bytes"),
        ));
    }
    if path.contains('\\') {
        return Err(path_error("a payload path must use `/`, not `\\`"));
    }
    if path.contains(':') {
        return Err(path_error(
            "a payload path must not contain a drive or stream separator",
        ));
    }
    if path.chars().any(char::is_control) {
        return Err(path_error(
            "a payload path must not contain a control character",
        ));
    }
    if path.starts_with('/') {
        return Err(path_error("a payload path must be relative"));
    }

    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > MAX_PATH_DEPTH {
        return Err(UpdateError::new(
            UpdateErrorKind::LimitExceeded,
            format!("payload path is deeper than {MAX_PATH_DEPTH} components"),
        ));
    }
    for part in parts {
        if part.is_empty() {
            return Err(path_error(
                "a payload path must not contain an empty component",
            ));
        }
        if part == "." || part == ".." {
            return Err(path_error("a payload path must not contain `.` or `..`"));
        }
        if part.ends_with(' ') || part.ends_with('.') {
            return Err(path_error(
                "a payload path component must not end with a space or a dot",
            ));
        }
        if is_reserved_windows_name(part) {
            return Err(path_error(
                "a payload path must not use a reserved Windows device name",
            ));
        }
    }

    let candidate = Path::new(path);
    if candidate.is_absolute() {
        return Err(path_error("a payload path must be relative"));
    }
    for component in candidate.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(path_error(
                "a payload path must contain only normal components",
            ));
        }
    }
    Ok(())
}

fn is_reserved_windows_name(part: &str) -> bool {
    let stem = part.split('.').next().unwrap_or(part).to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit())
}

fn path_error(message: impl Into<String>) -> UpdateError {
    UpdateError::new(UpdateErrorKind::PathEscape, message)
}

fn is_valid_version(version: &str) -> bool {
    if version.is_empty() || version.len() > MAX_VERSION_BYTES {
        return false;
    }
    let first = version.as_bytes()[0];
    if !first.is_ascii_alphanumeric() || version.contains("..") {
        return false;
    }
    version
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'))
}

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = temporary_path(path)?;
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&temporary, path).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        UpdateError::from(error)
    })
}

fn temporary_path(path: &Path) -> Result<PathBuf> {
    let parent = path.parent().ok_or_else(|| {
        UpdateError::new(
            UpdateErrorKind::PathEscape,
            format!("{} has no parent directory", path.display()),
        )
    })?;
    fs::create_dir_all(parent)?;
    let file_name = path.file_name().ok_or_else(|| {
        UpdateError::new(
            UpdateErrorKind::PathEscape,
            format!("{} has no file name", path.display()),
        )
    })?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut temporary_name = file_name.to_os_string();
    temporary_name.push(format!("{TEMP_PREFIX}{}-{sequence}", std::process::id()));
    Ok(parent.join(temporary_name))
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn copy_with_hash(source: &Path, destination: &Path) -> Result<(u64, String)> {
    let (temporary, bytes, digest) = copy_to_temp_with_hash(source, destination)?;
    fs::rename(&temporary, destination).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        UpdateError::from(error)
    })?;
    Ok((bytes, digest))
}

fn restore_copy(source: &Path, destination: &Path, expected: &BackupFile) -> Result<()> {
    let (temporary, bytes, digest) = copy_to_temp_with_hash(source, destination)?;
    if bytes != expected.bytes || digest != expected.sha256 {
        let _ = fs::remove_file(&temporary);
        return Err(UpdateError::new(
            UpdateErrorKind::RollbackFailed,
            "the snapshot copy does not match its recorded hash",
        ));
    }
    fs::rename(&temporary, destination).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        UpdateError::from(error)
    })
}

fn copy_to_temp_with_hash(source: &Path, destination: &Path) -> Result<(PathBuf, u64, String)> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = temporary_path(destination)?;
    let copied = copy_into_temp(source, &temporary);
    match copied {
        Ok((bytes, digest)) => Ok((temporary, bytes, digest)),
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(error)
        }
    }
}

fn copy_into_temp(source: &Path, temporary: &Path) -> Result<(u64, String)> {
    let mut input = fs::File::open(source)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temporary)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        output.write_all(&buffer[..read])?;
        total = total.checked_add(read as u64).ok_or_else(|| {
            UpdateError::new(UpdateErrorKind::LimitExceeded, "file size overflows")
        })?;
    }
    output.sync_all()?;
    Ok((total, hex(&hasher.finalize())))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packaging::{
        artifact_name, sbom_from_cargo_lock, sign_manifest, Artifact, ReleaseManifest,
    };
    use ed25519_dalek::SigningKey;

    /// Test-only seed for the placeholder embedded key. It matches the seed in
    /// the packaging tests, so the embedded-key path is exercised end to end.
    const EMBEDDED_TEST_SEED: [u8; 32] = [0x42; 32];
    const TARGET: &str = "x86_64-unknown-linux-gnu";
    const OLD_VERSION: &str = "0.1.0";
    const NEW_VERSION: &str = "0.2.0";
    const GIT_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn key() -> SigningKey {
        SigningKey::from_bytes(&EMBEDDED_TEST_SEED)
    }

    fn artifact(files: &[(&str, &[u8])], version: &str, target: &str) -> UpdateArtifact {
        let mut payload = UpdatePayload::new();
        for (path, bytes) in files {
            payload
                .insert(*path, bytes.to_vec())
                .expect("valid payload path");
        }
        let manifest = ReleaseManifest::new(
            version,
            GIT_SHA,
            1_764_000_000_000,
            "stable",
            vec![Artifact {
                target: target.to_string(),
                name: artifact_name(target, version).expect("helper name"),
                sha256: payload.sha256(),
                bytes: payload.total_bytes(),
            }],
            sbom_from_cargo_lock("version = 4\n", version),
        )
        .expect("valid manifest");
        let signed = sign_manifest(&manifest, &key()).expect("sign");
        UpdateArtifact::new(signed, payload)
    }

    fn policy<'a>(current: Option<&'a str>, allow_downgrade: bool) -> UpdatePolicy<'a> {
        UpdatePolicy {
            expected_target: TARGET,
            current_version: current,
            allow_downgrade,
        }
    }

    fn populate_install(root: &Path) {
        fs::create_dir_all(root.join("bin")).expect("bin dir");
        fs::create_dir_all(root.join("share")).expect("share dir");
        fs::create_dir_all(root.join("data")).expect("data dir");
        fs::write(root.join("bin/zero"), b"old-binary").expect("old binary");
        fs::write(root.join("share/readme.txt"), b"old readme").expect("old readme");
        fs::write(root.join("data/state.txt"), b"keep me").expect("user data");
        fs::write(root.join(VERSION_FILE), format!("{OLD_VERSION}\n")).expect("version file");
    }

    fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
        fn walk(root: &Path, directory: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
            for entry in fs::read_dir(directory).expect("read dir").flatten() {
                let path = entry.path();
                let relative = path
                    .strip_prefix(root)
                    .expect("inside root")
                    .to_string_lossy()
                    .replace('\\', "/");
                if path.is_dir() {
                    if path.parent() == Some(root) && relative.starts_with(BACKUP_DIR_PREFIX) {
                        continue;
                    }
                    walk(root, &path, out);
                } else if !entry.file_name().to_string_lossy().starts_with(TEMP_PREFIX) {
                    out.insert(relative, fs::read(&path).expect("read file"));
                }
            }
        }
        let mut out = BTreeMap::new();
        if root.exists() {
            walk(root, root, &mut out);
        }
        out
    }

    struct FailingHealth;

    impl HealthCheck for FailingHealth {
        fn healthy(&self, _install_root: &Path) -> Result<()> {
            Err(UpdateError::new(
                UpdateErrorKind::HealthCheck,
                "injected health-check failure",
            ))
        }
    }

    struct FixedDisk(u64);

    impl DiskProbe for FixedDisk {
        fn free_bytes(&self, _path: &Path) -> Result<u64> {
            Ok(self.0)
        }
    }

    struct FailSwapAt(usize);

    impl SwapHook for FailSwapAt {
        fn before_swap(&self, index: usize, relative: &str, _install_root: &Path) -> Result<()> {
            if index == self.0 {
                return Err(UpdateError::new(
                    UpdateErrorKind::Io,
                    format!("injected swap failure at `{relative}`"),
                ));
            }
            Ok(())
        }
    }

    #[test]
    fn valid_update_stages_verifies_installs_and_bumps_version() {
        let directory = tempfile::tempdir().expect("tempdir");
        let install = directory.path().join("install");
        let staging = directory.path().join("staging");
        populate_install(&install);

        let artifact = artifact(
            &[
                ("bin/zero", b"new-binary"),
                ("share/notes.txt", b"release notes"),
            ],
            NEW_VERSION,
            TARGET,
        );
        let verified = verify_update(&artifact, &policy(Some(OLD_VERSION), false)).expect("verify");
        assert_eq!(verified.version(), NEW_VERSION);
        assert_eq!(verified.target(), TARGET);
        assert_eq!(verified.channel(), "stable");
        assert_eq!(verified.file_count(), 2);
        assert_eq!(verified.payload_sha256(), artifact.payload.sha256());
        assert!(!verified.manifest_hash().is_empty());

        let report = apply_update(&verified, &install, &staging, 1_000).expect("apply");

        assert_eq!(report.from_version.as_deref(), Some(OLD_VERSION));
        assert_eq!(report.to_version, NEW_VERSION);
        assert_eq!(report.applied_ms, 1_000);
        assert_eq!(report.bytes_written, verified.total_bytes());
        assert!(report.backup_dir.is_dir());
        assert!(report.backup_dir.starts_with(&install));
        assert!(
            !report.staging_dir.exists(),
            "staging is cleaned on success"
        );
        assert_eq!(
            fs::read(install.join("bin/zero")).expect("new binary"),
            b"new-binary"
        );
        assert_eq!(
            fs::read(install.join("share/notes.txt")).expect("new notes"),
            b"release notes"
        );
        assert_eq!(
            fs::read(install.join("data/state.txt")).expect("user data kept"),
            b"keep me"
        );
        assert_eq!(
            current_version(&install).expect("read version").as_deref(),
            Some(NEW_VERSION)
        );
        assert!(report.files.contains(&VERSION_FILE.to_string()));

        let backup_manifest = read_backup_manifest(&report.backup_dir).expect("backup manifest");
        assert_eq!(backup_manifest.version.as_deref(), Some(OLD_VERSION));
        assert_eq!(backup_manifest.files.len(), 4);
        assert!(backup_manifest
            .files
            .iter()
            .any(|file| file.path == VERSION_FILE));
    }

    #[test]
    fn corrupted_payload_is_refused_before_any_swap() {
        let directory = tempfile::tempdir().expect("tempdir");
        let install = directory.path().join("install");
        populate_install(&install);
        let before = tree(&install);

        let mut artifact = artifact(&[("bin/zero", b"new-binary")], NEW_VERSION, TARGET);
        artifact
            .payload
            .insert("bin/zero", b"tampered".to_vec())
            .expect("valid path");
        let error = verify_update(&artifact, &policy(Some(OLD_VERSION), false)).unwrap_err();
        assert_eq!(error.kind(), UpdateErrorKind::ArtifactInvalid);
        assert_eq!(*error.rollback_state(), RollbackState::NotNeeded);
        assert_eq!(
            tree(&install),
            before,
            "a refused update never touches the tree"
        );

        let error = apply_update(
            &VerifiedUpdate {
                version: NEW_VERSION.to_string(),
                target: TARGET.to_string(),
                channel: "stable".to_string(),
                manifest_hash: "0".repeat(64),
                payload_sha256: "0".repeat(64),
                files: BTreeMap::new(),
            },
            &install,
            directory.path().join("staging"),
            1_000,
        )
        .unwrap_err();
        assert_eq!(error.kind(), UpdateErrorKind::ArtifactInvalid);
        assert_eq!(tree(&install), before);
    }

    #[test]
    fn health_check_failure_restores_the_backup_byte_for_byte() {
        let directory = tempfile::tempdir().expect("tempdir");
        let install = directory.path().join("install");
        let staging = directory.path().join("staging");
        populate_install(&install);
        let before = tree(&install);

        let artifact = artifact(
            &[
                ("bin/zero", b"new-binary"),
                ("share/readme.txt", b"new readme"),
            ],
            NEW_VERSION,
            TARGET,
        );
        let verified = verify_update(&artifact, &policy(Some(OLD_VERSION), false)).expect("verify");
        let options = ApplyOptions {
            health: Some(&FailingHealth),
            ..ApplyOptions::default()
        };
        let error = apply_update_with(&verified, &install, &staging, 1_000, &options).unwrap_err();

        assert_eq!(error.kind(), UpdateErrorKind::HealthCheck);
        assert_eq!(*error.rollback_state(), RollbackState::RolledBack);
        assert!(error.message().contains("snapshot was restored"), "{error}");
        assert_eq!(
            tree(&install),
            before,
            "the previous tree is restored byte for byte"
        );
        assert_eq!(
            current_version(&install).expect("version").as_deref(),
            Some(OLD_VERSION)
        );
        assert!(
            !staging.join(NEW_VERSION).exists(),
            "staging is cleaned on failure"
        );
    }

    #[test]
    fn a_mid_swap_failure_rolls_back() {
        let directory = tempfile::tempdir().expect("tempdir");
        let install = directory.path().join("install");
        let staging = directory.path().join("staging");
        populate_install(&install);
        let before = tree(&install);

        let artifact = artifact(
            &[
                ("bin/zero", b"new-binary"),
                ("share/a.txt", b"a"),
                ("share/b.txt", b"b"),
            ],
            NEW_VERSION,
            TARGET,
        );
        let verified = verify_update(&artifact, &policy(Some(OLD_VERSION), false)).expect("verify");
        let hook = FailSwapAt(2);
        let options = ApplyOptions {
            swap_hook: Some(&hook),
            ..ApplyOptions::default()
        };
        let error = apply_update_with(&verified, &install, &staging, 1_000, &options).unwrap_err();

        assert_eq!(error.kind(), UpdateErrorKind::Io);
        assert_eq!(*error.rollback_state(), RollbackState::RolledBack);
        assert_eq!(
            tree(&install),
            before,
            "files swapped before the failure are reverted"
        );
        assert!(!staging.join(NEW_VERSION).exists());
    }

    #[test]
    fn downgrade_is_refused_unless_allowed() {
        let artifact = artifact(&[("bin/zero", b"older")], OLD_VERSION, TARGET);

        let error = verify_update(&artifact, &policy(Some("0.2.0"), false)).unwrap_err();
        assert_eq!(error.kind(), UpdateErrorKind::DowngradeRefused);

        let verified =
            verify_update(&artifact, &policy(Some("0.2.0"), true)).expect("explicit downgrade");
        assert_eq!(verified.version(), OLD_VERSION);

        let verified =
            verify_update(&artifact, &policy(Some(OLD_VERSION), false)).expect("same version");
        assert_eq!(verified.version(), OLD_VERSION);

        let verified = verify_update(&artifact, &policy(None, false)).expect("fresh install");
        assert_eq!(verified.version(), OLD_VERSION);

        let error = verify_update(&artifact, &policy(Some("../0.1.0"), false)).unwrap_err();
        assert_eq!(error.kind(), UpdateErrorKind::VersionInvalid);
    }

    #[test]
    fn version_comparison_follows_semver_order() {
        use std::cmp::Ordering;
        assert_eq!(compare_versions("0.1.0", "0.1.0"), Ordering::Equal);
        assert_eq!(compare_versions("0.1.0", "0.1.1"), Ordering::Less);
        assert_eq!(compare_versions("0.10.0", "0.9.9"), Ordering::Greater);
        assert_eq!(compare_versions("1.0", "1.0.0"), Ordering::Equal);
        assert_eq!(compare_versions("1.0.0-beta.1", "1.0.0"), Ordering::Less);
        assert_eq!(
            compare_versions("1.0.0-beta.2", "1.0.0-beta.10"),
            Ordering::Less
        );
        assert_eq!(
            compare_versions("1.0.0-alpha", "1.0.0-beta"),
            Ordering::Less
        );
        assert_eq!(compare_versions("1.0.0+build.7", "1.0.0"), Ordering::Equal);
        assert_eq!(compare_versions("2.0.0", "10.0.0"), Ordering::Less);
    }

    #[test]
    fn path_escapes_and_reserved_names_are_refused() {
        let mut payload = UpdatePayload::new();
        for path in [
            "../evil",
            "/etc/passwd",
            "a/../../b",
            "a\\b",
            "C:/windows",
            "",
            "a//b",
            "a/./b",
            "a/",
            "con.txt",
            "LPT1",
            "trailing.",
            "trailing ",
        ] {
            let error = payload.insert(path, b"x".to_vec()).unwrap_err();
            assert_eq!(
                error.kind(),
                UpdateErrorKind::PathEscape,
                "path `{path}` was not refused: {error}"
            );
        }
        assert!(payload.insert("bin/zero.exe", b"x".to_vec()).is_ok());
        assert!(payload
            .insert("share/docs/readme.md", b"x".to_vec())
            .is_ok());
        assert_eq!(payload.len(), 2);
    }

    #[test]
    fn payload_limits_are_enforced() {
        let mut payload = UpdatePayload::new();
        let long = "a".repeat(MAX_PATH_BYTES + 1);
        assert_eq!(
            payload.insert(long, b"x".to_vec()).unwrap_err().kind(),
            UpdateErrorKind::LimitExceeded
        );

        let deep = vec!["d"; MAX_PATH_DEPTH + 1].join("/");
        assert_eq!(
            payload.insert(deep, b"x".to_vec()).unwrap_err().kind(),
            UpdateErrorKind::LimitExceeded
        );

        let oversized = vec![0u8; MAX_UPDATE_FILE_BYTES as usize + 1];
        assert_eq!(
            payload.insert("big", oversized).unwrap_err().kind(),
            UpdateErrorKind::LimitExceeded
        );

        let mut many = UpdatePayload::new();
        for index in 0..MAX_UPDATE_FILES {
            many.insert(format!("d/{index}"), Vec::new())
                .expect("under the limit");
        }
        let error = many.insert("d/one-too-many", Vec::new()).unwrap_err();
        assert_eq!(error.kind(), UpdateErrorKind::LimitExceeded);
    }

    #[test]
    fn wrong_target_missing_signature_and_missing_digest_are_refused() {
        let artifact = artifact(&[("bin/zero", b"new")], NEW_VERSION, TARGET);

        let wrong = UpdatePolicy {
            expected_target: "x86_64-pc-windows-msvc",
            current_version: None,
            allow_downgrade: false,
        };
        assert_eq!(
            verify_update(&artifact, &wrong).unwrap_err().kind(),
            UpdateErrorKind::WrongTarget
        );

        let unsupported = UpdatePolicy {
            expected_target: "wasm32-unknown-unknown",
            current_version: None,
            allow_downgrade: false,
        };
        assert_eq!(
            verify_update(&artifact, &unsupported).unwrap_err().kind(),
            UpdateErrorKind::WrongTarget
        );

        let mut bad_signature = artifact.clone();
        bad_signature.release.signature_b64.clear();
        assert_eq!(
            verify_update(&bad_signature, &policy(None, false))
                .unwrap_err()
                .kind(),
            UpdateErrorKind::SignatureInvalid
        );

        let mut short_signature = artifact.clone();
        short_signature.release.signature_b64 = "AAAA".to_string();
        assert_eq!(
            verify_update(&short_signature, &policy(None, false))
                .unwrap_err()
                .kind(),
            UpdateErrorKind::SignatureInvalid
        );

        let mut missing_digest = artifact.clone();
        missing_digest.release.manifest.artifacts[0].sha256.clear();
        assert_eq!(
            verify_update(&missing_digest, &policy(None, false))
                .unwrap_err()
                .kind(),
            UpdateErrorKind::ArtifactInvalid
        );

        let wrong_key = artifact;
        let other = SigningKey::from_bytes(&[0x24; 32]);
        assert_eq!(
            verify_update_with_key(&wrong_key, &policy(None, false), &other.verifying_key())
                .unwrap_err()
                .kind(),
            UpdateErrorKind::SignatureInvalid
        );
    }

    #[test]
    fn staging_from_another_version_is_refused_and_same_version_is_cleaned() {
        let directory = tempfile::tempdir().expect("tempdir");
        let install = directory.path().join("install");
        let staging = directory.path().join("staging");
        populate_install(&install);
        let before = tree(&install);

        let stage_dir = staging.join(NEW_VERSION);
        fs::create_dir_all(&stage_dir).expect("staging dir");
        fs::write(stage_dir.join(STAGING_MARKER), "0.1.5\n").expect("marker");
        fs::write(stage_dir.join("junk"), b"junk").expect("junk");

        let artifact = artifact(&[("bin/zero", b"new")], NEW_VERSION, TARGET);
        let verified = verify_update(&artifact, &policy(Some(OLD_VERSION), false)).expect("verify");

        let error = apply_update(&verified, &install, &staging, 1_000).unwrap_err();
        assert_eq!(error.kind(), UpdateErrorKind::StagingConflict);
        assert_eq!(tree(&install), before);
        assert!(
            stage_dir.exists(),
            "a foreign staging directory is left alone"
        );

        fs::write(stage_dir.join(STAGING_MARKER), format!("{NEW_VERSION}\n")).expect("marker");
        let report = apply_update(&verified, &install, &staging, 1_000).expect("apply");
        assert!(
            !stage_dir.join("junk").exists(),
            "stale same-version staging is cleaned"
        );
        assert!(!report.staging_dir.exists());
        assert_eq!(fs::read(install.join("bin/zero")).expect("binary"), b"new");

        let unmarked = directory.path().join("unmarked").join(NEW_VERSION);
        fs::create_dir_all(&unmarked).expect("unmarked dir");
        let error = apply_update(
            &verified,
            &install,
            directory.path().join("unmarked"),
            1_001,
        )
        .unwrap_err();
        assert_eq!(error.kind(), UpdateErrorKind::StagingConflict);
    }

    #[test]
    fn staging_roots_must_be_absolute_and_outside_the_install_root() {
        let directory = tempfile::tempdir().expect("tempdir");
        let install = directory.path().join("install");
        populate_install(&install);
        let artifact = artifact(&[("bin/zero", b"new")], NEW_VERSION, TARGET);
        let verified = verify_update(&artifact, &policy(Some(OLD_VERSION), false)).expect("verify");
        let before = tree(&install);

        let error = apply_update(&verified, &install, install.join("staging"), 1_000).unwrap_err();
        assert_eq!(error.kind(), UpdateErrorKind::StagingConflict);

        let error = apply_update(
            &verified,
            Path::new("relative"),
            directory.path().join("s"),
            1_000,
        )
        .unwrap_err();
        assert_eq!(error.kind(), UpdateErrorKind::PathEscape);
        assert_eq!(tree(&install), before);
    }

    #[test]
    fn an_insufficient_disk_probe_refuses_before_staging() {
        let directory = tempfile::tempdir().expect("tempdir");
        let install = directory.path().join("install");
        let staging = directory.path().join("staging");
        populate_install(&install);
        let before = tree(&install);

        let artifact = artifact(&[("bin/zero", b"new")], NEW_VERSION, TARGET);
        let verified = verify_update(&artifact, &policy(Some(OLD_VERSION), false)).expect("verify");
        let probe = FixedDisk(1);
        let options = ApplyOptions {
            disk: Some(&probe),
            ..ApplyOptions::default()
        };
        let error = apply_update_with(&verified, &install, &staging, 1_000, &options).unwrap_err();

        assert_eq!(error.kind(), UpdateErrorKind::DiskSpace);
        assert_eq!(*error.rollback_state(), RollbackState::NotNeeded);
        assert_eq!(tree(&install), before);
        assert!(
            !staging.exists(),
            "nothing is staged without room to stage it"
        );
    }

    #[test]
    fn explicit_rollback_restores_the_pre_update_tree() {
        let directory = tempfile::tempdir().expect("tempdir");
        let install = directory.path().join("install");
        let staging = directory.path().join("staging");
        populate_install(&install);
        let before = tree(&install);

        let artifact = artifact(
            &[("bin/zero", b"new-binary"), ("share/notes.txt", b"notes")],
            NEW_VERSION,
            TARGET,
        );
        let verified = verify_update(&artifact, &policy(Some(OLD_VERSION), false)).expect("verify");
        let report = apply_update(&verified, &install, &staging, 1_000).expect("apply");
        assert_ne!(tree(&install), before);

        rollback(&report).expect("rollback");
        assert_eq!(tree(&install), before);
        assert_eq!(
            current_version(&install).expect("version").as_deref(),
            Some(OLD_VERSION)
        );
        assert!(
            report.backup_dir.is_dir(),
            "the snapshot is kept for inspection"
        );
    }

    #[test]
    fn version_file_round_trips_and_rejects_unsafe_values() {
        let directory = tempfile::tempdir().expect("tempdir");
        let install = directory.path().join("install");
        fs::create_dir_all(&install).expect("install dir");

        assert_eq!(current_version(&install).expect("missing file"), None);
        fs::write(install.join(VERSION_FILE), " 0.3.0 \n").expect("version file");
        assert_eq!(
            current_version(&install).expect("valid").as_deref(),
            Some("0.3.0")
        );

        fs::write(install.join(VERSION_FILE), "../0.3.0\n").expect("bad version file");
        assert_eq!(
            current_version(&install).unwrap_err().kind(),
            UpdateErrorKind::VersionInvalid
        );

        fs::write(install.join(VERSION_FILE), "\n").expect("empty version file");
        assert_eq!(
            current_version(&install).unwrap_err().kind(),
            UpdateErrorKind::VersionInvalid
        );
    }

    #[test]
    fn verify_staged_detects_a_tampered_stage() {
        let directory = tempfile::tempdir().expect("tempdir");
        let stage = directory.path().join("stage");
        let artifact = artifact(
            &[("bin/zero", b"new"), ("share/a.txt", b"a")],
            NEW_VERSION,
            TARGET,
        );
        let verified = verify_update(&artifact, &policy(None, false)).expect("verify");
        prepare_staging(&stage, NEW_VERSION).expect("prepare");
        stage_files(&verified, &stage).expect("stage");
        verify_staged(&verified, &stage).expect("clean stage verifies");

        fs::write(stage.join("share/a.txt"), b"tampered").expect("tamper");
        let error = verify_staged(&verified, &stage).unwrap_err();
        assert_eq!(error.kind(), UpdateErrorKind::ArtifactInvalid);
    }

    #[test]
    fn an_unknown_version_is_still_accepted_as_a_local_package() {
        let directory = tempfile::tempdir().expect("tempdir");
        let install = directory.path().join("install");
        let staging = directory.path().join("staging");
        populate_install(&install);

        let artifact = artifact(&[("bin/zero", b"new")], "0.2.0-rc.1", TARGET);
        let verified = verify_update(&artifact, &policy(Some(OLD_VERSION), false)).expect("verify");
        let report = apply_update(&verified, &install, &staging, 1_000).expect("apply");
        assert_eq!(report.to_version, "0.2.0-rc.1");
        assert_eq!(
            current_version(&install).expect("version").as_deref(),
            Some("0.2.0-rc.1")
        );
    }

    #[test]
    fn the_update_path_has_no_network_or_shell_surface() {
        let source = include_str!("update.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "TcpStream",
            "std::net",
            "reqwest",
            "http://",
            "https://",
            "Command::new",
            "SigningKey::from_bytes",
        ] {
            assert!(
                !production.contains(forbidden),
                "update.rs must not contain `{forbidden}`"
            );
        }
        assert!(
            production.contains("installer work"),
            "the archive seam must be documented"
        );
    }
}
