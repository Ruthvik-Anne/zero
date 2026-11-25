//! Release packaging (T-INST-01): per-platform artifact names, an SBOM derived
//! from `Cargo.lock`, and a release manifest signed with Ed25519.
//!
//! Requirements: INST-01 (stable and beta channels), INST-02 (a manifest signed
//! with an Ed25519 key embedded in the installer), and INST-11 (per-platform
//! artifacts and an SBOM with each release).
//!
//! Everything here is local and offline. There is no network surface: the
//! module only hashes, signs, verifies, and reads or writes one JSON file.
//!
//! The manifest is signed over [`ReleaseManifest::canonical_bytes`], a
//! deterministic binary encoding that sorts artifacts by target and SBOM
//! components by name, version, source, and licence. Two manifests that differ
//! only in list order therefore have the same hash and verify against the same
//! signature.

use std::collections::BTreeSet;
use std::fmt;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Schema version of the release manifest this module writes.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Channels INST-01 requires.
pub const CHANNELS: &[&str] = &["stable", "beta"];

/// The six platforms a release publishes artifacts for (INST-11).
pub const SUPPORTED_TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
];

/// The licence value used when the source of truth is package metadata. The
/// SBOM never guesses a licence (INST-11).
pub const LICENCE_UNKNOWN: &str = "see package metadata";

/// Upper bound on one manifest field.
pub const MAX_FIELD_BYTES: usize = 256;
/// Upper bound on the artifact list.
pub const MAX_ARTIFACTS: usize = 64;
/// Upper bound on the SBOM component list, including the product component.
pub const MAX_SBOM_COMPONENTS: usize = 4096;
/// Upper bound on a signed manifest file accepted by [`load_signed`].
pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

const SHA256_HEX_BYTES: usize = 64;
const PUBLIC_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const MIN_GIT_SHA_BYTES: usize = 7;
const MAX_GIT_SHA_BYTES: usize = 64;

/// PLACEHOLDER Ed25519 public key, base64 (`STANDARD`, padded).
///
/// This is a test key, not a release key. Release tooling replaces this
/// constant with the public half of the offline signing key; the matching
/// private half is never in this repository. The `cfg(test)` helper
/// `embedded_test_signing_key` derives the private half of this placeholder so
/// the embedded-key path is exercised end to end.
pub const EMBEDDED_KEY_B64: &str = "IVL40Zt5HSRFMkLhXy6rbLfP+ntqXtMAl5YOBpiB2xI=";

/// Why a packaging value was refused. Kinds are stable strings for logs and
/// tests; they are local to packaging and are not part of the `zero-types`
/// error taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackagingErrorKind {
    InvalidManifest,
    InvalidSignature,
    InvalidArtifact,
    InvalidSbom,
    UnsupportedTarget,
    LimitExceeded,
    Io,
    Json,
}

impl PackagingErrorKind {
    /// Stable kind string, e.g. `manifest_invalid`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidManifest => "manifest_invalid",
            Self::InvalidSignature => "signature_invalid",
            Self::InvalidArtifact => "artifact_invalid",
            Self::InvalidSbom => "sbom_invalid",
            Self::UnsupportedTarget => "unsupported_target",
            Self::LimitExceeded => "limit_exceeded",
            Self::Io => "io",
            Self::Json => "json",
        }
    }
}

/// A typed packaging error with a kind and a message that never contains key
/// material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackagingError {
    kind: PackagingErrorKind,
    message: String,
}

impl PackagingError {
    fn new(kind: PackagingErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// The stable error kind.
    pub fn kind(&self) -> PackagingErrorKind {
        self.kind
    }

    /// The human-readable message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The stable kind string, e.g. `signature_invalid`.
    pub fn code(&self) -> &'static str {
        self.kind.as_str()
    }
}

impl fmt::Display for PackagingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "zero.packaging.{}: {}", self.kind.as_str(), self.message)
    }
}

impl std::error::Error for PackagingError {}

impl From<std::io::Error> for PackagingError {
    fn from(error: std::io::Error) -> Self {
        Self::new(PackagingErrorKind::Io, error.to_string())
    }
}

impl From<serde_json::Error> for PackagingError {
    fn from(error: serde_json::Error) -> Self {
        Self::new(PackagingErrorKind::Json, error.to_string())
    }
}

type Result<T> = std::result::Result<T, PackagingError>;

/// One per-platform archive published with a release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    /// The platform triple, one of [`SUPPORTED_TARGETS`].
    pub target: String,
    /// The archive file name, produced by [`artifact_name`].
    pub name: String,
    /// Lowercase hex SHA-256 of the archive bytes.
    pub sha256: String,
    /// Archive size in bytes. Zero is refused.
    pub bytes: u64,
}

impl Artifact {
    /// Validate the target, name, digest, and size.
    pub fn validate(&self) -> Result<()> {
        if !SUPPORTED_TARGETS.contains(&self.target.as_str()) {
            return Err(PackagingError::new(
                PackagingErrorKind::UnsupportedTarget,
                format!(
                    "artifact target `{}` is not one of the six release targets",
                    self.target
                ),
            ));
        }
        validate_file_name(&self.name, "artifact name")?;
        if !is_lower_hex_sha256(&self.sha256) {
            return Err(PackagingError::new(
                PackagingErrorKind::InvalidArtifact,
                format!(
                    "artifact `{}` has a sha256 that is not {SHA256_HEX_BYTES} lowercase hex characters",
                    self.name
                ),
            ));
        }
        if self.bytes == 0 {
            return Err(PackagingError::new(
                PackagingErrorKind::InvalidArtifact,
                format!("artifact `{}` must not be empty", self.name),
            ));
        }
        Ok(())
    }
}

/// One SBOM entry. `licence` is never guessed; when the metadata does not name
/// one, [`LICENCE_UNKNOWN`] is used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SbomComponent {
    pub name: String,
    pub version: String,
    pub licence: String,
    pub source: String,
}

impl SbomComponent {
    /// Validate the four text fields.
    pub fn validate(&self) -> Result<()> {
        validate_text(&self.name, "SBOM component name")?;
        validate_text(&self.version, "SBOM component version")?;
        validate_text(&self.licence, "SBOM component licence")?;
        validate_text(&self.source, "SBOM component source")?;
        Ok(())
    }
}

/// The released manifest. Serialization is strict JSON: unknown fields are
/// refused at every level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub schema_version: u32,
    pub version: String,
    pub git_sha: String,
    pub created_ms: u64,
    pub artifacts: Vec<Artifact>,
    pub sbom: Vec<SbomComponent>,
    /// `stable` or `beta` (INST-01).
    pub channel: String,
}

impl ReleaseManifest {
    /// Build a manifest at the current schema version and validate it.
    pub fn new(
        version: impl Into<String>,
        git_sha: impl Into<String>,
        created_ms: u64,
        channel: impl Into<String>,
        artifacts: Vec<Artifact>,
        sbom: Vec<SbomComponent>,
    ) -> Result<Self> {
        let manifest = Self {
            schema_version: MANIFEST_SCHEMA_VERSION,
            version: version.into(),
            git_sha: git_sha.into(),
            created_ms,
            artifacts,
            sbom,
            channel: channel.into(),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validate every field, the channel, unique targets and names, the
    /// helper-produced artifact names, and the SBOM shape.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(PackagingError::new(
                PackagingErrorKind::InvalidManifest,
                format!(
                    "manifest schema {} is not the supported schema {MANIFEST_SCHEMA_VERSION}",
                    self.schema_version
                ),
            ));
        }
        validate_version(&self.version).map_err(|error| {
            PackagingError::new(
                PackagingErrorKind::InvalidManifest,
                format!("manifest version: {}", error.message),
            )
        })?;
        validate_git_sha(&self.git_sha)?;
        if self.created_ms == 0 {
            return Err(PackagingError::new(
                PackagingErrorKind::InvalidManifest,
                "manifest created_ms must be a real timestamp",
            ));
        }
        if !CHANNELS.contains(&self.channel.as_str()) {
            return Err(PackagingError::new(
                PackagingErrorKind::InvalidManifest,
                format!(
                    "manifest channel `{}` is not `stable` or `beta`",
                    self.channel
                ),
            ));
        }
        if self.artifacts.is_empty() {
            return Err(PackagingError::new(
                PackagingErrorKind::InvalidManifest,
                "a release manifest must list at least one artifact",
            ));
        }
        if self.artifacts.len() > MAX_ARTIFACTS {
            return Err(PackagingError::new(
                PackagingErrorKind::LimitExceeded,
                format!(
                    "manifest lists {} artifacts, above the {MAX_ARTIFACTS} artifact limit",
                    self.artifacts.len()
                ),
            ));
        }

        let mut targets = BTreeSet::new();
        let mut names = BTreeSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            if !targets.insert(artifact.target.as_str()) {
                return Err(PackagingError::new(
                    PackagingErrorKind::InvalidManifest,
                    format!("duplicate artifact target `{}`", artifact.target),
                ));
            }
            if !names.insert(artifact.name.as_str()) {
                return Err(PackagingError::new(
                    PackagingErrorKind::InvalidManifest,
                    format!("duplicate artifact name `{}`", artifact.name),
                ));
            }
        }
        for artifact in &self.artifacts {
            let expected = artifact_name(&artifact.target, &self.version)?;
            if artifact.name != expected {
                return Err(PackagingError::new(
                    PackagingErrorKind::InvalidArtifact,
                    format!(
                        "artifact name `{}` does not match the release helper name `{expected}`",
                        artifact.name
                    ),
                ));
            }
        }

        validate_sbom(&self.sbom)
    }

    /// Deterministic bytes the signature covers.
    ///
    /// Binary, length-prefixed, and independent of list order. The tag keeps a
    /// manifest signature from being confused with any other signed document.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(b"zero.release.manifest\0v1\0");
        push_u32(&mut out, self.schema_version);
        push_bytes(&mut out, self.version.as_bytes());
        push_bytes(&mut out, self.git_sha.as_bytes());
        push_u64(&mut out, self.created_ms);
        push_bytes(&mut out, self.channel.as_bytes());

        let mut artifacts: Vec<&Artifact> = self.artifacts.iter().collect();
        artifacts.sort_by(|a, b| (&a.target, &a.name).cmp(&(&b.target, &b.name)));
        push_u64(&mut out, artifacts.len() as u64);
        for artifact in artifacts {
            push_bytes(&mut out, artifact.target.as_bytes());
            push_bytes(&mut out, artifact.name.as_bytes());
            push_bytes(&mut out, artifact.sha256.as_bytes());
            push_u64(&mut out, artifact.bytes);
        }

        let mut sbom: Vec<&SbomComponent> = self.sbom.iter().collect();
        sbom.sort_by(|a, b| component_key(a).cmp(&component_key(b)));
        push_u64(&mut out, sbom.len() as u64);
        for component in sbom {
            push_bytes(&mut out, component.name.as_bytes());
            push_bytes(&mut out, component.version.as_bytes());
            push_bytes(&mut out, component.licence.as_bytes());
            push_bytes(&mut out, component.source.as_bytes());
        }
        out
    }

    /// SHA-256 of [`Self::canonical_bytes`] as lowercase hex.
    pub fn manifest_hash(&self) -> String {
        sha256_hex(&self.canonical_bytes())
    }

    /// A clone with artifacts and SBOM components in canonical order. Saving
    /// and serializing use this form, so reruns are byte-identical.
    pub fn normalized(&self) -> Self {
        let mut out = self.clone();
        out.artifacts
            .sort_by(|a, b| (&a.target, &a.name).cmp(&(&b.target, &b.name)));
        out.sbom
            .sort_by(|a, b| component_key(a).cmp(&component_key(b)));
        out
    }

    /// Strict, normalized JSON bytes with a trailing newline.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = serde_json::to_vec_pretty(&self.normalized())?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Parse and validate a manifest from strict JSON bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(limit_error(bytes.len() as u64));
        }
        let manifest: Self = serde_json::from_slice(bytes)?;
        manifest.validate()?;
        Ok(manifest)
    }
}

/// A manifest plus its base64 Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRelease {
    pub manifest: ReleaseManifest,
    /// Base64 (`STANDARD`, padded) Ed25519 signature over the manifest's
    /// canonical bytes.
    pub signature_b64: String,
}

impl SignedRelease {
    /// Validate the manifest and the signature's shape (not its authenticity).
    pub fn validate(&self) -> Result<()> {
        self.manifest.validate()?;
        decode_signature(&self.signature_b64)?;
        Ok(())
    }

    /// A clone with the manifest in canonical order.
    pub fn normalized(&self) -> Self {
        Self {
            manifest: self.manifest.normalized(),
            signature_b64: self.signature_b64.clone(),
        }
    }

    /// Strict, normalized JSON bytes with a trailing newline.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = serde_json::to_vec_pretty(&self.normalized())?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Parse and validate a signed release from strict JSON bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(limit_error(bytes.len() as u64));
        }
        let signed: Self = serde_json::from_slice(bytes)?;
        signed.validate()?;
        Ok(signed)
    }
}

/// Sign a validated manifest. The signature covers [`ReleaseManifest::canonical_bytes`].
pub fn sign_manifest(
    manifest: &ReleaseManifest,
    signing_key: &SigningKey,
) -> Result<SignedRelease> {
    manifest.validate()?;
    let signature = signing_key.sign(&manifest.canonical_bytes());
    Ok(SignedRelease {
        manifest: manifest.normalized(),
        signature_b64: B64.encode(signature.to_bytes()),
    })
}

/// Verify a signed release against an explicit public key.
pub fn verify_signed(signed: &SignedRelease, public_key: &VerifyingKey) -> Result<()> {
    signed.validate()?;
    let signature = decode_signature(&signed.signature_b64)?;
    public_key
        .verify_strict(&signed.manifest.canonical_bytes(), &signature)
        .map_err(|_| {
            PackagingError::new(
                PackagingErrorKind::InvalidSignature,
                "manifest signature does not verify with this key",
            )
        })
}

/// Decode the embedded public key. The error never contains key bytes.
pub fn embedded_public_key() -> Result<VerifyingKey> {
    let bytes = B64.decode(EMBEDDED_KEY_B64).map_err(|_| {
        PackagingError::new(
            PackagingErrorKind::InvalidManifest,
            "the embedded release key is not valid base64",
        )
    })?;
    let bytes: [u8; PUBLIC_KEY_BYTES] = bytes.try_into().map_err(|_| {
        PackagingError::new(
            PackagingErrorKind::InvalidManifest,
            format!("the embedded release key must decode to {PUBLIC_KEY_BYTES} bytes"),
        )
    })?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| {
        PackagingError::new(
            PackagingErrorKind::InvalidManifest,
            "the embedded release key is not a valid Ed25519 public key",
        )
    })
}

/// Verify a signed release with the key embedded in the installer (INST-02).
pub fn verify_embedded(signed: &SignedRelease) -> Result<()> {
    verify_signed(signed, &embedded_public_key()?)
}

/// The archive file name for a target and release version.
///
/// Windows releases ship a `.zip`; Linux and macOS releases ship a `.tar.gz`.
/// The version is validated so the name can never contain a path separator.
pub fn artifact_name(target: &str, version: &str) -> Result<String> {
    if !SUPPORTED_TARGETS.contains(&target) {
        return Err(PackagingError::new(
            PackagingErrorKind::UnsupportedTarget,
            format!("artifact target `{target}` is not one of the six release targets"),
        ));
    }
    validate_version(version).map_err(|error| {
        PackagingError::new(
            PackagingErrorKind::InvalidArtifact,
            format!("artifact version: {}", error.message),
        )
    })?;
    let extension = if target.contains("windows") {
        "zip"
    } else {
        "tar.gz"
    };
    let name = format!("zero-{version}-{target}.{extension}");
    if name.len() > MAX_FIELD_BYTES {
        return Err(limit_error(name.len() as u64));
    }
    Ok(name)
}

/// The executable name inside the archive: `zero.exe` on Windows, `zero`
/// elsewhere.
pub fn executable_name(target: &str) -> Result<&'static str> {
    if !SUPPORTED_TARGETS.contains(&target) {
        return Err(PackagingError::new(
            PackagingErrorKind::UnsupportedTarget,
            format!("artifact target `{target}` is not one of the six release targets"),
        ));
    }
    Ok(if target.contains("windows") {
        "zero.exe"
    } else {
        "zero"
    })
}

/// Build the SBOM from `Cargo.lock` text (INST-11).
///
/// The scan is line-based, so it needs no TOML dependency. It records
/// `[[package]]` name, version, and source (when Cargo.lock names one; a path
/// package has no source and is recorded as `workspace`). Entries are deduped
/// by (name, version, source) and sorted. Licences are never invented: every
/// component uses [`LICENCE_UNKNOWN`].
///
/// The product itself is the first component, named `zero` at the release
/// `version`. The result is bounded by [`MAX_SBOM_COMPONENTS`]; extra lock
/// entries beyond the bound are dropped deterministically.
pub fn sbom_from_cargo_lock(lock_text: &str, version: &str) -> Vec<SbomComponent> {
    let mut components = Vec::new();
    let mut seen = BTreeSet::new();
    push_component(
        &mut components,
        &mut seen,
        SbomComponent {
            name: "zero".to_string(),
            version: version.to_string(),
            licence: LICENCE_UNKNOWN.to_string(),
            source: "workspace".to_string(),
        },
    );

    let mut current: Option<SbomComponent> = None;
    for raw in lock_text.lines() {
        let line = raw.trim();
        if line == "[[package]]" {
            if let Some(component) = current.take() {
                push_component(&mut components, &mut seen, component);
            }
            current = Some(SbomComponent {
                name: String::new(),
                version: String::new(),
                licence: LICENCE_UNKNOWN.to_string(),
                source: String::new(),
            });
            continue;
        }
        let Some(component) = current.as_mut() else {
            continue;
        };
        if let Some(value) = lock_field(line, "name") {
            component.name = value;
        } else if let Some(value) = lock_field(line, "version") {
            component.version = value;
        } else if let Some(value) = lock_field(line, "source") {
            component.source = value;
        }
    }
    if let Some(component) = current {
        push_component(&mut components, &mut seen, component);
    }

    components.sort_by(|a, b| component_key(a).cmp(&component_key(b)));
    components
}

/// Check that a manifest's SBOM matches the lock file it was generated from.
///
/// Every component must have non-empty name and version, and the component
/// count (including the `zero` product entry) must equal the count regenerated
/// from `lock_text`.
pub fn verify_sbom(manifest: &ReleaseManifest, lock_text: &str) -> Result<()> {
    manifest.validate()?;
    let expected = sbom_from_cargo_lock(lock_text, &manifest.version);
    if expected.len() != manifest.sbom.len() {
        return Err(PackagingError::new(
            PackagingErrorKind::InvalidSbom,
            format!(
                "SBOM count {} does not match the {expected_count} components in Cargo.lock",
                manifest.sbom.len(),
                expected_count = expected.len()
            ),
        ));
    }
    let mut actual = manifest.sbom.clone();
    actual.sort_by(|a, b| component_key(a).cmp(&component_key(b)));
    if actual != expected {
        return Err(PackagingError::new(
            PackagingErrorKind::InvalidSbom,
            "SBOM components do not match the package name and version entries in Cargo.lock",
        ));
    }
    Ok(())
}

/// Read a signed manifest from disk. The file is bounded and strict JSON.
pub fn load_signed(path: impl AsRef<Path>) -> Result<SignedRelease> {
    let path = path.as_ref();
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err(limit_error(metadata.len()));
    }
    let bytes = std::fs::read(path)?;
    SignedRelease::from_json(&bytes)
}

/// Write a signed manifest atomically.
///
/// The manifest is validated and normalized first, written to a temporary file
/// beside the target, flushed, and renamed over the target.
pub fn save_signed(path: impl AsRef<Path>, signed: &SignedRelease) -> Result<()> {
    let bytes = signed.to_json()?;
    write_atomic(path.as_ref(), &bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut temporary = path.as_os_str().to_os_string();
    temporary.push(format!(".tmp-{}", std::process::id()));
    let temporary = PathBuf::from(temporary);
    {
        let mut file = std::fs::File::create(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&temporary, path).map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        PackagingError::from(error)
    })
}

fn validate_version(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(PackagingError::new(
            PackagingErrorKind::InvalidManifest,
            "release version must not be empty",
        ));
    }
    if value.len() > 64 {
        return Err(limit_error(value.len() as u64));
    }
    let first = value.as_bytes()[0];
    if !first.is_ascii_alphanumeric() {
        return Err(PackagingError::new(
            PackagingErrorKind::InvalidManifest,
            "release version must start with an ASCII letter or digit",
        ));
    }
    if value.contains("..") {
        return Err(PackagingError::new(
            PackagingErrorKind::InvalidManifest,
            "release version must not contain `..`",
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'))
    {
        return Err(PackagingError::new(
            PackagingErrorKind::InvalidManifest,
            "release version may contain only letters, digits, `.`, `+`, and `-`",
        ));
    }
    Ok(())
}

fn validate_git_sha(value: &str) -> Result<()> {
    if value.len() < MIN_GIT_SHA_BYTES || value.len() > MAX_GIT_SHA_BYTES {
        return Err(PackagingError::new(
            PackagingErrorKind::InvalidManifest,
            format!("git_sha must be {MIN_GIT_SHA_BYTES} to {MAX_GIT_SHA_BYTES} hex characters"),
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(PackagingError::new(
            PackagingErrorKind::InvalidManifest,
            "git_sha must be lowercase hexadecimal",
        ));
    }
    Ok(())
}

fn validate_sbom(components: &[SbomComponent]) -> Result<()> {
    if components.is_empty() {
        return Err(PackagingError::new(
            PackagingErrorKind::InvalidSbom,
            "a release manifest must include an SBOM",
        ));
    }
    if components.len() > MAX_SBOM_COMPONENTS {
        return Err(PackagingError::new(
            PackagingErrorKind::LimitExceeded,
            format!(
                "SBOM lists {} components, above the {MAX_SBOM_COMPONENTS} component limit",
                components.len()
            ),
        ));
    }
    let mut seen = BTreeSet::new();
    for component in components {
        component.validate()?;
        let key = component_key(component);
        if !seen.insert(key) {
            return Err(PackagingError::new(
                PackagingErrorKind::InvalidSbom,
                format!(
                    "duplicate SBOM component `{}` version `{}`",
                    component.name, component.version
                ),
            ));
        }
    }
    Ok(())
}

fn validate_file_name(value: &str, field: &str) -> Result<()> {
    if value.is_empty() {
        return Err(PackagingError::new(
            PackagingErrorKind::InvalidArtifact,
            format!("{field} must not be empty"),
        ));
    }
    if value.len() > MAX_FIELD_BYTES {
        return Err(limit_error(value.len() as u64));
    }
    if value == "." || value == ".." {
        return Err(PackagingError::new(
            PackagingErrorKind::InvalidArtifact,
            format!("{field} must be a file name"),
        ));
    }
    if value
        .bytes()
        .any(|byte| matches!(byte, b'/' | b'\\' | b':') || byte.is_ascii_control())
    {
        return Err(PackagingError::new(
            PackagingErrorKind::InvalidArtifact,
            format!("{field} must not contain a path separator or control character"),
        ));
    }
    Ok(())
}

fn validate_text(value: &str, field: &str) -> Result<()> {
    if value.is_empty() {
        return Err(PackagingError::new(
            PackagingErrorKind::InvalidSbom,
            format!("{field} must not be empty"),
        ));
    }
    if value.len() > MAX_FIELD_BYTES {
        return Err(limit_error(value.len() as u64));
    }
    if value.chars().any(char::is_control) {
        return Err(PackagingError::new(
            PackagingErrorKind::InvalidSbom,
            format!("{field} must not contain control characters"),
        ));
    }
    Ok(())
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == SHA256_HEX_BYTES
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn decode_signature(value: &str) -> Result<Signature> {
    let bytes = B64.decode(value).map_err(|_| {
        PackagingError::new(
            PackagingErrorKind::InvalidSignature,
            "manifest signature is not valid base64",
        )
    })?;
    let bytes: [u8; SIGNATURE_BYTES] = bytes.try_into().map_err(|_| {
        PackagingError::new(
            PackagingErrorKind::InvalidSignature,
            format!("manifest signature must decode to {SIGNATURE_BYTES} bytes"),
        )
    })?;
    Ok(Signature::from_bytes(&bytes))
}

fn component_key(component: &SbomComponent) -> (&str, &str, &str, &str) {
    (
        component.name.as_str(),
        component.version.as_str(),
        component.source.as_str(),
        component.licence.as_str(),
    )
}

fn push_component(
    components: &mut Vec<SbomComponent>,
    seen: &mut BTreeSet<(String, String, String)>,
    component: SbomComponent,
) {
    if component.name.is_empty() || component.version.is_empty() {
        return;
    }
    if components.len() >= MAX_SBOM_COMPONENTS {
        return;
    }
    let source = if component.source.is_empty() {
        "workspace".to_string()
    } else {
        component.source
    };
    let key = (
        component.name.clone(),
        component.version.clone(),
        source.clone(),
    );
    if seen.insert(key) {
        components.push(SbomComponent {
            name: component.name,
            version: component.version,
            licence: component.licence,
            source,
        });
    }
}

fn lock_field(line: &str, key: &str) -> Option<String> {
    let rest = line.strip_prefix(key)?;
    let rest = rest.strip_prefix(" = ")?;
    let value = rest.trim();
    let inner = value.strip_prefix('"')?.strip_suffix('"')?;
    Some(inner.to_string())
}

fn limit_error(size: u64) -> PackagingError {
    PackagingError::new(
        PackagingErrorKind::LimitExceeded,
        format!("value is {size} bytes, above the allowed packaging limit"),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(SHA256_HEX_BYTES);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    push_u64(out, value.len() as u64);
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only seed for the placeholder embedded key. This is not a release
    /// key: release tooling replaces `EMBEDDED_KEY_B64` and keeps the real
    /// private half in the release signer. The production code above never
    /// derives a private key.
    const EMBEDDED_TEST_SEED: [u8; 32] = [0x42; 32];

    const LOCK: &str = r#"
version = 4

[[package]]
name = "zero-cli"
version = "0.1.0"
dependencies = [
 "serde",
]

[[package]]
name = "serde"
version = "1.0.215"
source = "registry+crates.io-index"
checksum = "aaaaaaaa"

[[package]]
name = "serde"
version = "1.0.215"
source = "registry+crates.io-index"
checksum = "aaaaaaaa"

[[package]]
name = "serde"
version = "1.0.100"
source = "registry+crates.io-index"

[[package]]
name = "zero-types"
version = "0.1.0"
"#;

    fn embedded_test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&EMBEDDED_TEST_SEED)
    }

    fn artifact(target: &str, version: &str, byte: u8) -> Artifact {
        Artifact {
            target: target.to_string(),
            name: artifact_name(target, version).expect("helper name"),
            sha256: format!("{byte:02x}").repeat(32),
            bytes: 1024 + u64::from(byte),
        }
    }

    fn manifest() -> ReleaseManifest {
        let version = "0.1.0";
        ReleaseManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            version: version.to_string(),
            git_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
            created_ms: 1_764_000_000_000,
            artifacts: vec![
                artifact("x86_64-pc-windows-msvc", version, 0x22),
                artifact("x86_64-unknown-linux-gnu", version, 0x11),
            ],
            sbom: sbom_from_cargo_lock(LOCK, version),
            channel: "stable".to_string(),
        }
    }

    #[test]
    fn canonical_bytes_and_signature_round_trip() {
        let manifest = manifest();
        manifest.validate().expect("valid manifest");
        let bytes = manifest.canonical_bytes();
        assert_eq!(bytes, manifest.clone().canonical_bytes());
        assert_eq!(manifest.manifest_hash(), sha256_hex(&bytes));

        let mut reversed = manifest.clone();
        reversed.artifacts.reverse();
        reversed.sbom.reverse();
        assert_eq!(reversed.canonical_bytes(), bytes);
        assert_eq!(reversed.manifest_hash(), manifest.manifest_hash());

        let key = embedded_test_signing_key();
        let signed = sign_manifest(&manifest, &key).expect("sign");
        verify_signed(&signed, &key.verifying_key()).expect("verify");
        assert_eq!(signed.manifest, manifest.normalized());
    }

    #[test]
    fn embedded_key_verifies_a_signed_manifest() {
        let key = embedded_test_signing_key();
        assert_eq!(
            B64.encode(key.verifying_key().to_bytes()),
            EMBEDDED_KEY_B64,
            "the test helper must match the placeholder embedded key"
        );
        let signed = sign_manifest(&manifest(), &key).expect("sign");
        verify_embedded(&signed).expect("the embedded key verifies the manifest");
        assert_eq!(embedded_public_key().unwrap(), key.verifying_key());
    }

    #[test]
    fn a_tampered_manifest_and_a_tampered_signature_fail() {
        let key = embedded_test_signing_key();
        let signed = sign_manifest(&manifest(), &key).expect("sign");

        let mut tampered = signed.clone();
        tampered.manifest.artifacts[0].sha256 = "aa".repeat(32);
        assert!(
            verify_embedded(&tampered).is_err(),
            "a changed digest must fail"
        );

        let mut bad_signature = signed.clone();
        bad_signature.signature_b64 = B64.encode([0u8; SIGNATURE_BYTES]);
        assert!(
            verify_embedded(&bad_signature).is_err(),
            "a zero signature must fail"
        );

        let mut truncated = signed;
        truncated.signature_b64 = B64.encode([0u8; 32]);
        assert!(
            verify_embedded(&truncated).is_err(),
            "a short signature must fail"
        );
    }

    #[test]
    fn a_wrong_key_fails() {
        let signed = sign_manifest(&manifest(), &embedded_test_signing_key()).expect("sign");
        let wrong = SigningKey::from_bytes(&[0x24; 32]);
        let error = verify_signed(&signed, &wrong.verifying_key()).unwrap_err();
        assert_eq!(error.kind(), PackagingErrorKind::InvalidSignature);
        assert!(!error.message().contains(EMBEDDED_KEY_B64));
    }

    #[test]
    fn validation_rejects_duplicates_bad_sha_and_unknown_targets() {
        let version = "0.1.0";

        let mut duplicate_target = manifest();
        duplicate_target
            .artifacts
            .push(artifact("x86_64-pc-windows-msvc", version, 0x33));
        let error = duplicate_target.validate().unwrap_err();
        assert!(
            error.message().contains("duplicate artifact target"),
            "{error}"
        );

        let mut duplicate_name = manifest();
        let mut second_name = artifact("aarch64-unknown-linux-gnu", version, 0x33);
        second_name.name = duplicate_name.artifacts[0].name.clone();
        duplicate_name.artifacts.push(second_name);
        let error = duplicate_name.validate().unwrap_err();
        assert!(
            error.message().contains("duplicate artifact name"),
            "{error}"
        );

        let mut bad_sha = manifest();
        bad_sha.artifacts[0].sha256 = "A".repeat(64);
        let error = bad_sha.validate().unwrap_err();
        assert_eq!(error.kind(), PackagingErrorKind::InvalidArtifact);

        let mut short_sha = manifest();
        short_sha.artifacts[0].sha256 = "abc".to_string();
        assert!(short_sha.validate().is_err());

        let mut empty_artifact = manifest();
        empty_artifact.artifacts[0].bytes = 0;
        assert!(empty_artifact.validate().is_err());

        let mut unknown_target = manifest();
        unknown_target.artifacts[0].target = "x86_64-unknown-freebsd".to_string();
        unknown_target.artifacts[0].name = "zero-0.1.0-x86_64-unknown-freebsd.tar.gz".to_string();
        let error = unknown_target.validate().unwrap_err();
        assert_eq!(error.kind(), PackagingErrorKind::UnsupportedTarget);

        let mut bad_channel = manifest();
        bad_channel.channel = "nightly".to_string();
        assert!(bad_channel.validate().is_err());

        let mut bad_version = manifest();
        bad_version.version = "../0.1.0".to_string();
        assert!(bad_version.validate().is_err());

        let mut no_artifacts = manifest();
        no_artifacts.artifacts.clear();
        assert!(no_artifacts.validate().is_err());

        let mut no_sbom = manifest();
        no_sbom.sbom.clear();
        assert!(no_sbom.validate().is_err());
    }

    #[test]
    fn artifact_names_cover_the_six_targets() {
        let cases = [
            (
                "x86_64-unknown-linux-gnu",
                "zero-0.1.0-x86_64-unknown-linux-gnu.tar.gz",
                "zero",
            ),
            (
                "aarch64-unknown-linux-gnu",
                "zero-0.1.0-aarch64-unknown-linux-gnu.tar.gz",
                "zero",
            ),
            (
                "x86_64-apple-darwin",
                "zero-0.1.0-x86_64-apple-darwin.tar.gz",
                "zero",
            ),
            (
                "aarch64-apple-darwin",
                "zero-0.1.0-aarch64-apple-darwin.tar.gz",
                "zero",
            ),
            (
                "x86_64-pc-windows-msvc",
                "zero-0.1.0-x86_64-pc-windows-msvc.zip",
                "zero.exe",
            ),
            (
                "aarch64-pc-windows-msvc",
                "zero-0.1.0-aarch64-pc-windows-msvc.zip",
                "zero.exe",
            ),
        ];
        for (target, expected_name, expected_executable) in cases {
            let name = artifact_name(target, "0.1.0").expect("supported target");
            assert_eq!(name, expected_name);
            assert!(!name.contains('/') && !name.contains('\\') && !name.contains(':'));
            assert!(name.len() <= MAX_FIELD_BYTES);
            assert_eq!(executable_name(target).unwrap(), expected_executable);
        }
        assert!(artifact_name("x86_64-unknown-freebsd", "0.1.0").is_err());
        assert!(artifact_name("x86_64-unknown-linux-gnu", "../0.1.0").is_err());
        assert!(artifact_name("x86_64-unknown-linux-gnu", "").is_err());
        assert!(executable_name("wasm32-unknown-unknown").is_err());
    }

    #[test]
    fn sbom_parses_dedupes_sorts_and_stays_bounded() {
        let sbom = sbom_from_cargo_lock(LOCK, "0.1.0");
        assert_eq!(
            sbom.len(),
            5,
            "four lock packages plus the product, one dedupe"
        );
        let names: Vec<&str> = sbom.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["serde", "serde", "zero", "zero-cli", "zero-types"]);
        assert!(sbom
            .windows(2)
            .all(|pair| component_key(&pair[0]) <= component_key(&pair[1])));
        assert!(sbom.iter().all(|c| c.licence == LICENCE_UNKNOWN));
        assert_eq!(
            sbom.iter().find(|c| c.name == "zero").unwrap().version,
            "0.1.0"
        );
        assert_eq!(
            sbom.iter().find(|c| c.name == "zero-types").unwrap().source,
            "workspace"
        );

        let mut large = String::from("version = 4\n");
        for index in 0..(MAX_SBOM_COMPONENTS + 100) {
            large.push_str(&format!(
                "\n[[package]]\nname = \"pkg{index}\"\nversion = \"1.0.{index}\"\n"
            ));
        }
        let bounded = sbom_from_cargo_lock(&large, "0.1.0");
        assert_eq!(bounded.len(), MAX_SBOM_COMPONENTS);
        assert!(bounded
            .windows(2)
            .all(|pair| component_key(&pair[0]) <= component_key(&pair[1])));
    }

    #[test]
    fn verify_sbom_matches_the_lock_and_rejects_a_changed_count() {
        let manifest = manifest();
        verify_sbom(&manifest, LOCK).expect("generated SBOM matches the lock");

        let mut extra = manifest;
        extra.sbom.push(SbomComponent {
            name: "extra".to_string(),
            version: "1.0.0".to_string(),
            licence: LICENCE_UNKNOWN.to_string(),
            source: "workspace".to_string(),
        });
        let error = verify_sbom(&extra, LOCK).unwrap_err();
        assert_eq!(error.kind(), PackagingErrorKind::InvalidSbom);
        assert!(error.message().contains("count"), "{error}");
    }

    #[test]
    fn save_and_load_round_trip_and_json_is_strict() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("release.json");
        let signed = sign_manifest(&manifest(), &embedded_test_signing_key()).expect("sign");
        save_signed(&path, &signed).expect("save");
        let loaded = load_signed(&path).expect("load");
        assert_eq!(loaded, signed.normalized());
        verify_embedded(&loaded).expect("embedded verification after load");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.ends_with('\n'));
        save_signed(&path, &loaded).expect("replace atomically");

        let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
        value["unexpected"] = serde_json::json!(true);
        let error =
            SignedRelease::from_json(serde_json::to_vec(&value).unwrap().as_slice()).unwrap_err();
        assert_eq!(error.kind(), PackagingErrorKind::Json);

        let duplicate_field = r#"{"manifest":{},"manifest":{},"signature_b64":""}"#;
        assert!(SignedRelease::from_json(duplicate_field.as_bytes()).is_err());

        let oversized = vec![b' '; MAX_MANIFEST_BYTES as usize + 1];
        let error = SignedRelease::from_json(&oversized).unwrap_err();
        assert_eq!(error.kind(), PackagingErrorKind::LimitExceeded);
    }

    #[test]
    fn no_private_key_or_network_surface_is_shipped() {
        let source = include_str!("packaging.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let (begin_marker, private_marker) = private_key_markers();
        assert!(!production.contains(&begin_marker));
        assert!(!production.contains(&private_marker));
        assert!(!production.contains("SigningKey::from_bytes"));
        assert!(!production.contains("TcpStream"));
        assert!(!production.contains("std::net"));
        assert!(!production.contains("reqwest"));
        assert!(!production.contains("http://"));
        assert!(!production.contains("https://"));
        assert!(source.contains("PLACEHOLDER Ed25519 public key"));

        let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut violations = Vec::new();
        scan_for_key_material(crate_root, &mut violations);
        assert!(violations.is_empty(), "key material found: {violations:?}");
    }

    fn private_key_markers() -> (String, String) {
        (
            format!("{}{}", "-".repeat(5), "BEGIN"),
            format!("{} {} {}", "PRIVATE", "KEY", "-".repeat(5)),
        )
    }

    fn scan_for_key_material(directory: &Path, violations: &mut Vec<String>) {
        let (begin_marker, private_marker) = private_key_markers();
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan_for_key_material(&path, violations);
                continue;
            }
            let extension = path
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or_default();
            if matches!(extension, "pem" | "key" | "p12" | "pfx") {
                violations.push(format!("private-key file {}", path.display()));
                continue;
            }
            let Ok(metadata) = std::fs::metadata(&path) else {
                continue;
            };
            if metadata.len() > 1024 * 1024 {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if text.contains(&begin_marker) && text.contains(&private_marker) {
                violations.push(format!("PEM private key in {}", path.display()));
            }
        }
    }
}
