//! Kernel bootstrap (T-INST-06): a pinned dependency plan, a checksum-verified
//! download or cache path, a safe install layout, and an offline mode.
//!
//! Requirements: INST-06 (the bootstrap reports the PATH entry the installer
//! must add) and INST-07 (install `uv`, Python, and `ipykernel` on request with
//! checksum verification and an offline mode).
//!
//! # What is modelled here
//!
//! The bootstrap is a plan ([`BootstrapPlan`]) plus an environment
//! ([`BootstrapEnv`]). A plan names every component, its pinned SHA-256, the
//! HTTPS URL it comes from, an optional version requirement, and whether the
//! component is optional. A component is one verified file:
//!
//! | Kind | Installed file |
//! |---|---|
//! | `uv` | `uv` (`.exe` on Windows) |
//! | `python` | `python` (`.exe` on Windows) |
//! | `ipykernel` | `ipykernel` |
//! | `pyzmq` | `pyzmq` |
//! | wheel | `<name>-<version>.whl` |
//!
//! Decoding a real release archive into that file, and laying out a full Python
//! environment, is installer work: this crate has no archive dependency. The
//! checksum, cache, offline, install, and probe rules below are complete and
//! tested.
//!
//! # Execution rules
//!
//! 1. The plan is validated first: schema version, bounded component count,
//!    unique kinds and wheel names, 64 lowercase hex SHA-256 values, HTTPS URLs
//!    without embedded credentials, and bounded text fields.
//! 2. The local cache is consulted by SHA-256. A cache hit is hashed again
//!    before it is used, so a corrupted cache entry cannot install.
//! 3. In offline mode the cache is the only source. A miss is a typed
//!    `cache_miss` failure that names the component, the digest, and the cache
//!    path to seed; the downloader is never called.
//! 4. Online, a miss is downloaded, hashed, and refused on any mismatch before
//!    it is cached or installed. The verified bytes are stored in the cache
//!    atomically (temporary file plus rename).
//! 5. Installation writes a temporary file in the bin directory, syncs it, sets
//!    the executable bit on Unix for `uv` and `python`, and renames it into
//!    place. A different file at the same name is never overwritten: it is an
//!    `install_conflict`. A file with the expected hash is reused, so a second
//!    run is idempotent.
//! 6. A component carrying the placeholder digest from
//!    [`default_plan`] is refused with `placeholder_checksum`; release tooling
//!    must pin real digests.
//!
//! The module has no network code of its own: downloads go through the
//! injected [`Downloader`], and the tests use a fake with a call counter. There
//! is no shell surface.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Schema version of a bootstrap plan this module accepts.
pub const BOOTSTRAP_SCHEMA_VERSION: u32 = 1;

/// Upper bound on components in one plan.
pub const MAX_BOOTSTRAP_COMPONENTS: usize = 32;

/// Upper bound on one component's bytes, whether cached or downloaded.
pub const MAX_COMPONENT_BYTES: u64 = 256 * 1024 * 1024;

/// Upper bound on a component URL.
pub const MAX_URL_BYTES: usize = 512;

/// Upper bound on a plan or component text field.
pub const MAX_BOOTSTRAP_FIELD_BYTES: usize = 128;

/// Upper bound on the advisory cache directory string in a plan.
pub const MAX_CACHE_DIR_BYTES: usize = 256;

/// The clearly marked placeholder digest used by [`default_plan`].
///
/// A real release manifest replaces every placeholder with the SHA-256 of the
/// exact artifact. The executor refuses a placeholder rather than trusting
/// unverified bytes.
pub const PLACEHOLDER_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// The clearly marked placeholder manifest version used by [`default_plan`].
pub const PLACEHOLDER_MANIFEST_VERSION: &str = "dev-placeholder-release-1";

/// The advisory cache directory recorded by [`default_plan`].
pub const DEFAULT_CACHE_DIR: &str = "kernel-cache";

const SHA256_HEX_BYTES: usize = 64;
const TEMP_PREFIX: &str = ".zero-bootstrap.tmp-";

#[cfg(windows)]
const EXECUTABLE_SUFFIX: &str = ".exe";
#[cfg(not(windows))]
const EXECUTABLE_SUFFIX: &str = "";

/// Why a bootstrap plan or component was refused.
///
/// Kinds are stable strings for logs and tests; they are local to the bootstrap
/// path and are not part of the `zero-types` error taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapErrorKind {
    PlanInvalid,
    LimitExceeded,
    PlaceholderChecksum,
    CacheMiss,
    CacheTampered,
    CacheWrite,
    Download,
    ChecksumMismatch,
    InstallConflict,
    PathUnsafe,
    TooLarge,
    Io,
}

impl BootstrapErrorKind {
    /// Stable kind string, e.g. `cache_miss`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlanInvalid => "plan_invalid",
            Self::LimitExceeded => "limit_exceeded",
            Self::PlaceholderChecksum => "placeholder_checksum",
            Self::CacheMiss => "cache_miss",
            Self::CacheTampered => "cache_tampered",
            Self::CacheWrite => "cache_write",
            Self::Download => "download",
            Self::ChecksumMismatch => "checksum_mismatch",
            Self::InstallConflict => "install_conflict",
            Self::PathUnsafe => "path_unsafe",
            Self::TooLarge => "too_large",
            Self::Io => "io",
        }
    }
}

/// A typed bootstrap error with a stable kind and a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapError {
    kind: BootstrapErrorKind,
    message: String,
}

impl BootstrapError {
    /// Build an error. Public so a [`Downloader`] or [`Cache`] implementation
    /// can report its own failure in the shared type.
    pub fn new(kind: BootstrapErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// The stable error kind.
    pub fn kind(&self) -> BootstrapErrorKind {
        self.kind
    }

    /// The stable kind string.
    pub fn code(&self) -> &'static str {
        self.kind.as_str()
    }

    /// The human-readable message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "zero.bootstrap.{}: {}", self.kind.as_str(), self.message)
    }
}

impl std::error::Error for BootstrapError {}

impl From<std::io::Error> for BootstrapError {
    fn from(error: std::io::Error) -> Self {
        Self::new(BootstrapErrorKind::Io, error.to_string())
    }
}

/// Result type used by plan validation, caches, downloaders, and installs.
pub type BootstrapResult<T> = std::result::Result<T, BootstrapError>;

/// The kind of one bootstrap component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BootstrapKind {
    /// The `uv` package manager.
    Uv,
    /// A pinned CPython runtime.
    Python,
    /// The `ipykernel` package.
    Ipkernel,
    /// The `pyzmq` package.
    Pyzmq,
    /// A wheel, identified by name and version.
    Wheel {
        /// Wheel distribution name.
        name: String,
        /// Wheel version.
        version: String,
    },
}

impl BootstrapKind {
    /// Stable kind string.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Uv => "uv",
            Self::Python => "python",
            Self::Ipkernel => "ipykernel",
            Self::Pyzmq => "pyzmq",
            Self::Wheel { .. } => "wheel",
        }
    }

    /// Whether the installed file is a program that needs an executable bit.
    pub const fn is_executable(&self) -> bool {
        matches!(self, Self::Uv | Self::Python)
    }
}

/// One pinned component in a [`BootstrapPlan`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapComponent {
    /// What the component is.
    pub kind: BootstrapKind,
    /// A human-readable requirement, e.g. `>=6.29,<7`. Bounded text; not
    /// resolved by this module.
    pub version_req: String,
    /// The HTTPS URL the verified bytes come from.
    pub url: String,
    /// Lowercase hex SHA-256 of the exact bytes.
    pub sha256: String,
    /// An optional component may fail without failing the bootstrap.
    pub optional: bool,
}

impl BootstrapComponent {
    /// A stable label for reports and guidance.
    pub fn label(&self) -> String {
        match &self.kind {
            BootstrapKind::Wheel { name, version } => format!("wheel {name} {version}"),
            other => other.as_str().to_string(),
        }
    }

    /// Whether this component still carries the placeholder digest.
    pub fn is_placeholder_checksum(&self) -> bool {
        self.sha256 == PLACEHOLDER_SHA256
    }

    /// Validate the digest, URL, requirement, and wheel name and version.
    pub fn validate(&self) -> BootstrapResult<()> {
        validate_sha256(&self.sha256)?;
        validate_url(&self.url)?;
        validate_text(&self.version_req, "version_req")?;
        if self.version_req.starts_with(char::is_whitespace)
            || self.version_req.ends_with(char::is_whitespace)
        {
            return Err(BootstrapError::new(
                BootstrapErrorKind::PlanInvalid,
                format!(
                    "component `{}` has a version_req with surrounding whitespace",
                    self.label()
                ),
            ));
        }
        if let BootstrapKind::Wheel { name, version } = &self.kind {
            validate_component_token(name, "wheel name")?;
            validate_component_token(version, "wheel version")?;
        }
        component_file_name(self)?;
        Ok(())
    }

    fn duplicate_key(&self) -> (String, String) {
        match &self.kind {
            BootstrapKind::Wheel { name, .. } => ("wheel".to_string(), name.clone()),
            other => (other.as_str().to_string(), String::new()),
        }
    }
}

/// The pinned dependency plan for one kernel bootstrap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapPlan {
    /// Must be [`BOOTSTRAP_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The release manifest version that produced this plan. Placeholder plans
    /// use [`PLACEHOLDER_MANIFEST_VERSION`].
    pub manifest_version: String,
    /// The pinned CPython version, e.g. `3.12.7`.
    pub python_version: String,
    /// Advisory cache directory recorded by the plan. The path actually used
    /// is [`BootstrapEnv::cache_dir`].
    pub cache_dir: String,
    /// The components, in install order.
    pub components: Vec<BootstrapComponent>,
}

impl BootstrapPlan {
    /// Validate the schema, manifest version, Python version, cache directory,
    /// component bounds, unique kinds and wheel names, and every component.
    pub fn validate(&self) -> BootstrapResult<()> {
        if self.schema_version != BOOTSTRAP_SCHEMA_VERSION {
            return Err(BootstrapError::new(
                BootstrapErrorKind::PlanInvalid,
                format!(
                    "bootstrap plan schema {} is not the supported schema {BOOTSTRAP_SCHEMA_VERSION}",
                    self.schema_version
                ),
            ));
        }
        validate_manifest_version(&self.manifest_version)?;
        validate_python_version(&self.python_version)?;
        validate_cache_dir(&self.cache_dir)?;
        if self.components.is_empty() {
            return Err(BootstrapError::new(
                BootstrapErrorKind::PlanInvalid,
                "a bootstrap plan must list at least one component",
            ));
        }
        if self.components.len() > MAX_BOOTSTRAP_COMPONENTS {
            return Err(BootstrapError::new(
                BootstrapErrorKind::LimitExceeded,
                format!(
                    "bootstrap plan lists {} components, above the {MAX_BOOTSTRAP_COMPONENTS} component limit",
                    self.components.len()
                ),
            ));
        }

        let mut seen = BTreeSet::new();
        for component in &self.components {
            component.validate()?;
            let key = component.duplicate_key();
            if !seen.insert(key) {
                return Err(BootstrapError::new(
                    BootstrapErrorKind::PlanInvalid,
                    format!(
                        "bootstrap plan repeats component `{}` (kinds and wheel names must be unique)",
                        component.label()
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Whether every component still carries the placeholder digest. A plan in
    /// this state is representative only; the executor refuses it.
    pub fn has_placeholder_checksums(&self) -> bool {
        self.components
            .iter()
            .all(BootstrapComponent::is_placeholder_checksum)
    }
}

/// The default representative plan for a Python version.
///
/// It lists one component of each supported kind so the shape is exercised,
/// but every digest is [`PLACEHOLDER_SHA256`] and the manifest version is
/// [`PLACEHOLDER_MANIFEST_VERSION`]. The URLs are illustrative
/// `example.invalid` locations. Release tooling replaces all three with the
/// real upstream location, digest, and manifest version. The returned plan is
/// validated only when [`BootstrapPlan::validate`] is called; the executor
/// refuses the placeholder digests with `placeholder_checksum`.
pub fn default_plan(python_version: impl Into<String>) -> BootstrapPlan {
    let python_version = python_version.into();
    let placeholder = PLACEHOLDER_SHA256.to_string();
    BootstrapPlan {
        schema_version: BOOTSTRAP_SCHEMA_VERSION,
        manifest_version: PLACEHOLDER_MANIFEST_VERSION.to_string(),
        python_version,
        cache_dir: DEFAULT_CACHE_DIR.to_string(),
        components: vec![
            BootstrapComponent {
                kind: BootstrapKind::Uv,
                version_req: ">=0.5".to_string(),
                url: "https://example.invalid/zero/kernel/uv".to_string(),
                sha256: placeholder.clone(),
                optional: false,
            },
            BootstrapComponent {
                kind: BootstrapKind::Python,
                version_req: "==3.12".to_string(),
                url: "https://example.invalid/zero/kernel/python".to_string(),
                sha256: placeholder.clone(),
                optional: false,
            },
            BootstrapComponent {
                kind: BootstrapKind::Ipkernel,
                version_req: ">=6.29,<7".to_string(),
                url: "https://example.invalid/zero/kernel/ipykernel".to_string(),
                sha256: placeholder.clone(),
                optional: false,
            },
            BootstrapComponent {
                kind: BootstrapKind::Pyzmq,
                version_req: ">=25".to_string(),
                url: "https://example.invalid/zero/kernel/pyzmq".to_string(),
                sha256: placeholder.clone(),
                optional: true,
            },
            BootstrapComponent {
                kind: BootstrapKind::Wheel {
                    name: "traitlets".to_string(),
                    version: "5.14.3".to_string(),
                },
                version_req: "==5.14.3".to_string(),
                url: "https://example.invalid/zero/kernel/traitlets-5.14.3-py3-none-any.whl"
                    .to_string(),
                sha256: placeholder,
                optional: true,
            },
        ],
    }
}

/// The local cache consulted before any download.
pub trait Cache {
    /// The bytes stored under `sha256`, or `None` when absent or unreadable.
    fn get(&self, sha256: &str) -> Option<Vec<u8>>;

    /// Store verified bytes under `sha256`. Implementations must be atomic with
    /// respect to a concurrent reader: a reader sees the old bytes or the new
    /// bytes, never a partial file.
    fn put(&self, sha256: &str, bytes: &[u8]) -> BootstrapResult<()>;
}

/// A filesystem cache: one file per SHA-256, named `<sha256>.bin`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsCache {
    root: PathBuf,
}

impl FsCache {
    /// A cache rooted at `root`. The directory is created on the first write.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The cache root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The file name for a digest, with the digest validated so the path can
    /// never escape the root.
    pub fn path_for(&self, sha256: &str) -> BootstrapResult<PathBuf> {
        validate_sha256(sha256)?;
        Ok(self.root.join(format!("{sha256}.bin")))
    }
}

impl Cache for FsCache {
    fn get(&self, sha256: &str) -> Option<Vec<u8>> {
        let path = self.path_for(sha256).ok()?;
        let metadata = fs::symlink_metadata(&path).ok()?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_COMPONENT_BYTES {
            return None;
        }
        let bytes = fs::read(&path).ok()?;
        if bytes.len() as u64 > MAX_COMPONENT_BYTES {
            return None;
        }
        Some(bytes)
    }

    fn put(&self, sha256: &str, bytes: &[u8]) -> BootstrapResult<()> {
        let target = self.path_for(sha256)?;
        if bytes.len() as u64 > MAX_COMPONENT_BYTES {
            return Err(BootstrapError::new(
                BootstrapErrorKind::TooLarge,
                format!(
                    "cache entry is {} bytes, above the {MAX_COMPONENT_BYTES} byte component limit",
                    bytes.len()
                ),
            ));
        }
        if sha256_hex(bytes) != sha256 {
            return Err(BootstrapError::new(
                BootstrapErrorKind::ChecksumMismatch,
                "refusing to cache bytes that do not match the key digest",
            ));
        }
        fs::create_dir_all(&self.root)?;
        write_atomic(&self.root, &target, bytes)
    }
}

fn write_atomic(root: &Path, target: &Path, bytes: &[u8]) -> BootstrapResult<()> {
    let temporary = temporary_path(root);
    let written = (|| -> std::io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, target)
    })();
    match written {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(error.into())
        }
    }
}

/// The source of component bytes when the cache does not have them.
pub trait Downloader {
    /// Fetch `url`. The caller enforces the size bound and verifies SHA-256;
    /// `size` is an informational upper bound.
    fn download(&self, url: &str, size: u64) -> BootstrapResult<Vec<u8>>;
}

/// Where the bootstrap reads, writes, and whether it may use the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapEnv {
    /// The verified-component cache directory.
    pub cache_dir: PathBuf,
    /// The directory the bootstrap installs into and adds to PATH.
    pub bin_dir: PathBuf,
    /// When true, the cache is the only source and the downloader is never
    /// called.
    pub offline: bool,
}

impl BootstrapEnv {
    /// Build an environment.
    pub fn new(cache_dir: impl Into<PathBuf>, bin_dir: impl Into<PathBuf>, offline: bool) -> Self {
        Self {
            cache_dir: cache_dir.into(),
            bin_dir: bin_dir.into(),
            offline,
        }
    }
}

/// One component that could not be installed, with actionable guidance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapFailure {
    /// The component label, or `plan` for a plan-level failure.
    pub component: String,
    /// The pinned digest, or empty for a plan-level failure.
    pub sha256: String,
    /// The stable failure kind.
    pub kind: BootstrapErrorKind,
    /// Whether the component was optional.
    pub optional: bool,
    /// What failed, without secrets.
    pub message: String,
    /// What the operator should do next.
    pub guidance: String,
}

/// The outcome of a bootstrap attempt.
///
/// - `installed` lists components this run wrote into `bin_dir`.
/// - `already_installed` lists components that were already present with the
///   expected digest.
/// - `reused_from_cache` lists components whose bytes came from the cache.
/// - `downloaded` lists components fetched from the network this run.
/// - `failed` lists every component or plan-level failure.
/// - `env_vars` is the environment the installer must apply. It contains only
///   PATH-like values and never a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapReport {
    /// Components written by this run.
    pub installed: Vec<String>,
    /// Components already installed with the expected digest.
    pub already_installed: Vec<String>,
    /// Components satisfied from the local cache.
    pub reused_from_cache: Vec<String>,
    /// Components downloaded this run.
    pub downloaded: Vec<String>,
    /// Every failure, including optional ones.
    pub failed: Vec<BootstrapFailure>,
    /// The environment entries to apply, e.g. `PATH`.
    pub env_vars: BTreeMap<String, String>,
}

impl BootstrapReport {
    fn new(env: &BootstrapEnv) -> Self {
        let mut env_vars = BTreeMap::new();
        env_vars.insert("PATH".to_string(), env.bin_dir.display().to_string());
        Self {
            installed: Vec::new(),
            already_installed: Vec::new(),
            reused_from_cache: Vec::new(),
            downloaded: Vec::new(),
            failed: Vec::new(),
            env_vars,
        }
    }

    /// Whether every required component succeeded. A failure of an optional
    /// component is recorded but does not fail the bootstrap.
    pub fn is_success(&self) -> bool {
        self.failed.iter().all(|failure| failure.optional)
    }

    /// The PATH entry the installer must add.
    pub fn path_entry(&self) -> Option<&str> {
        self.env_vars.get("PATH").map(String::as_str)
    }
}

/// The install outcome for one component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallOutcome {
    Installed,
    AlreadyPresent,
}

/// Bootstrap using a filesystem cache at [`BootstrapEnv::cache_dir`].
pub fn bootstrap(
    plan: &BootstrapPlan,
    env: &BootstrapEnv,
    downloader: &dyn Downloader,
) -> BootstrapReport {
    let cache = FsCache::new(&env.cache_dir);
    bootstrap_with_cache(plan, env, downloader, &cache)
}

/// Bootstrap with an explicit [`Cache`] implementation.
///
/// Components run in plan order. A required failure stops the run; an optional
/// failure is recorded and the next component is attempted. Nothing touches the
/// network in offline mode.
pub fn bootstrap_with_cache(
    plan: &BootstrapPlan,
    env: &BootstrapEnv,
    downloader: &dyn Downloader,
    cache: &dyn Cache,
) -> BootstrapReport {
    let mut report = BootstrapReport::new(env);
    if let Err(error) = plan.validate() {
        report.failed.push(BootstrapFailure {
            component: "plan".to_string(),
            sha256: String::new(),
            kind: error.kind(),
            optional: false,
            message: error.message().to_string(),
            guidance: plan_guidance(&error),
        });
        return report;
    }

    let mut halted = false;
    for component in &plan.components {
        if halted {
            break;
        }
        match bootstrap_component(component, env, downloader, cache, &mut report) {
            Ok(()) => {}
            Err(error) => {
                let optional = component.optional;
                report.failed.push(BootstrapFailure {
                    component: component.label(),
                    sha256: component.sha256.clone(),
                    kind: error.kind(),
                    optional,
                    message: error.message().to_string(),
                    guidance: component_guidance(component, &error, env),
                });
                if !optional {
                    halted = true;
                }
            }
        }
    }
    report
}

fn bootstrap_component(
    component: &BootstrapComponent,
    env: &BootstrapEnv,
    downloader: &dyn Downloader,
    cache: &dyn Cache,
    report: &mut BootstrapReport,
) -> BootstrapResult<()> {
    if component.is_placeholder_checksum() {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PlaceholderChecksum,
            format!(
                "component `{}` carries the placeholder digest, so its bytes cannot be verified",
                component.label()
            ),
        ));
    }

    let sha256 = component.sha256.as_str();
    let label = component.label();

    if let Some(bytes) = cache.get(sha256) {
        if bytes.len() as u64 > MAX_COMPONENT_BYTES {
            return Err(BootstrapError::new(
                BootstrapErrorKind::TooLarge,
                format!(
                    "cached bytes for `{label}` are {} bytes, above the {MAX_COMPONENT_BYTES} byte component limit",
                    bytes.len()
                ),
            ));
        }
        let actual = sha256_hex(&bytes);
        if actual != sha256 {
            return Err(BootstrapError::new(
                BootstrapErrorKind::CacheTampered,
                format!(
                    "cached bytes for `{label}` hash to {actual} instead of the pinned {sha256}"
                ),
            ));
        }
        let outcome = install_bytes(&env.bin_dir, component, &bytes, sha256)?;
        record_install(report, &label, outcome);
        report.reused_from_cache.push(label);
        return Ok(());
    }

    if env.offline {
        return Err(BootstrapError::new(
            BootstrapErrorKind::CacheMiss,
            format!(
                "offline bootstrap cannot find component `{label}` (sha256 {sha256}) in the cache"
            ),
        ));
    }

    let bytes = downloader.download(&component.url, MAX_COMPONENT_BYTES)?;
    if bytes.len() as u64 > MAX_COMPONENT_BYTES {
        return Err(BootstrapError::new(
            BootstrapErrorKind::TooLarge,
            format!(
                "downloaded bytes for `{label}` are {} bytes, above the {MAX_COMPONENT_BYTES} byte component limit",
                bytes.len()
            ),
        ));
    }
    let actual = sha256_hex(&bytes);
    if actual != sha256 {
        return Err(BootstrapError::new(
            BootstrapErrorKind::ChecksumMismatch,
            format!(
                "downloaded bytes for `{label}` hash to {actual} instead of the pinned {sha256}; nothing was installed"
            ),
        ));
    }
    cache.put(sha256, &bytes).map_err(|error| {
        BootstrapError::new(
            BootstrapErrorKind::CacheWrite,
            format!(
                "could not store `{label}` in the cache: {}",
                error.message()
            ),
        )
    })?;

    let outcome = install_bytes(&env.bin_dir, component, &bytes, sha256)?;
    record_install(report, &label, outcome);
    report.downloaded.push(label);
    Ok(())
}

fn record_install(report: &mut BootstrapReport, label: &str, outcome: InstallOutcome) {
    match outcome {
        InstallOutcome::Installed => report.installed.push(label.to_string()),
        InstallOutcome::AlreadyPresent => report.already_installed.push(label.to_string()),
    }
}

/// The file name a component installs as.
///
/// `uv` and `python` get the platform executable suffix and an executable bit
/// on Unix. A wheel installs as `<name>-<version>.whl`. Every result is checked
/// as a safe single file name: no separator, drive, control character, `..`,
/// reserved Windows device name, or trailing dot or space.
pub fn component_file_name(component: &BootstrapComponent) -> BootstrapResult<String> {
    let stem = match &component.kind {
        BootstrapKind::Uv => "uv".to_string(),
        BootstrapKind::Python => "python".to_string(),
        BootstrapKind::Ipkernel => "ipykernel".to_string(),
        BootstrapKind::Pyzmq => "pyzmq".to_string(),
        BootstrapKind::Wheel { name, version } => format!("{name}-{version}.whl"),
    };
    let name = if component.kind.is_executable() {
        format!("{stem}{EXECUTABLE_SUFFIX}")
    } else {
        stem
    };
    validate_install_name(&name)?;
    Ok(name)
}

fn install_bytes(
    bin_dir: &Path,
    component: &BootstrapComponent,
    bytes: &[u8],
    expected_sha256: &str,
) -> BootstrapResult<InstallOutcome> {
    let file_name = component_file_name(component)?;
    let target = bin_dir.join(&file_name);
    fs::create_dir_all(bin_dir)?;

    match fs::symlink_metadata(&target) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err(BootstrapError::new(
                    BootstrapErrorKind::PathUnsafe,
                    format!("install target {} is not a regular file", target.display()),
                ));
            }
            if metadata.len() > MAX_COMPONENT_BYTES {
                return Err(BootstrapError::new(
                    BootstrapErrorKind::TooLarge,
                    format!(
                        "install target {} is {} bytes, above the {MAX_COMPONENT_BYTES} byte component limit",
                        target.display(),
                        metadata.len()
                    ),
                ));
            }
            if metadata.len() != bytes.len() as u64 {
                return Err(install_conflict(&target, expected_sha256));
            }
            let existing = file_sha256(&target)?;
            if existing == expected_sha256 {
                Ok(InstallOutcome::AlreadyPresent)
            } else {
                Err(install_conflict(&target, expected_sha256))
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_new_file(&target, bytes, component, expected_sha256)
        }
        Err(error) => Err(error.into()),
    }
}

fn install_conflict(target: &Path, expected_sha256: &str) -> BootstrapError {
    BootstrapError::new(
        BootstrapErrorKind::InstallConflict,
        format!(
            "install target {} already exists with a different digest; refusing to overwrite it with {expected_sha256}",
            target.display()
        ),
    )
}

fn write_new_file(
    target: &Path,
    bytes: &[u8],
    component: &BootstrapComponent,
    expected_sha256: &str,
) -> BootstrapResult<InstallOutcome> {
    let parent = target.parent().ok_or_else(|| {
        BootstrapError::new(
            BootstrapErrorKind::PathUnsafe,
            format!(
                "install target {} has no parent directory",
                target.display()
            ),
        )
    })?;
    fs::create_dir_all(parent)?;
    let temporary = temporary_path(parent);

    let written = (|| -> BootstrapResult<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        apply_permissions(&temporary, component)?;
        Ok(())
    })();
    if let Err(error) = written {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }

    match fs::rename(&temporary, target) {
        Ok(()) => Ok(InstallOutcome::Installed),
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            if target.is_file() && file_sha256(target)? == expected_sha256 {
                return Ok(InstallOutcome::AlreadyPresent);
            }
            Err(error.into())
        }
    }
}

#[cfg(unix)]
fn apply_permissions(path: &Path, component: &BootstrapComponent) -> BootstrapResult<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if component.kind.is_executable() {
        0o755
    } else {
        0o644
    };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn apply_permissions(_path: &Path, _component: &BootstrapComponent) -> BootstrapResult<()> {
    Ok(())
}

/// The kernel readiness report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelStatus {
    /// The detected Python version or install path.
    pub python: Option<String>,
    /// The detected `ipykernel` version or install path.
    pub ipykernel: Option<String>,
    /// True when both Python and `ipykernel` are present.
    pub ready: bool,
}

/// The injected kernel probe seam. A real probe runs the interpreter; tests
/// inject a fixed one.
pub trait KernelProbe {
    /// The Python version or path, or `None` when missing.
    fn python(&self, env: &BootstrapEnv) -> Option<String>;
    /// The `ipykernel` version or path, or `None` when missing.
    fn ipykernel(&self, env: &BootstrapEnv) -> Option<String>;
}

/// The default probe: checks the bootstrap bin directory for the installed
/// files. It reports the path, not an interpreter version.
#[derive(Debug, Clone, Copy, Default)]
pub struct BinDirProbe;

impl KernelProbe for BinDirProbe {
    fn python(&self, env: &BootstrapEnv) -> Option<String> {
        installed_file(env, &format!("python{EXECUTABLE_SUFFIX}"))
    }

    fn ipykernel(&self, env: &BootstrapEnv) -> Option<String> {
        installed_file(env, "ipykernel")
    }
}

fn installed_file(env: &BootstrapEnv, name: &str) -> Option<String> {
    let path = env.bin_dir.join(name);
    if path.is_file() {
        Some(path.display().to_string())
    } else {
        None
    }
}

/// Probe the kernel through an injected [`KernelProbe`].
pub fn probe_kernel(env: &BootstrapEnv, probe: &dyn KernelProbe) -> KernelStatus {
    let python = probe.python(env);
    let ipykernel = probe.ipykernel(env);
    let ready = python.is_some() && ipykernel.is_some();
    KernelStatus {
        python,
        ipykernel,
        ready,
    }
}

fn plan_guidance(error: &BootstrapError) -> String {
    match error.kind() {
        BootstrapErrorKind::LimitExceeded | BootstrapErrorKind::PlanInvalid => format!(
            "fix the bootstrap plan before retrying: {}",
            error.message()
        ),
        _ => format!("the bootstrap plan could not be used: {}", error.message()),
    }
}

fn component_guidance(
    component: &BootstrapComponent,
    error: &BootstrapError,
    env: &BootstrapEnv,
) -> String {
    let label = component.label();
    let sha256 = component.sha256.as_str();
    match error.kind() {
        BootstrapErrorKind::CacheMiss => format!(
            "component `{label}` (sha256 {sha256}) is missing from the offline cache at {}; run the bootstrap once online, or copy the verified file to {}",
            env.cache_dir.display(),
            env.cache_dir.join(format!("{sha256}.bin")).display()
        ),
        BootstrapErrorKind::CacheTampered => format!(
            "the cached bytes for `{label}` do not match sha256 {sha256}; delete {} and let an online run download it again",
            env.cache_dir.join(format!("{sha256}.bin")).display()
        ),
        BootstrapErrorKind::ChecksumMismatch => format!(
            "the bytes for `{label}` do not match the pinned sha256 {sha256}; nothing was installed or cached. Check the release manifest and the mirror."
        ),
        BootstrapErrorKind::PlaceholderChecksum => format!(
            "component `{label}` still has the placeholder digest; pin the real SHA-256 in the release manifest before bootstrapping."
        ),
        BootstrapErrorKind::Download => format!(
            "could not download `{label}` from {}: {}; check the mirror, or seed the cache and retry offline",
            component.url,
            error.message()
        ),
        BootstrapErrorKind::InstallConflict => format!(
            "`{label}` is already installed with a different digest; move or remove the existing file in {} and retry",
            env.bin_dir.display()
        ),
        BootstrapErrorKind::PathUnsafe => format!(
            "the install name for `{label}` is not a safe file name; fix the component name or version"
        ),
        BootstrapErrorKind::TooLarge => format!(
            "`{label}` exceeds the {MAX_COMPONENT_BYTES} byte component limit; use a smaller artifact or raise the documented limit"
        ),
        BootstrapErrorKind::CacheWrite => format!(
            "could not store `{label}` in the cache at {}; check permissions and free space",
            env.cache_dir.display()
        ),
        BootstrapErrorKind::LimitExceeded | BootstrapErrorKind::PlanInvalid => {
            format!("fix the bootstrap plan: {}", error.message())
        }
        BootstrapErrorKind::Io => format!(
            "a filesystem operation failed for `{label}`: {}; check {} and {}",
            error.message(),
            env.bin_dir.display(),
            env.cache_dir.display()
        ),
    }
}

fn validate_manifest_version(value: &str) -> BootstrapResult<()> {
    if value.is_empty() {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PlanInvalid,
            "bootstrap manifest_version must not be empty",
        ));
    }
    if value.len() > MAX_BOOTSTRAP_FIELD_BYTES {
        return Err(limit_error(value.len(), "manifest_version"));
    }
    let first = value.as_bytes()[0];
    if !first.is_ascii_alphanumeric() || value.contains("..") {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PlanInvalid,
            "bootstrap manifest_version must start alphanumeric and must not contain `..`",
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-' | b'_'))
    {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PlanInvalid,
            "bootstrap manifest_version may contain only letters, digits, `.`, `+`, `-`, and `_`",
        ));
    }
    Ok(())
}

fn validate_python_version(value: &str) -> BootstrapResult<()> {
    if value.is_empty() {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PlanInvalid,
            "bootstrap python_version must not be empty",
        ));
    }
    if value.len() > 32 {
        return Err(limit_error(value.len(), "python_version"));
    }
    let parts: Vec<&str> = value.split('.').collect();
    if parts
        .iter()
        .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PlanInvalid,
            "bootstrap python_version must be dot-separated numeric segments, e.g. 3.12.7",
        ));
    }
    Ok(())
}

fn validate_cache_dir(value: &str) -> BootstrapResult<()> {
    if value.is_empty() {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PlanInvalid,
            "bootstrap cache_dir must not be empty",
        ));
    }
    if value.len() > MAX_CACHE_DIR_BYTES {
        return Err(limit_error(value.len(), "cache_dir"));
    }
    if value.chars().any(char::is_control) {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PlanInvalid,
            "bootstrap cache_dir must not contain control characters",
        ));
    }
    Ok(())
}

fn validate_text(value: &str, field: &str) -> BootstrapResult<()> {
    if value.is_empty() {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PlanInvalid,
            format!("component {field} must not be empty"),
        ));
    }
    if value.len() > MAX_BOOTSTRAP_FIELD_BYTES {
        return Err(limit_error(value.len(), field));
    }
    if value.chars().any(char::is_control) {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PlanInvalid,
            format!("component {field} must not contain control characters"),
        ));
    }
    Ok(())
}

fn validate_component_token(value: &str, field: &str) -> BootstrapResult<()> {
    validate_text(value, field)?;
    if !value.as_bytes()[0].is_ascii_alphanumeric() {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PlanInvalid,
            format!("component {field} must start with a letter or digit"),
        ));
    }
    if value.contains("..") {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PlanInvalid,
            format!("component {field} must not contain `..`"),
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
    {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PlanInvalid,
            format!("component {field} may contain only letters, digits, `.`, `_`, `+`, and `-`"),
        ));
    }
    Ok(())
}

fn validate_url(value: &str) -> BootstrapResult<()> {
    if value.len() > MAX_URL_BYTES {
        return Err(limit_error(value.len(), "url"));
    }
    let Some(rest) = value.strip_prefix("https://") else {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PlanInvalid,
            "component url must use https://",
        ));
    };
    if rest.is_empty() || rest.starts_with('/') {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PlanInvalid,
            "component url must name a host after https://",
        ));
    }
    if rest.contains('@') {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PlanInvalid,
            "component url must not embed credentials",
        ));
    }
    if rest
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
        || rest.contains('\\')
    {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PlanInvalid,
            "component url must not contain whitespace, control characters, or a backslash",
        ));
    }
    Ok(())
}

fn validate_sha256(value: &str) -> BootstrapResult<()> {
    if !is_lower_hex_sha256(value) {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PlanInvalid,
            format!(
                "component sha256 must be {SHA256_HEX_BYTES} lowercase hex characters, got `{value}`"
            ),
        ));
    }
    Ok(())
}

fn validate_install_name(value: &str) -> BootstrapResult<()> {
    if value.is_empty() {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PathUnsafe,
            "an install file name must not be empty",
        ));
    }
    if value.len() > MAX_BOOTSTRAP_FIELD_BYTES {
        return Err(limit_error(value.len(), "install file name"));
    }
    if value == "." || value == ".." || value.starts_with('.') {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PathUnsafe,
            format!("install file name `{value}` must be a normal file name"),
        ));
    }
    if value
        .bytes()
        .any(|byte| matches!(byte, b'/' | b'\\' | b':') || byte.is_ascii_control())
    {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PathUnsafe,
            format!("install file name `{value}` must not contain a path separator or control character"),
        ));
    }
    if value.ends_with(' ') || value.ends_with('.') {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PathUnsafe,
            format!("install file name `{value}` must not end with a space or a dot"),
        ));
    }
    if is_reserved_windows_name(value) {
        return Err(BootstrapError::new(
            BootstrapErrorKind::PathUnsafe,
            format!("install file name `{value}` must not be a reserved Windows device name"),
        ));
    }
    Ok(())
}

fn is_reserved_windows_name(value: &str) -> bool {
    let stem = value
        .split('.')
        .next()
        .unwrap_or(value)
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit())
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == SHA256_HEX_BYTES
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn limit_error(size: usize, field: &str) -> BootstrapError {
    BootstrapError::new(
        BootstrapErrorKind::LimitExceeded,
        format!("{field} is {size} bytes, above the allowed bootstrap limit"),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn file_sha256(path: &Path) -> BootstrapResult<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(&hasher.finalize()))
}

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn temporary_path(parent: &Path) -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    parent.join(format!("{TEMP_PREFIX}{}-{sequence}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    struct MemoryCache {
        entries: RefCell<HashMap<String, Vec<u8>>>,
        puts: Cell<usize>,
    }

    impl MemoryCache {
        fn new() -> Self {
            Self {
                entries: RefCell::new(HashMap::new()),
                puts: Cell::new(0),
            }
        }

        fn seed(&self, sha256: &str, bytes: &[u8]) {
            self.entries
                .borrow_mut()
                .insert(sha256.to_string(), bytes.to_vec());
        }
    }

    impl Cache for MemoryCache {
        fn get(&self, sha256: &str) -> Option<Vec<u8>> {
            self.entries.borrow().get(sha256).cloned()
        }

        fn put(&self, sha256: &str, bytes: &[u8]) -> BootstrapResult<()> {
            self.puts.set(self.puts.get() + 1);
            self.entries
                .borrow_mut()
                .insert(sha256.to_string(), bytes.to_vec());
            Ok(())
        }
    }

    struct FakeDownloader {
        payloads: HashMap<String, Vec<u8>>,
        calls: Cell<usize>,
        error: Option<String>,
    }

    impl FakeDownloader {
        fn with(payloads: &[(&BootstrapComponent, &[u8])]) -> Self {
            let mut map = HashMap::new();
            for (component, bytes) in payloads {
                map.insert(component.url.clone(), bytes.to_vec());
            }
            Self {
                payloads: map,
                calls: Cell::new(0),
                error: None,
            }
        }

        fn failing(message: &str) -> Self {
            Self {
                payloads: HashMap::new(),
                calls: Cell::new(0),
                error: Some(message.to_string()),
            }
        }

        fn calls(&self) -> usize {
            self.calls.get()
        }
    }

    impl Downloader for FakeDownloader {
        fn download(&self, url: &str, _size: u64) -> BootstrapResult<Vec<u8>> {
            self.calls.set(self.calls.get() + 1);
            if let Some(message) = &self.error {
                return Err(BootstrapError::new(
                    BootstrapErrorKind::Download,
                    message.clone(),
                ));
            }
            self.payloads.get(url).cloned().ok_or_else(|| {
                BootstrapError::new(
                    BootstrapErrorKind::Download,
                    format!("no fixture payload for {url}"),
                )
            })
        }
    }

    struct FixedProbe {
        python: Option<String>,
        ipykernel: Option<String>,
    }

    impl KernelProbe for FixedProbe {
        fn python(&self, _env: &BootstrapEnv) -> Option<String> {
            self.python.clone()
        }

        fn ipykernel(&self, _env: &BootstrapEnv) -> Option<String> {
            self.ipykernel.clone()
        }
    }

    const UV_BYTES: &[u8] = b"uv-binary-0.5.11";
    const PYTHON_BYTES: &[u8] = b"python-3.12.7-runtime";
    const IPYKERNEL_BYTES: &[u8] = b"ipykernel-6.29.5";

    fn component(kind: BootstrapKind, url: &str, bytes: &[u8]) -> BootstrapComponent {
        BootstrapComponent {
            kind,
            version_req: ">=1".to_string(),
            url: url.to_string(),
            sha256: sha256_hex(bytes),
            optional: false,
        }
    }

    fn uv() -> BootstrapComponent {
        component(BootstrapKind::Uv, "https://example.invalid/uv", UV_BYTES)
    }

    fn python() -> BootstrapComponent {
        component(
            BootstrapKind::Python,
            "https://example.invalid/python",
            PYTHON_BYTES,
        )
    }

    fn ipykernel() -> BootstrapComponent {
        component(
            BootstrapKind::Ipkernel,
            "https://example.invalid/ipykernel",
            IPYKERNEL_BYTES,
        )
    }

    fn plan(components: Vec<BootstrapComponent>) -> BootstrapPlan {
        BootstrapPlan {
            schema_version: BOOTSTRAP_SCHEMA_VERSION,
            manifest_version: "test-manifest-1".to_string(),
            python_version: "3.12.7".to_string(),
            cache_dir: DEFAULT_CACHE_DIR.to_string(),
            components,
        }
    }

    fn three_component_plan() -> BootstrapPlan {
        plan(vec![uv(), python(), ipykernel()])
    }

    fn downloader_for(plan: &BootstrapPlan, payloads: &[&[u8]]) -> FakeDownloader {
        let pairs: Vec<(&BootstrapComponent, &[u8])> = plan
            .components
            .iter()
            .zip(payloads.iter().copied())
            .collect();
        FakeDownloader::with(&pairs)
    }

    fn fill_cache(cache: &FsCache, plan: &BootstrapPlan, payloads: &[&[u8]]) {
        for (component, bytes) in plan.components.iter().zip(payloads.iter().copied()) {
            cache.put(&component.sha256, bytes).expect("seed cache");
        }
    }

    fn installed_name(component: &BootstrapComponent) -> String {
        component_file_name(component).expect("safe name")
    }

    fn directory_is_empty(path: &Path) -> bool {
        !path.exists()
            || fs::read_dir(path)
                .map(|mut it| it.next().is_none())
                .unwrap_or(true)
    }

    #[test]
    fn the_default_plan_is_clearly_marked_as_a_placeholder() {
        let plan = default_plan("3.12.7");
        plan.validate().expect("the representative plan is valid");
        assert_eq!(plan.manifest_version, PLACEHOLDER_MANIFEST_VERSION);
        assert_eq!(plan.schema_version, BOOTSTRAP_SCHEMA_VERSION);
        assert!(plan.has_placeholder_checksums());
        assert!(plan
            .components
            .iter()
            .all(BootstrapComponent::is_placeholder_checksum));
        assert!(plan.components.iter().any(|c| c.kind == BootstrapKind::Uv));
        assert!(plan
            .components
            .iter()
            .any(|c| c.kind == BootstrapKind::Python));
        assert!(plan
            .components
            .iter()
            .any(|c| c.kind == BootstrapKind::Ipkernel));
        assert!(plan
            .components
            .iter()
            .any(|c| matches!(c.kind, BootstrapKind::Wheel { .. })));
        assert!(plan
            .components
            .iter()
            .all(|c| c.url.starts_with("https://")));

        let directory = tempfile::tempdir().expect("tempdir");
        let env = BootstrapEnv::new(
            directory.path().join("cache"),
            directory.path().join("bin"),
            true,
        );
        let downloader = FakeDownloader::with(&[]);
        let report = bootstrap(&plan, &env, &downloader);
        assert!(!report.is_success());
        assert_eq!(report.failed.len(), 1);
        assert_eq!(
            report.failed[0].kind,
            BootstrapErrorKind::PlaceholderChecksum
        );
        assert!(report.failed[0].guidance.contains("placeholder"));
        assert_eq!(downloader.calls(), 0);
        assert!(report.installed.is_empty());
    }

    #[test]
    fn plan_validation_rejects_duplicates_bad_digests_and_insecure_urls() {
        let duplicate_kind = plan(vec![uv(), uv()]);
        let error = duplicate_kind.validate().unwrap_err();
        assert_eq!(error.kind(), BootstrapErrorKind::PlanInvalid);
        assert!(error.message().contains("repeats"), "{error}");

        let wheel = |name: &str, version: &str| BootstrapComponent {
            kind: BootstrapKind::Wheel {
                name: name.to_string(),
                version: version.to_string(),
            },
            version_req: "==1".to_string(),
            url: "https://example.invalid/wheel".to_string(),
            sha256: "a".repeat(64),
            optional: false,
        };
        let duplicate_wheel = plan(vec![
            wheel("traitlets", "5.14.3"),
            wheel("traitlets", "5.9.0"),
        ]);
        let error = duplicate_wheel.validate().unwrap_err();
        assert!(error.message().contains("repeats"), "{error}");

        let mut bad_digest = uv();
        bad_digest.sha256 = "A".repeat(64);
        assert_eq!(
            plan(vec![bad_digest]).validate().unwrap_err().kind(),
            BootstrapErrorKind::PlanInvalid
        );

        let mut short_digest = uv();
        short_digest.sha256 = "abc".to_string();
        assert_eq!(
            plan(vec![short_digest]).validate().unwrap_err().kind(),
            BootstrapErrorKind::PlanInvalid
        );

        for url in [
            "http://example.invalid/uv",
            "https://",
            "https://example.invalid/a b",
            "https://user:pass@example.invalid/uv",
            "https://example.invalid/a\\b",
        ] {
            let mut component = uv();
            component.url = url.to_string();
            assert!(
                plan(vec![component]).validate().is_err(),
                "url `{url}` must be refused"
            );
        }

        let mut wrong_schema = plan(vec![uv()]);
        wrong_schema.schema_version = 2;
        assert!(wrong_schema.validate().is_err());

        assert!(plan(Vec::new()).validate().is_err());

        let mut empty_manifest = plan(vec![uv()]);
        empty_manifest.manifest_version.clear();
        assert!(empty_manifest.validate().is_err());

        let mut bad_python = plan(vec![uv()]);
        bad_python.python_version = "3.x".to_string();
        assert!(bad_python.validate().is_err());

        let mut empty_cache = plan(vec![uv()]);
        empty_cache.cache_dir.clear();
        assert!(empty_cache.validate().is_err());
    }

    #[test]
    fn component_limits_and_unsafe_names_are_enforced() {
        let components: Vec<BootstrapComponent> = (0..=MAX_BOOTSTRAP_COMPONENTS)
            .map(|index| BootstrapComponent {
                kind: BootstrapKind::Wheel {
                    name: format!("pkg{index}"),
                    version: "1.0.0".to_string(),
                },
                version_req: "==1.0.0".to_string(),
                url: "https://example.invalid/wheel".to_string(),
                sha256: "a".repeat(64),
                optional: false,
            })
            .collect();
        let error = plan(components).validate().unwrap_err();
        assert_eq!(error.kind(), BootstrapErrorKind::LimitExceeded);

        let long_url = format!("https://example.invalid/{}", "a".repeat(MAX_URL_BYTES));
        let mut component = uv();
        component.url = long_url;
        assert_eq!(
            plan(vec![component]).validate().unwrap_err().kind(),
            BootstrapErrorKind::LimitExceeded
        );

        let safe_wheel = BootstrapComponent {
            kind: BootstrapKind::Wheel {
                name: "traitlets".to_string(),
                version: "5.14.3".to_string(),
            },
            version_req: "==5.14.3".to_string(),
            url: "https://example.invalid/wheel".to_string(),
            sha256: "a".repeat(64),
            optional: false,
        };
        assert_eq!(
            component_file_name(&safe_wheel).unwrap(),
            "traitlets-5.14.3.whl"
        );
        let expected_uv = if cfg!(windows) { "uv.exe" } else { "uv" };
        assert_eq!(component_file_name(&uv()).unwrap(), expected_uv);
        assert_eq!(component_file_name(&ipykernel()).unwrap(), "ipykernel");
        assert_eq!(component_file_name(&python()).unwrap(), {
            if cfg!(windows) {
                "python.exe"
            } else {
                "python"
            }
        });

        for (name, version) in [
            ("../evil", "1.0.0"),
            ("a/b", "1.0.0"),
            ("evil ", "1.0.0"),
            ("traitlets", "1/2"),
            ("traitlets", ".."),
        ] {
            let component = BootstrapComponent {
                kind: BootstrapKind::Wheel {
                    name: name.to_string(),
                    version: version.to_string(),
                },
                version_req: "==1".to_string(),
                url: "https://example.invalid/wheel".to_string(),
                sha256: "a".repeat(64),
                optional: false,
            };
            assert!(
                plan(vec![component]).validate().is_err(),
                "wheel `{name}` `{version}` must be refused"
            );
        }

        for unsafe_name in [
            "CON", "NUL.txt", "COM1", "lpt9", ".hidden", "name.", "name ",
        ] {
            assert!(
                validate_install_name(unsafe_name).is_err(),
                "install name `{unsafe_name}` must be refused"
            );
        }
        for safe_name in ["uv", "uv.exe", "python", "traitlets-5.14.3.whl", "console"] {
            validate_install_name(safe_name).expect("safe install name");
        }
    }

    #[test]
    fn offline_bootstrap_from_a_populated_cache_succeeds() {
        let directory = tempfile::tempdir().expect("tempdir");
        let cache = FsCache::new(directory.path().join("cache"));
        let plan = three_component_plan();
        fill_cache(&cache, &plan, &[UV_BYTES, PYTHON_BYTES, IPYKERNEL_BYTES]);

        let env = BootstrapEnv::new(cache.root(), directory.path().join("bin"), true);
        let downloader = FakeDownloader::with(&[]);
        let report = bootstrap(&plan, &env, &downloader);

        assert!(report.is_success(), "{:?}", report.failed);
        assert!(report.failed.is_empty());
        assert_eq!(report.installed.len(), 3);
        assert_eq!(report.reused_from_cache.len(), 3);
        assert!(report.downloaded.is_empty());
        assert!(report.already_installed.is_empty());
        assert_eq!(downloader.calls(), 0);
        assert_eq!(
            report.path_entry(),
            Some(env.bin_dir.display().to_string().as_str())
        );

        for (component, expected) in
            plan.components
                .iter()
                .zip([UV_BYTES, PYTHON_BYTES, IPYKERNEL_BYTES])
        {
            let installed = env.bin_dir.join(installed_name(component));
            assert_eq!(fs::read(&installed).unwrap(), expected);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let uv_mode = fs::metadata(env.bin_dir.join("uv"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(uv_mode & 0o777, 0o755);
            let kernel_mode = fs::metadata(env.bin_dir.join("ipykernel"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(kernel_mode & 0o777, 0o644);
        }
    }

    #[test]
    fn offline_missing_component_fails_with_guidance_and_no_download() {
        let directory = tempfile::tempdir().expect("tempdir");
        let plan = plan(vec![uv()]);
        let env = BootstrapEnv::new(
            directory.path().join("cache"),
            directory.path().join("bin"),
            true,
        );
        let downloader = FakeDownloader::with(&[(&plan.components[0], UV_BYTES)]);
        let report = bootstrap(&plan, &env, &downloader);

        assert!(!report.is_success());
        assert_eq!(report.failed.len(), 1);
        let failure = &report.failed[0];
        assert_eq!(failure.kind, BootstrapErrorKind::CacheMiss);
        assert_eq!(failure.component, "uv");
        assert_eq!(failure.sha256, plan.components[0].sha256);
        assert!(failure.guidance.contains(&plan.components[0].sha256));
        assert!(failure.guidance.contains("offline cache"));
        assert!(failure.guidance.contains("cache"));
        assert_eq!(downloader.calls(), 0);
        assert!(report.installed.is_empty());
        assert!(report.downloaded.is_empty());
        assert!(directory_is_empty(&env.bin_dir));
    }

    #[test]
    fn online_miss_downloads_verifies_and_stores_in_the_cache() {
        let directory = tempfile::tempdir().expect("tempdir");
        let cache = FsCache::new(directory.path().join("cache"));
        let plan = three_component_plan();
        let env = BootstrapEnv::new(cache.root(), directory.path().join("bin"), false);
        let downloader = downloader_for(&plan, &[UV_BYTES, PYTHON_BYTES, IPYKERNEL_BYTES]);
        let report = bootstrap(&plan, &env, &downloader);

        assert!(report.is_success(), "{:?}", report.failed);
        assert_eq!(report.downloaded.len(), 3);
        assert_eq!(report.installed.len(), 3);
        assert!(report.reused_from_cache.is_empty());
        assert_eq!(downloader.calls(), 3);

        for (component, expected) in
            plan.components
                .iter()
                .zip([UV_BYTES, PYTHON_BYTES, IPYKERNEL_BYTES])
        {
            let cached = cache.get(&component.sha256).expect("cached after download");
            assert_eq!(cached, expected);
            assert_eq!(
                fs::read(env.bin_dir.join(installed_name(component))).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn a_bad_checksum_is_refused_and_nothing_is_installed_or_cached() {
        let directory = tempfile::tempdir().expect("tempdir");
        let cache = FsCache::new(directory.path().join("cache"));
        let plan = plan(vec![uv()]);
        let env = BootstrapEnv::new(cache.root(), directory.path().join("bin"), false);
        let downloader = FakeDownloader::with(&[(&plan.components[0], b"tampered bytes")]);
        let report = bootstrap(&plan, &env, &downloader);

        assert!(!report.is_success());
        assert_eq!(report.failed.len(), 1);
        let failure = &report.failed[0];
        assert_eq!(failure.kind, BootstrapErrorKind::ChecksumMismatch);
        assert!(failure.guidance.contains(&plan.components[0].sha256));
        assert!(failure.message.contains("nothing was installed"));
        assert_eq!(downloader.calls(), 1);
        assert!(report.installed.is_empty());
        assert!(cache.get(&plan.components[0].sha256).is_none());
        assert!(directory_is_empty(&env.bin_dir));
    }

    #[test]
    fn a_tampered_cache_entry_is_refused_without_a_download() {
        let directory = tempfile::tempdir().expect("tempdir");
        let cache = FsCache::new(directory.path().join("cache"));
        let plan = plan(vec![uv()]);
        fs::create_dir_all(cache.root()).unwrap();
        fs::write(
            cache.path_for(&plan.components[0].sha256).unwrap(),
            b"corrupted cache bytes",
        )
        .unwrap();
        let env = BootstrapEnv::new(cache.root(), directory.path().join("bin"), false);
        let downloader = FakeDownloader::with(&[(&plan.components[0], UV_BYTES)]);
        let report = bootstrap(&plan, &env, &downloader);

        assert!(!report.is_success());
        assert_eq!(report.failed[0].kind, BootstrapErrorKind::CacheTampered);
        assert!(report.failed[0].guidance.contains("delete"));
        assert_eq!(downloader.calls(), 0);
        assert!(report.installed.is_empty());
        assert!(directory_is_empty(&env.bin_dir));
    }

    #[test]
    fn a_cache_hit_does_not_download() {
        let cache = MemoryCache::new();
        let plan = plan(vec![uv()]);
        cache.seed(&plan.components[0].sha256, UV_BYTES);
        let directory = tempfile::tempdir().expect("tempdir");
        let env = BootstrapEnv::new(
            directory.path().join("cache"),
            directory.path().join("bin"),
            false,
        );
        let downloader = FakeDownloader::with(&[]);
        let report = bootstrap_with_cache(&plan, &env, &downloader, &cache);

        assert!(report.is_success(), "{:?}", report.failed);
        assert_eq!(report.reused_from_cache, vec!["uv".to_string()]);
        assert_eq!(report.installed, vec!["uv".to_string()]);
        assert!(report.downloaded.is_empty());
        assert_eq!(downloader.calls(), 0);
        assert_eq!(cache.puts.get(), 0, "a hit must not rewrite the cache");
        assert_eq!(
            fs::read(env.bin_dir.join(installed_name(&plan.components[0]))).unwrap(),
            UV_BYTES
        );
    }

    #[test]
    fn a_second_run_reuses_installed_components() {
        let directory = tempfile::tempdir().expect("tempdir");
        let cache = FsCache::new(directory.path().join("cache"));
        let plan = three_component_plan();
        let env = BootstrapEnv::new(cache.root(), directory.path().join("bin"), false);

        let first_downloader = downloader_for(&plan, &[UV_BYTES, PYTHON_BYTES, IPYKERNEL_BYTES]);
        let first = bootstrap(&plan, &env, &first_downloader);
        assert!(first.is_success(), "{:?}", first.failed);
        assert_eq!(first.installed.len(), 3);
        let before: Vec<Vec<u8>> = plan
            .components
            .iter()
            .map(|component| fs::read(env.bin_dir.join(installed_name(component))).unwrap())
            .collect();

        let second_downloader = FakeDownloader::with(&[]);
        let second = bootstrap(&plan, &env, &second_downloader);
        assert!(second.is_success(), "{:?}", second.failed);
        assert!(second.installed.is_empty());
        assert_eq!(second.already_installed.len(), 3);
        assert_eq!(second.reused_from_cache.len(), 3);
        assert!(second.downloaded.is_empty());
        assert_eq!(second_downloader.calls(), 0);

        let after: Vec<Vec<u8>> = plan
            .components
            .iter()
            .map(|component| fs::read(env.bin_dir.join(installed_name(component))).unwrap())
            .collect();
        assert_eq!(before, after);
    }

    #[test]
    fn an_install_conflict_does_not_overwrite_another_hash() {
        let directory = tempfile::tempdir().expect("tempdir");
        let cache = FsCache::new(directory.path().join("cache"));
        let plan = plan(vec![uv()]);
        fill_cache(&cache, &plan, &[UV_BYTES]);
        let bin = directory.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let target = bin.join(installed_name(&plan.components[0]));
        fs::write(&target, b"another installation").unwrap();

        let env = BootstrapEnv::new(cache.root(), &bin, true);
        let downloader = FakeDownloader::with(&[]);
        let report = bootstrap(&plan, &env, &downloader);

        assert!(!report.is_success());
        assert_eq!(report.failed[0].kind, BootstrapErrorKind::InstallConflict);
        assert!(report.installed.is_empty());
        assert_eq!(fs::read(&target).unwrap(), b"another installation");
        assert_eq!(downloader.calls(), 0);
    }

    #[test]
    fn a_download_error_is_reported_without_installing() {
        let directory = tempfile::tempdir().expect("tempdir");
        let plan = plan(vec![uv()]);
        let env = BootstrapEnv::new(
            directory.path().join("cache"),
            directory.path().join("bin"),
            false,
        );
        let downloader = FakeDownloader::failing("mirror unreachable");
        let report = bootstrap(&plan, &env, &downloader);

        assert!(!report.is_success());
        assert_eq!(report.failed[0].kind, BootstrapErrorKind::Download);
        assert!(report.failed[0].guidance.contains("mirror unreachable"));
        assert_eq!(downloader.calls(), 1);
        assert!(report.installed.is_empty());
        assert!(directory_is_empty(&env.bin_dir));
    }

    #[test]
    fn an_optional_component_failure_does_not_fail_the_bootstrap() {
        let directory = tempfile::tempdir().expect("tempdir");
        let cache = FsCache::new(directory.path().join("cache"));
        let mut missing = python();
        missing.optional = true;
        let plan = plan(vec![uv(), missing]);
        cache
            .put(&plan.components[0].sha256, UV_BYTES)
            .expect("seed uv only");

        let env = BootstrapEnv::new(cache.root(), directory.path().join("bin"), true);
        let downloader = FakeDownloader::with(&[]);
        let report = bootstrap(&plan, &env, &downloader);

        assert!(report.is_success(), "{:?}", report.failed);
        assert_eq!(report.installed, vec!["uv".to_string()]);
        assert_eq!(report.failed.len(), 1);
        assert!(report.failed[0].optional);
        assert_eq!(report.failed[0].component, "python");
        assert_eq!(report.failed[0].kind, BootstrapErrorKind::CacheMiss);
        assert_eq!(downloader.calls(), 0);
    }

    #[test]
    fn env_vars_are_path_like_and_carry_no_secrets() {
        let directory = tempfile::tempdir().expect("tempdir");
        let cache = FsCache::new(directory.path().join("cache"));
        let plan = plan(vec![uv()]);
        fill_cache(&cache, &plan, &[UV_BYTES]);
        let env = BootstrapEnv::new(cache.root(), directory.path().join("bin"), true);
        let downloader = FakeDownloader::with(&[]);
        let report = bootstrap(&plan, &env, &downloader);

        assert_eq!(report.env_vars.len(), 1);
        let keys: Vec<&String> = report.env_vars.keys().collect();
        assert_eq!(keys, vec!["PATH"]);
        let path = report.path_entry().expect("PATH entry");
        assert_eq!(path, env.bin_dir.display().to_string());
        assert!(!path.contains("token"));
        assert!(!path.contains("secret"));
    }

    #[test]
    fn probe_reports_ready_only_when_python_and_ipykernel_are_present() {
        let directory = tempfile::tempdir().expect("tempdir");
        let env = BootstrapEnv::new(
            directory.path().join("cache"),
            directory.path().join("bin"),
            true,
        );

        let status = probe_kernel(&env, &BinDirProbe);
        assert!(!status.ready);
        assert!(status.python.is_none());
        assert!(status.ipykernel.is_none());

        fs::create_dir_all(&env.bin_dir).unwrap();
        fs::write(
            env.bin_dir.join(format!("python{EXECUTABLE_SUFFIX}")),
            b"python",
        )
        .unwrap();
        let status = probe_kernel(&env, &BinDirProbe);
        assert!(!status.ready, "ipykernel is still missing");
        assert!(status.python.is_some());
        assert!(status.ipykernel.is_none());

        fs::write(env.bin_dir.join("ipykernel"), b"ipykernel").unwrap();
        let status = probe_kernel(&env, &BinDirProbe);
        assert!(status.ready);
        assert!(status.python.unwrap().contains("python"));
        assert!(status.ipykernel.unwrap().contains("ipykernel"));

        let fixed = FixedProbe {
            python: Some("3.12.7".to_string()),
            ipykernel: None,
        };
        let status = probe_kernel(&env, &fixed);
        assert!(!status.ready);
        assert_eq!(status.python.as_deref(), Some("3.12.7"));

        let fixed = FixedProbe {
            python: Some("3.12.7".to_string()),
            ipykernel: Some("6.29.5".to_string()),
        };
        let status = probe_kernel(&env, &fixed);
        assert!(status.ready);
        assert_eq!(status.ipykernel.as_deref(), Some("6.29.5"));
    }

    #[test]
    fn the_offline_path_has_no_network_or_shell_surface() {
        let source = include_str!("bootstrap.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("std::net"));
        assert!(!production.contains("TcpStream"));
        assert!(!production.contains("reqwest"));
        assert!(!production.contains("http://"));
        assert!(!production.contains("Command::new"));
        assert!(!production.contains("sh -c"));
        assert!(production.contains("offline"));
        assert!(production.contains("downloader.download"));
        assert!(source.contains("#[cfg(unix)]"));
        assert!(production.contains("PLACEHOLDER_SHA256"));
    }
}
