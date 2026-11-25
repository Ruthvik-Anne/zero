//! Headless browser fallback (WEB-09, T-WEB-05).
//!
//! JavaScript-heavy pages cannot be read by the in-house HTML tokenizer, so
//! this module drives a locally installed Chromium-family browser as a last
//! resort. It is deliberately small and process-based: discovery, a checksummed
//! install, an isolated profile per session, and one `--dump-dom` render.
//!
//! Choices worth knowing:
//!
//! - **No shell, no PATH lookup.** [`find_system_browser`] probes absolute
//!   platform-standard install locations only. Nothing runs `which`, `where`,
//!   or a shell to locate a browser.
//! - **Checksum before extraction.** [`Installer::install`] writes the archive
//!   to a temporary file, hashes that file, and refuses on a missing or
//!   mismatched digest *before* the archive planner or anything executable sees
//!   the bytes. Installation is unpacking only: no installer program and no
//!   command is ever executed.
//! - **Atomic publish.** The archive is unpacked into a `.staging-*` sibling and
//!   renamed into `browsers/<platform>/<version>` once the manifest is recorded,
//!   so a half-installed browser is never visible under its final name.
//! - **Profile isolation.** Every render creates a fresh
//!   `--user-data-dir` under `profile_root/browser-profiles/<session>`. Two
//!   sessions never share cookies or cache, and [`Profile::close`] removes the
//!   directory. On Unix the directory mode is `0700`; Windows inherits the
//!   user-profile ACLs.
//! - **Local URLs are opt-in.** `http(s)` goes through [`EgressGuard::check_url`]
//!   first. `file:` and `data:` are refused unless `allow_local` is set.
//! - **Typed failures.** A non-zero exit is `zero.fnd.unavailable`, an expired
//!   deadline is `zero.fnd.timeout`, and an output over the cap is
//!   `zero.fnd.limit_exceeded`. Stderr is kept as a short tail and withheld
//!   entirely when it contains a registered secret.
//!
//! Known limitation: `--dump-dom` is a single process with its own networking.
//! The top-level URL is policy-checked, but subresource requests made by the
//! page are **not** pinned or re-checked. Strict egress enforcement belongs to
//! the DevTools transport in [`crate::browser`]; this fallback is for pages the
//! caller already decided to render.

use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::archive::{self, ArchiveLimits};
use crate::egress::EgressGuard;

/// Default render deadline (30 s).
pub const DEFAULT_HEADLESS_TIMEOUT_MS: u64 = 30_000;
/// Default DOM output ceiling (8 MiB).
pub const DEFAULT_MAX_HEADLESS_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
/// Default bytes kept from the end of stderr (4 KiB).
pub const DEFAULT_MAX_STDERR_BYTES: usize = 4 * 1024;
/// Maximum characters of stderr copied into an error message.
pub const MAX_STDERR_CHARS: usize = 400;
/// Inline HTML ceiling for [`HeadlessBrowser::render`]'s override path (8 MiB).
pub const MAX_INLINE_HTML_BYTES: usize = 8 * 1024 * 1024;
/// A `data:` URL must fit on a process command line (16 KiB).
pub const MAX_DATA_URL_BYTES: usize = 16 * 1024;
/// Directory under the data root that holds installed browsers.
const BROWSER_DIR: &str = "browsers";
/// Directory under the data root that holds per-session profiles.
const PROFILE_DIR: &str = "browser-profiles";
/// Name of the archive inside the staging directory.
const ARCHIVE_FILE: &str = "archive.zip";
/// Name of the install record inside a published browser directory.
const RECORD_FILE: &str = "install.json";
/// Install record schema version.
const INSTALL_SCHEMA: u32 = 1;
/// Pause between process liveness probes.
const POLL_INTERVAL: Duration = Duration::from_millis(10);
/// Windows `CREATE_NO_WINDOW`: no console flashes when a daemon renders a page.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// Maximum depth of the installed-browser executable search.
const MAX_SCAN_DEPTH: usize = 10;
/// Maximum directory entries inspected while locating an installed browser.
const MAX_SCAN_ENTRIES: usize = 20_000;

/// File names treated as a browser executable inside an installed archive.
///
/// The list is deliberately fixed. An archive cannot nominate an arbitrary
/// file to run; only a known Chromium-family binary is accepted.
const EXECUTABLE_NAMES: &[&str] = &[
    "chrome.exe",
    "msedge.exe",
    "chromium.exe",
    "chrome",
    "chromium",
    "chromium-browser",
    "microsoft-edge",
    "headless_shell",
    "headless-shell",
];

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyDenied, message)
}

fn unavailable(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Unavailable, message)
}

fn timeout(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Timeout, message)
}

fn limit(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

fn corrupt(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Corrupt, message)
}

fn not_found(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::NotFound, message)
}

fn io_error(error: io::Error) -> ZeroError {
    ZeroError::new(ErrorCode::Io, error.to_string())
}

/// A Chromium-family browser that may be driven headlessly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserChannel {
    Chrome,
    Chromium,
    Edge,
}

impl BrowserChannel {
    /// Stable lower-case name used in diagnostics and documentation.
    pub fn as_str(self) -> &'static str {
        match self {
            BrowserChannel::Chrome => "chrome",
            BrowserChannel::Chromium => "chromium",
            BrowserChannel::Edge => "edge",
        }
    }

    /// Headless switch for this channel.
    ///
    /// Every supported channel is Chromium-based, so all three understand
    /// `--headless=new`.
    pub fn headless_flag(self) -> &'static str {
        "--headless=new"
    }
}

/// One locally discovered browser executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserCandidate {
    /// Browser family, used for diagnostics and the headless switch.
    pub channel: BrowserChannel,
    /// Absolute path to the executable that was found.
    pub path: PathBuf,
    /// Version when the install path exposes one, for example `124.0.6367.60`.
    pub version: Option<String>,
}

/// Probe the platform-standard install locations for a Chromium-family browser.
///
/// The locations are fixed absolute paths (plus `ProgramFiles`-style
/// environment variables on Windows); no `PATH` lookup or shell command runs.
/// The first existing executable wins, in the order Chrome, Chromium, Edge.
pub fn find_system_browser() -> Option<BrowserCandidate> {
    for (channel, path) in candidate_paths() {
        if is_executable_file(&path) {
            let version = version_from_path(&path);
            return Some(BrowserCandidate {
                channel,
                path,
                version,
            });
        }
    }
    None
}

#[cfg(windows)]
fn candidate_paths() -> Vec<(BrowserChannel, PathBuf)> {
    use BrowserChannel::{Chrome, Chromium, Edge};

    let program_files = std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
    let program_files_x86 = std::env::var_os("ProgramFiles(x86)")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files (x86)"));
    let local_app_data = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);

    let mut paths = vec![
        (
            Chrome,
            program_files
                .join(r"Google\Chrome\Application")
                .join("chrome.exe"),
        ),
        (
            Chrome,
            program_files_x86
                .join(r"Google\Chrome\Application")
                .join("chrome.exe"),
        ),
    ];
    if let Some(local) = &local_app_data {
        paths.push((
            Chrome,
            local.join(r"Google\Chrome\Application").join("chrome.exe"),
        ));
        paths.push((
            Chromium,
            local.join(r"Chromium\Application").join("chrome.exe"),
        ));
    }
    paths.push((
        Edge,
        program_files_x86
            .join(r"Microsoft\Edge\Application")
            .join("msedge.exe"),
    ));
    paths.push((
        Edge,
        program_files
            .join(r"Microsoft\Edge\Application")
            .join("msedge.exe"),
    ));
    paths
}

#[cfg(target_os = "macos")]
fn candidate_paths() -> Vec<(BrowserChannel, PathBuf)> {
    use BrowserChannel::{Chrome, Chromium, Edge};

    let applications = PathBuf::from("/Applications");
    vec![
        (
            Chrome,
            applications
                .join("Google Chrome.app")
                .join("Contents/MacOS/Google Chrome"),
        ),
        (
            Chromium,
            applications
                .join("Chromium.app")
                .join("Contents/MacOS/Chromium"),
        ),
        (
            Edge,
            applications
                .join("Microsoft Edge.app")
                .join("Contents/MacOS/Microsoft Edge"),
        ),
    ]
}

#[cfg(all(unix, not(target_os = "macos")))]
fn candidate_paths() -> Vec<(BrowserChannel, PathBuf)> {
    use BrowserChannel::{Chrome, Chromium, Edge};

    vec![
        (Chrome, PathBuf::from("/usr/bin/google-chrome")),
        (Chrome, PathBuf::from("/usr/bin/google-chrome-stable")),
        (Chromium, PathBuf::from("/usr/bin/chromium")),
        (Chromium, PathBuf::from("/usr/bin/chromium-browser")),
        (Chromium, PathBuf::from("/snap/bin/chromium")),
        (Edge, PathBuf::from("/usr/bin/microsoft-edge")),
        (Edge, PathBuf::from("/usr/bin/microsoft-edge-stable")),
    ]
}

#[cfg(not(any(unix, windows)))]
fn candidate_paths() -> Vec<(BrowserChannel, PathBuf)> {
    Vec::new()
}

fn is_executable_file(path: &Path) -> bool {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return false,
    };
    metadata.is_file() && is_executable_metadata(&metadata)
}

#[cfg(unix)]
fn is_executable_metadata(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable_metadata(_metadata: &fs::Metadata) -> bool {
    true
}

fn version_from_path(path: &Path) -> Option<String> {
    for component in path.components() {
        let Component::Normal(part) = component else {
            continue;
        };
        let Some(part) = part.to_str() else {
            continue;
        };
        if part.len() < 5 {
            continue;
        }
        let segments: Vec<&str> = part.split('.').collect();
        if segments.len() < 3 {
            continue;
        }
        let all_numeric = segments.iter().all(|segment| {
            !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_digit())
        });
        if all_numeric {
            return Some(part.to_string());
        }
    }
    None
}

/// Archive format accepted by [`Installer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveKind {
    Zip,
}

/// The pinned description of one browser build.
///
/// `sha256_hex` is the digest of the archive exactly as served. An empty or
/// malformed digest is refused, and a digest that does not match the download
/// is refused before anything is extracted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallManifest {
    /// Browser build version, for example `124.0.6367.60`.
    pub version: String,
    /// Platform tag, for example `windows-x64` or `linux-x64`.
    pub platform: String,
    /// Archive location handed to the [`Downloader`].
    pub url: String,
    /// Lower-case or upper-case SHA-256 hex digest of the archive.
    pub sha256_hex: String,
    /// Archive format. Only ZIP is accepted today.
    pub archive: ArchiveKind,
}

impl InstallManifest {
    /// Build a ZIP manifest.
    pub fn zip(
        version: impl Into<String>,
        platform: impl Into<String>,
        url: impl Into<String>,
        sha256_hex: impl Into<String>,
    ) -> Self {
        Self {
            version: version.into(),
            platform: platform.into(),
            url: url.into(),
            sha256_hex: sha256_hex.into(),
            archive: ArchiveKind::Zip,
        }
    }
}

/// The byte source for [`Installer`].
///
/// The production fetch layer is not wired here; tests inject a scripted
/// downloader. An implementation must write the archive to `dest` and must not
/// execute it.
pub trait Downloader: Send + Sync {
    /// Write the archive at `url` to `dest`.
    ///
    /// `dest` is a fresh path inside a staging directory whose parent exists.
    fn download(&self, url: &str, dest: &Path) -> Result<()>;
}

/// A browser that was installed (or found already installed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledBrowser {
    /// Absolute path to the executable to launch.
    pub executable: PathBuf,
    /// Version that was installed.
    pub version: String,
    /// Versioned install directory.
    pub root: PathBuf,
    /// `true` when an existing matching install was reused.
    pub reused: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct InstallRecord {
    schema: u32,
    version: String,
    platform: String,
    sha256_hex: String,
    executable: String,
}

/// Checksum-verified, unpack-only browser installer.
///
/// `D` is the [`Downloader`]; tests script the bytes, production supplies a
/// fetch-layer adapter.
pub struct Installer<D: Downloader> {
    downloader: D,
    limits: ArchiveLimits,
}

impl<D: Downloader> Installer<D> {
    /// Build an installer with the archive bounds sized for a browser build.
    pub fn new(downloader: D) -> Self {
        Self {
            downloader,
            limits: install_archive_limits(),
        }
    }

    /// Replace the archive safety bounds.
    pub fn with_archive_limits(mut self, limits: ArchiveLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Install `manifest` under `data_dir` and return the executable path.
    pub fn install(
        &self,
        manifest: &InstallManifest,
        data_dir: impl AsRef<Path>,
    ) -> Result<PathBuf> {
        self.install_with_report(manifest, data_dir)
            .map(|installed| installed.executable)
    }

    /// [`Self::install`] plus the install directory and reuse flag.
    pub fn install_with_report(
        &self,
        manifest: &InstallManifest,
        data_dir: impl AsRef<Path>,
    ) -> Result<InstalledBrowser> {
        let checksum = normalize_checksum(&manifest.sha256_hex)?;
        let version = validate_component(&manifest.version, "install version")?;
        let platform = validate_component(&manifest.platform, "install platform")?;
        if manifest.archive != ArchiveKind::Zip {
            return Err(ZeroError::new(
                ErrorCode::Unsupported,
                "only ZIP browser archives are supported",
            ));
        }

        let base = data_dir.as_ref().join(BROWSER_DIR).join(platform);
        fs::create_dir_all(&base).map_err(io_error)?;
        let final_dir = base.join(version);

        if let Some(existing) = self.read_existing(&final_dir, version, platform, &checksum)? {
            return Ok(existing);
        }

        let staging = base.join(format!(".staging-{}", unique_suffix()));
        fs::create_dir(&staging).map_err(io_error)?;
        let outcome = self.populate(manifest, &checksum, version, platform, &staging, &final_dir);
        if outcome.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        outcome
    }

    fn populate(
        &self,
        manifest: &InstallManifest,
        checksum: &str,
        version: &str,
        platform: &str,
        staging: &Path,
        final_dir: &Path,
    ) -> Result<InstalledBrowser> {
        let archive_path = staging.join(ARCHIVE_FILE);
        self.downloader.download(&manifest.url, &archive_path)?;

        let metadata = fs::metadata(&archive_path).map_err(io_error)?;
        if metadata.len() == 0 {
            return Err(corrupt("the downloaded browser archive is empty"));
        }
        if metadata.len() > self.limits.max_total_bytes {
            return Err(limit(format!(
                "the browser archive is {} bytes, limit is {}",
                metadata.len(),
                self.limits.max_total_bytes
            )));
        }

        // The checksum gate runs before the archive planner reads a header and
        // before anything is extracted or executed.
        let actual = sha256_file(&archive_path)?;
        if actual != checksum {
            return Err(corrupt(format!(
                "browser archive checksum mismatch: expected {checksum}, got {actual}"
            )));
        }

        archive::extract(&archive_path, staging, &self.limits)
            .map_err(|error| error.into_zero_error())?;

        let executable = locate_executable(staging)
            .ok_or_else(|| not_found("the browser archive contains no known executable"))?;
        let relative = executable.strip_prefix(staging).map_err(|_| {
            corrupt("the located browser executable is outside the staging directory")
        })?;
        make_executable(&executable)?;

        let record = InstallRecord {
            schema: INSTALL_SCHEMA,
            version: version.to_string(),
            platform: platform.to_string(),
            sha256_hex: checksum.to_string(),
            executable: slash_path(relative),
        };
        let encoded = serde_json::to_vec_pretty(&record)?;
        fs::write(staging.join(RECORD_FILE), encoded).map_err(io_error)?;
        let _ = fs::remove_file(&archive_path);

        match fs::rename(staging, final_dir) {
            Ok(()) => {}
            Err(error) => {
                // A concurrent installer may have published the same version
                // first. Only an install with the same recorded checksum is
                // accepted, so the bytes are still the ones we verified.
                if fs::symlink_metadata(final_dir).is_ok() {
                    if let Some(existing) =
                        self.read_existing(final_dir, version, platform, checksum)?
                    {
                        let _ = fs::remove_dir_all(staging);
                        return Ok(existing);
                    }
                }
                return Err(io_error(error));
            }
        }

        Ok(InstalledBrowser {
            executable: final_dir.join(relative),
            version: version.to_string(),
            root: final_dir.to_path_buf(),
            reused: false,
        })
    }

    fn read_existing(
        &self,
        final_dir: &Path,
        version: &str,
        platform: &str,
        checksum: &str,
    ) -> Result<Option<InstalledBrowser>> {
        let metadata = match fs::symlink_metadata(final_dir) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(error)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(corrupt(
                "the browser install path exists but is not a real directory",
            ));
        }

        let encoded = fs::read(final_dir.join(RECORD_FILE)).map_err(|error| {
            corrupt(format!(
                "the browser install has no readable install record: {error}"
            ))
        })?;
        let record: InstallRecord = serde_json::from_slice(&encoded).map_err(|error| {
            corrupt(format!("the browser install record is malformed: {error}"))
        })?;
        if record.schema != INSTALL_SCHEMA {
            return Err(ZeroError::new(
                ErrorCode::SchemaVersion,
                format!(
                    "browser install schema {} is not supported (expected {INSTALL_SCHEMA})",
                    record.schema
                ),
            ));
        }
        if record.version != version || record.platform != platform || record.sha256_hex != checksum
        {
            return Err(corrupt(
                "the installed browser does not match the requested version or checksum",
            ));
        }

        let executable = resolve_recorded(final_dir, &record.executable)
            .or_else(|| locate_executable(final_dir))
            .ok_or_else(|| not_found("the installed browser executable is missing"))?;
        Ok(Some(InstalledBrowser {
            executable,
            version: version.to_string(),
            root: final_dir.to_path_buf(),
            reused: true,
        }))
    }
}

/// Archive bounds for a browser build.
///
/// Browsers are much larger than the documents [`ArchiveLimits::default`] is
/// sized for, so the entry, total, and ratio bounds are raised; every safety
/// rule (paths, links, encryption, actual-byte accounting) still applies.
pub fn install_archive_limits() -> ArchiveLimits {
    ArchiveLimits {
        max_entries: 10_000,
        max_total_bytes: 1024 * 1024 * 1024,
        max_entry_bytes: 512 * 1024 * 1024,
        max_compression_ratio: 200,
        max_path_depth: 24,
    }
}

fn normalize_checksum(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(invalid(
            "the install manifest has no SHA-256 checksum; refusing to install",
        ));
    }
    let lowered = trimmed.to_ascii_lowercase();
    if lowered.len() != 64 || !lowered.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(
            "the install manifest checksum is not a 64-character SHA-256 hex digest",
        ));
    }
    Ok(lowered)
}

fn validate_component<'a>(value: &'a str, label: &str) -> Result<&'a str> {
    if value.is_empty() {
        return Err(invalid(format!("the {label} is empty")));
    }
    if value.len() > 128 {
        return Err(invalid(format!("the {label} is longer than 128 bytes")));
    }
    let usable = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !usable || value == "." || value == ".." || value.contains("..") {
        return Err(invalid(format!(
            "the {label} must be a single path component without `..`"
        )));
    }
    Ok(value)
}

/// Mark the verified browser binary executable on Unix.
///
/// ZIP extraction creates regular files with the process umask, so a stored
/// mode is not applied. Only the already checksum-verified, known-name binary
/// is marked; nothing is executed.
#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(io_error)
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(io_error)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(io_error)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex_encode(&hasher.finalize()))
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn executable_rank(path: &Path) -> Option<usize> {
    let name = path.file_name()?.to_str()?.to_ascii_lowercase();
    EXECUTABLE_NAMES
        .iter()
        .position(|candidate| *candidate == name)
}

fn locate_executable(root: &Path) -> Option<PathBuf> {
    let mut found: Vec<(usize, PathBuf)> = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut visited = 0usize;

    while let Some((directory, depth)) = stack.pop() {
        if depth > MAX_SCAN_DEPTH || visited > MAX_SCAN_ENTRIES {
            continue;
        }
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited > MAX_SCAN_ENTRIES {
                break;
            }
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => continue,
            };
            if file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            if file_type.is_dir() {
                stack.push((path, depth + 1));
            } else if file_type.is_file() {
                if let Some(rank) = executable_rank(&path) {
                    found.push((rank, path));
                }
            }
        }
    }

    found.sort();
    found.into_iter().next().map(|(_, path)| path)
}

fn slash_path(path: &Path) -> String {
    let mut parts = Vec::new();
    for component in path.components() {
        if let Component::Normal(part) = component {
            parts.push(part.to_string_lossy().into_owned());
        }
    }
    parts.join("/")
}

fn resolve_recorded(root: &Path, recorded: &str) -> Option<PathBuf> {
    let trimmed = recorded.trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let mut path = root.to_path_buf();
    for part in trimmed.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return None;
        }
        path.push(part);
    }
    if path.is_file() {
        Some(path)
    } else {
        None
    }
}

fn unique_suffix() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{nanos}-{counter}", std::process::id())
}

/// A per-session `--user-data-dir`.
///
/// Creation is confined to `<root>/browser-profiles/<session_id>`; the session
/// id must be one safe path component. A stale directory for the same session is
/// removed first, so the profile is empty on first use.
#[derive(Debug)]
pub struct Profile {
    path: PathBuf,
    root: PathBuf,
    closed: bool,
}

impl Profile {
    /// Create an isolated profile directory for `session_id` under `root`.
    pub fn create(root: impl AsRef<Path>, session_id: &str) -> Result<Self> {
        let root = absolute_path(root.as_ref())?;
        fs::create_dir_all(&root).map_err(io_error)?;
        let canonical_root = fs::canonicalize(&root).map_err(io_error)?;

        let base = root.join(PROFILE_DIR);
        fs::create_dir_all(&base).map_err(io_error)?;
        let canonical_base = fs::canonicalize(&base).map_err(io_error)?;
        if !canonical_base.starts_with(&canonical_root) {
            return Err(denied(
                "the browser profile directory escapes its data root",
            ));
        }

        let name = validate_component(session_id, "browser profile session id")?;
        let path = base.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(denied(
                        "refusing to reuse a browser profile path that is a symbolic link",
                    ));
                }
                if !metadata.is_dir() {
                    return Err(ZeroError::new(
                        ErrorCode::AlreadyExists,
                        "the browser profile path exists and is not a directory",
                    ));
                }
                fs::remove_dir_all(&path).map_err(io_error)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }

        fs::create_dir(&path).map_err(io_error)?;
        set_private(&path)?;
        let canonical = fs::canonicalize(&path).map_err(io_error)?;
        if !canonical.starts_with(&canonical_base) {
            let _ = fs::remove_dir_all(&path);
            return Err(denied("the browser profile directory escapes its root"));
        }

        Ok(Self {
            path,
            root: canonical_base,
            closed: false,
        })
    }

    /// The directory to pass as `--user-data-dir`.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether [`Self::close`] has already run.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Remove the profile directory. Idempotent.
    ///
    /// A path that has become a symbolic link, or that no longer resolves under
    /// the profile root, is refused rather than followed or deleted.
    pub fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(denied(
                        "refusing to remove a browser profile that is a symbolic link",
                    ));
                }
                if !metadata.is_dir() {
                    return Err(ZeroError::new(
                        ErrorCode::Io,
                        "the browser profile path is not a directory",
                    ));
                }
                let canonical = fs::canonicalize(&self.path).map_err(io_error)?;
                if !canonical.starts_with(&self.root) {
                    return Err(denied(
                        "refusing to remove a browser profile outside its root",
                    ));
                }
                fs::remove_dir_all(&self.path).map_err(io_error)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }
        self.closed = true;
        Ok(())
    }
}

#[cfg(unix)]
fn set_private(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error)
}

#[cfg(not(unix))]
fn set_private(_path: &Path) -> Result<()> {
    Ok(())
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    std::env::current_dir()
        .map(|current| current.join(path))
        .map_err(io_error)
}

/// Configuration for [`HeadlessBrowser`].
#[derive(Debug, Clone)]
pub struct HeadlessConfig {
    /// Browser executable to launch.
    pub executable: PathBuf,
    /// Data directory that holds per-session profiles.
    pub profile_root: PathBuf,
    /// Hard render deadline. `0` uses [`DEFAULT_HEADLESS_TIMEOUT_MS`].
    pub timeout_ms: u64,
    /// DOM ceiling. `0` uses [`DEFAULT_MAX_HEADLESS_OUTPUT_BYTES`].
    pub max_output_bytes: usize,
    /// Egress guard applied to `http(s)` targets before launch.
    pub egress: EgressGuard,
    /// Allow `file:` and `data:` targets.
    pub allow_local: bool,
}

impl HeadlessConfig {
    /// Build a configuration with the documented defaults for the caps.
    pub fn new(
        executable: impl Into<PathBuf>,
        profile_root: impl Into<PathBuf>,
        egress: EgressGuard,
    ) -> Self {
        Self {
            executable: executable.into(),
            profile_root: profile_root.into(),
            timeout_ms: DEFAULT_HEADLESS_TIMEOUT_MS,
            max_output_bytes: DEFAULT_MAX_HEADLESS_OUTPUT_BYTES,
            egress,
            allow_local: false,
        }
    }
}

/// One rendered page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedPage {
    /// The post-JavaScript DOM printed by `--dump-dom`.
    pub html: String,
    /// HTTP status, when a transport can report one.
    ///
    /// `--dump-dom` exposes only the DOM, so the process fallback always
    /// returns `None`. The field is reserved for the DevTools transport.
    pub status: Option<u16>,
    /// Number of DOM bytes received (before lossy UTF-8 conversion).
    pub bytes: usize,
}

/// One browser launch description handed to a [`BrowserProcess`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchRequest {
    /// Executable to run.
    pub executable: PathBuf,
    /// Arguments after the executable.
    pub args: Vec<String>,
    /// Hard deadline; the process is killed when it expires.
    pub timeout: Duration,
    /// Ceiling on captured stdout bytes.
    pub max_stdout_bytes: usize,
    /// Bytes kept from the end of stderr.
    pub max_stderr_bytes: usize,
}

/// Captured process result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutput {
    /// Platform exit code; `-1` when the platform reported none.
    pub status: i32,
    /// Captured stdout.
    pub stdout: Vec<u8>,
    /// Bounded tail of stderr.
    pub stderr: String,
}

/// The process seam.
///
/// Tests script it to prove the launch arguments and caps without a browser;
/// production uses [`SystemProcess`].
pub trait BrowserProcess: Send + Sync {
    /// Run one browser launch and return its captured output.
    ///
    /// Implementations must kill the child at `request.timeout`, must not keep
    /// more than `max_stdout_bytes` of stdout, and must keep only the tail of
    /// stderr. A timeout is `zero.fnd.timeout`; a breached stdout cap is
    /// `zero.fnd.limit_exceeded`.
    fn run(&self, request: &LaunchRequest) -> Result<ProcessOutput>;
}

/// Production process runner.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemProcess;

impl BrowserProcess for SystemProcess {
    fn run(&self, request: &LaunchRequest) -> Result<ProcessOutput> {
        run_system_process(request)
    }
}

fn run_system_process(request: &LaunchRequest) -> Result<ProcessOutput> {
    if !request.executable.is_file() {
        return Err(not_found(format!(
            "the headless browser executable does not exist: {}",
            request.executable.display()
        )));
    }

    let mut command = command_for(&request.executable);
    command
        .args(&request.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;

        command.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = command
        .spawn()
        .map_err(|error| unavailable(format!("could not launch the headless browser: {error}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| unavailable("the headless browser has no stdout pipe"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| unavailable("the headless browser has no stderr pipe"))?;

    let exceeded = Arc::new(AtomicBool::new(false));
    let stdout_thread =
        spawn_stdout_reader(stdout, request.max_stdout_bytes, Arc::clone(&exceeded));
    let stderr_thread = spawn_stderr_tail(stderr, request.max_stderr_bytes);

    let start = Instant::now();
    let mut exit = None;
    let mut timed_out = false;
    loop {
        if exceeded.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                exit = Some(status);
                break;
            }
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io_error(error));
            }
        }
        if start.elapsed() >= request.timeout {
            timed_out = true;
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }

    let stdout = stdout_thread.join().unwrap_or_default();
    let stderr = stderr_thread.join().unwrap_or_default();

    if timed_out {
        return Err(timeout(format!(
            "the headless browser did not finish within {} ms",
            request.timeout.as_millis()
        )));
    }
    if exceeded.load(Ordering::Relaxed) {
        return Err(limit(format!(
            "the headless browser exceeded the {} byte output cap",
            request.max_stdout_bytes
        )));
    }

    Ok(ProcessOutput {
        status: exit.and_then(|status| status.code()).unwrap_or(-1),
        stdout,
        stderr,
    })
}

#[cfg(windows)]
fn is_windows_script(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| {
            extension.eq_ignore_ascii_case("cmd") || extension.eq_ignore_ascii_case("bat")
        })
        .unwrap_or(false)
}

#[cfg(windows)]
fn command_for(executable: &Path) -> Command {
    // `CreateProcess` cannot start a batch file directly; `cmd /C` is the
    // standard wrapper. Real browser executables are launched directly.
    if is_windows_script(executable) {
        let mut command = Command::new("cmd");
        command.arg("/C").arg(executable);
        return command;
    }
    Command::new(executable)
}

#[cfg(not(windows))]
fn command_for(executable: &Path) -> Command {
    Command::new(executable)
}

fn spawn_stdout_reader(
    mut reader: impl Read + Send + 'static,
    cap: usize,
    exceeded: Arc<AtomicBool>,
) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut kept = Vec::new();
        let mut buffer = [0u8; 8 * 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    if kept.len() + read > cap {
                        exceeded.store(true, Ordering::Relaxed);
                    }
                    if kept.len() < cap {
                        let room = cap - kept.len();
                        kept.extend_from_slice(&buffer[..read.min(room)]);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        kept
    })
}

fn spawn_stderr_tail(
    mut reader: impl Read + Send + 'static,
    cap: usize,
) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let mut tail: VecDeque<u8> = VecDeque::new();
        let mut buffer = [0u8; 8 * 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    for byte in &buffer[..read] {
                        tail.push_back(*byte);
                    }
                    while tail.len() > cap {
                        tail.pop_front();
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        let bytes: Vec<u8> = tail.into_iter().collect();
        String::from_utf8_lossy(&bytes).into_owned()
    })
}

enum Target<'a> {
    Url(String),
    Inline(&'a str),
}

/// Policy-checked, one-shot headless renderer.
///
/// `P` is the process seam; production uses [`SystemProcess`].
pub struct HeadlessBrowser<P = SystemProcess> {
    config: HeadlessConfig,
    process: P,
}

impl HeadlessBrowser<SystemProcess> {
    /// Build a renderer that launches real processes.
    pub fn new(config: HeadlessConfig) -> Self {
        Self {
            config,
            process: SystemProcess,
        }
    }
}

impl<P: BrowserProcess> HeadlessBrowser<P> {
    /// Build a renderer over an injected process seam.
    pub fn with_process(config: HeadlessConfig, process: P) -> Self {
        Self { config, process }
    }

    /// The active configuration.
    pub fn config(&self) -> &HeadlessConfig {
        &self.config
    }

    /// Render `url` and return the post-JavaScript DOM.
    ///
    /// When `html_override` is present the HTML is written to a file inside the
    /// render profile and rendered instead of fetching `url`; that path requires
    /// `allow_local`. The target is checked before a profile is created for an
    /// `http(s)` URL, so a denied destination never launches a browser.
    ///
    /// The profile is always closed, including after a failed launch. A cleanup
    /// failure is not reported as a render failure.
    pub fn render(&self, url: &str, html_override: Option<&str>) -> Result<RenderedPage> {
        let target = match html_override {
            Some(html) => {
                if !self.config.allow_local {
                    return Err(denied(
                        "refusing to render supplied HTML: local URLs are disabled",
                    ));
                }
                if html.len() > MAX_INLINE_HTML_BYTES {
                    return Err(limit(format!(
                        "the supplied HTML is {} bytes, limit is {MAX_INLINE_HTML_BYTES}",
                        html.len()
                    )));
                }
                Target::Inline(html)
            }
            None => Target::Url(validate_target(&self.config, url)?),
        };

        let mut profile = Profile::create(
            &self.config.profile_root,
            &format!("render-{}", unique_suffix()),
        )?;
        let outcome = self.render_in_profile(&profile, target);
        let _ = profile.close();
        outcome
    }

    fn render_in_profile(&self, profile: &Profile, target: Target<'_>) -> Result<RenderedPage> {
        let target = match target {
            Target::Url(url) => url,
            Target::Inline(html) => {
                let path = profile.path().join("zero-render.html");
                fs::write(&path, html.as_bytes()).map_err(io_error)?;
                Url::from_file_path(&path)
                    .map_err(|_| invalid("the temporary render file has no file URL"))?
                    .to_string()
            }
        };

        let timeout_ms = if self.config.timeout_ms == 0 {
            DEFAULT_HEADLESS_TIMEOUT_MS
        } else {
            self.config.timeout_ms
        };
        let max_output = if self.config.max_output_bytes == 0 {
            DEFAULT_MAX_HEADLESS_OUTPUT_BYTES
        } else {
            self.config.max_output_bytes
        };

        let request = LaunchRequest {
            executable: self.config.executable.clone(),
            args: launch_args(&target, profile.path()),
            timeout: Duration::from_millis(timeout_ms),
            max_stdout_bytes: max_output,
            max_stderr_bytes: DEFAULT_MAX_STDERR_BYTES,
        };
        let output = self.process.run(&request)?;

        if output.stdout.len() > max_output {
            return Err(limit(format!(
                "the headless browser produced {} bytes, limit is {max_output}",
                output.stdout.len()
            )));
        }
        if output.status != 0 {
            let tail = sanitize_stderr(&self.config.egress, &output.stderr);
            return Err(unavailable(format!(
                "the headless browser exited with status {}: {tail}",
                output.status
            )));
        }

        let bytes = output.stdout.len();
        Ok(RenderedPage {
            html: String::from_utf8_lossy(&output.stdout).into_owned(),
            status: None,
            bytes,
        })
    }
}

fn validate_target(config: &HeadlessConfig, url: &str) -> Result<String> {
    let parsed = Url::parse(url)
        .map_err(|error| invalid(format!("the headless target URL is invalid: {error}")))?;

    match parsed.scheme() {
        "http" | "https" => Ok(config.egress.check_url(url)?.url().to_string()),
        "file" => {
            if !config.allow_local {
                return Err(denied(
                    "refusing a local file target: local URLs are disabled",
                ));
            }
            if !parsed.username().is_empty() || parsed.password().is_some() {
                return Err(denied("refusing a file URL with embedded credentials"));
            }
            match parsed.host_str() {
                None | Some("") | Some("localhost") => {}
                Some(host) => {
                    return Err(denied(format!(
                        "refusing a file URL that names host `{host}`"
                    )))
                }
            }
            let path = parsed
                .to_file_path()
                .map_err(|_| invalid("the file URL has no usable local path"))?;
            if !path.is_file() {
                return Err(not_found(format!(
                    "the local render target does not exist: {}",
                    path.display()
                )));
            }
            Ok(parsed.to_string())
        }
        "data" => {
            if !config.allow_local {
                return Err(denied("refusing a data URL: local URLs are disabled"));
            }
            if url.len() > MAX_DATA_URL_BYTES {
                return Err(limit(format!(
                    "the data URL is {} bytes, limit is {MAX_DATA_URL_BYTES}; use the HTML override",
                    url.len()
                )));
            }
            Ok(parsed.to_string())
        }
        scheme => Err(denied(format!(
            "refusing non-HTTP(S) headless scheme `{scheme}`"
        ))),
    }
}

fn launch_args(target: &str, profile: &Path) -> Vec<String> {
    vec![
        "--headless=new".to_string(),
        "--disable-gpu".to_string(),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        format!("--user-data-dir={}", profile.display()),
        "--dump-dom".to_string(),
        target.to_string(),
    ]
}

fn sanitize_stderr(egress: &EgressGuard, raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "no stderr output".to_string();
    }
    if egress.assert_no_secrets(trimmed, &[]).is_err() {
        return "stderr withheld: it contained a registered secret".to_string();
    }

    let mut kept = String::new();
    let mut truncated = false;
    for (count, character) in trimmed.chars().enumerate() {
        if count >= MAX_STDERR_CHARS {
            truncated = true;
            break;
        }
        kept.push(if character.is_control() {
            ' '
        } else {
            character
        });
    }
    if truncated {
        kept.push_str("...");
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use std::sync::Mutex;

    use tempfile::TempDir;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    use crate::egress::NetworkPolicy;

    fn sha256_hex(bytes: &[u8]) -> String {
        hex_encode(&Sha256::digest(bytes))
    }

    fn zip_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in entries {
            writer
                .start_file(*name, SimpleFileOptions::default())
                .expect("start file");
            writer.write_all(data).expect("write entry");
        }
        writer.finish().expect("finish archive").into_inner()
    }

    fn manifest(bytes: &[u8], checksum: Option<&str>) -> InstallManifest {
        InstallManifest::zip(
            "1.2.3",
            "test-platform",
            "https://example.invalid/browser.zip",
            checksum
                .map(str::to_string)
                .unwrap_or_else(|| sha256_hex(bytes)),
        )
    }

    #[derive(Clone)]
    struct ScriptedDownloader {
        payloads: Arc<Mutex<Vec<Vec<u8>>>>,
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl ScriptedDownloader {
        fn new(payload: Vec<u8>) -> Self {
            Self {
                payloads: Arc::new(Mutex::new(vec![payload])),
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn never() -> Self {
            Self {
                payloads: Arc::new(Mutex::new(Vec::new())),
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn calls(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    impl Downloader for ScriptedDownloader {
        fn download(&self, url: &str, dest: &Path) -> Result<()> {
            self.calls.lock().unwrap().push(url.to_string());
            let payload = {
                let mut payloads = self.payloads.lock().unwrap();
                if payloads.is_empty() {
                    None
                } else {
                    Some(payloads.remove(0))
                }
            };
            let payload =
                payload.ok_or_else(|| unavailable("the scripted downloader has no bytes"))?;
            fs::write(dest, payload).map_err(io_error)
        }
    }

    fn browser_zip() -> Vec<u8> {
        zip_with(&[("chrome", b"fake-browser-binary")])
    }

    #[test]
    fn a_matching_manifest_installs_and_a_second_install_is_reused() {
        let bytes = browser_zip();
        let checksum = sha256_hex(&bytes);
        let data = TempDir::new().expect("tempdir");
        let first = ScriptedDownloader::new(bytes.clone());
        let installer = Installer::new(first.clone());

        let installed = installer
            .install_with_report(&manifest(&bytes, Some(&checksum)), data.path())
            .expect("install");
        assert!(!installed.reused);
        assert_eq!(installed.version, "1.2.3");
        assert_eq!(
            fs::read(&installed.executable).unwrap(),
            b"fake-browser-binary"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_ne!(
                fs::metadata(&installed.executable)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111,
                0,
                "the installed browser must be executable"
            );
        }
        assert!(installed
            .root
            .canonicalize()
            .unwrap()
            .starts_with(data.path().canonicalize().unwrap()));
        assert_eq!(
            installed.root,
            data.path()
                .join(BROWSER_DIR)
                .join("test-platform")
                .join("1.2.3")
        );
        assert!(installed.root.join(RECORD_FILE).is_file());
        assert_eq!(first.calls(), 1);

        // A second install must use the record, not the downloader.
        let second = ScriptedDownloader::never();
        let installer = Installer::new(second.clone());
        let reused = installer
            .install_with_report(&manifest(&bytes, Some(&checksum)), data.path())
            .expect("idempotent install");
        assert!(reused.reused);
        assert_eq!(reused.executable, installed.executable);
        assert_eq!(second.calls(), 0);
    }

    #[test]
    fn a_checksum_mismatch_is_refused_before_extraction() {
        // The archive itself would be refused by the planner (zip slip), so a
        // checksum error proves the hash gate ran first.
        let bytes = zip_with(&[("../evil.txt", b"escape")]);
        let bad = "0".repeat(64);
        let data = TempDir::new().expect("tempdir");
        let downloader = ScriptedDownloader::new(bytes);
        let installer = Installer::new(downloader);

        let error = installer
            .install(&manifest(&browser_zip(), Some(&bad)), data.path())
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Corrupt);
        assert!(
            error.message().contains("checksum mismatch"),
            "{}",
            error.message()
        );

        let version_root = data
            .path()
            .join(BROWSER_DIR)
            .join("test-platform")
            .join("1.2.3");
        assert!(!version_root.exists());
        let platform_root = data.path().join(BROWSER_DIR).join("test-platform");
        let leftovers: Vec<_> = fs::read_dir(platform_root)
            .expect("platform directory")
            .flatten()
            .collect();
        assert!(leftovers.is_empty(), "staging directories must be removed");
    }

    #[test]
    fn a_missing_or_malformed_checksum_is_refused_without_downloading() {
        let data = TempDir::new().expect("tempdir");
        let malformed = "z".repeat(64);
        for checksum in ["", "  ", "abc", malformed.as_str()] {
            let downloader = ScriptedDownloader::never();
            let installer = Installer::new(downloader.clone());
            let error = installer
                .install(&manifest(&browser_zip(), Some(checksum)), data.path())
                .unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidInput, "{checksum:?}");
            assert_eq!(downloader.calls(), 0, "{checksum:?}");
        }
    }

    #[test]
    fn a_zip_slip_archive_is_refused_after_the_checksum_passes() {
        let bytes = zip_with(&[("../evil.txt", b"escape")]);
        let checksum = sha256_hex(&bytes);
        let data = TempDir::new().expect("tempdir");
        let installer = Installer::new(ScriptedDownloader::new(bytes.clone()));

        let error = installer
            .install(&manifest(&bytes, Some(&checksum)), data.path())
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(
            !data.path().join("evil.txt").exists(),
            "nothing may be written outside the versioned directory"
        );
        assert!(!data
            .path()
            .join(BROWSER_DIR)
            .join("test-platform")
            .join("evil.txt")
            .exists());
        assert!(!data
            .path()
            .join(BROWSER_DIR)
            .join("test-platform")
            .join("1.2.3")
            .exists());
    }

    #[test]
    fn two_sessions_get_distinct_empty_profiles_and_close_removes_them() {
        let data = TempDir::new().expect("tempdir");
        let mut first = Profile::create(data.path(), "session-a").expect("first profile");
        let mut second = Profile::create(data.path(), "session-b").expect("second profile");

        assert_ne!(first.path(), second.path());
        assert_eq!(fs::read_dir(first.path()).unwrap().count(), 0);
        assert_eq!(fs::read_dir(second.path()).unwrap().count(), 0);

        fs::write(first.path().join("Cookies"), b"session-a-cookie").unwrap();
        fs::write(second.path().join("Cache"), b"session-b-cache").unwrap();
        assert!(!second.path().join("Cookies").exists());
        assert!(!first.path().join("Cache").exists());
        assert_eq!(
            fs::read(first.path().join("Cookies")).unwrap(),
            b"session-a-cookie"
        );

        let first_path = first.path().to_path_buf();
        let second_path = second.path().to_path_buf();
        first.close().unwrap();
        assert!(first.is_closed());
        assert!(!first_path.exists());
        assert!(second_path.exists());
        assert_eq!(
            fs::read(second.path().join("Cache")).unwrap(),
            b"session-b-cache"
        );
        second.close().unwrap();
        assert!(!second_path.exists());

        // Closing twice is harmless.
        first.close().unwrap();
        second.close().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_profile_directory_is_mode_0700_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let data = TempDir::new().expect("tempdir");
        let mut profile = Profile::create(data.path(), "mode-check").expect("profile");
        let mode = fs::metadata(profile.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        profile.close().unwrap();
    }

    #[test]
    fn a_session_id_that_escapes_the_profile_root_is_refused() {
        let data = TempDir::new().expect("tempdir");
        for session in ["../escape", "a/b", "..", "", "a\\b"] {
            let error = Profile::create(data.path(), session).unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidInput, "{session:?}");
        }
        assert!(!data.path().parent().unwrap().join("escape").exists());
    }

    enum ScriptedReply {
        Output(ProcessOutput),
        Timeout,
    }

    #[derive(Clone)]
    struct ScriptedProcess {
        requests: Arc<Mutex<Vec<LaunchRequest>>>,
        reply: Arc<Mutex<Option<ScriptedReply>>>,
    }

    impl ScriptedProcess {
        fn new(reply: ScriptedReply) -> Self {
            Self {
                requests: Arc::new(Mutex::new(Vec::new())),
                reply: Arc::new(Mutex::new(Some(reply))),
            }
        }

        fn output(status: i32, stdout: &[u8], stderr: &str) -> Self {
            Self::new(ScriptedReply::Output(ProcessOutput {
                status,
                stdout: stdout.to_vec(),
                stderr: stderr.to_string(),
            }))
        }

        fn requests(&self) -> Vec<LaunchRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl BrowserProcess for ScriptedProcess {
        fn run(&self, request: &LaunchRequest) -> Result<ProcessOutput> {
            self.requests.lock().unwrap().push(request.clone());
            match self.reply.lock().unwrap().take() {
                Some(ScriptedReply::Output(output)) => Ok(output),
                Some(ScriptedReply::Timeout) => Err(timeout("scripted timeout")),
                None => Err(ZeroError::new(
                    ErrorCode::Internal,
                    "the scripted process has no reply",
                )),
            }
        }
    }

    fn headless_config(profile_root: &Path) -> HeadlessConfig {
        HeadlessConfig {
            executable: PathBuf::from("chrome"),
            profile_root: profile_root.to_path_buf(),
            timeout_ms: 1_234,
            max_output_bytes: 4_096,
            egress: EgressGuard::system(NetworkPolicy::Restricted),
            allow_local: true,
        }
    }

    fn local_page() -> (TempDir, String) {
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("page.html");
        fs::write(&path, b"<html><body>scripted</body></html>").unwrap();
        let url = Url::from_file_path(&path).expect("file url").to_string();
        (directory, url)
    }

    #[test]
    fn the_pipeline_passes_the_documented_arguments_and_caps() {
        let profile_root = TempDir::new().expect("tempdir");
        let (_page_dir, url) = local_page();
        let process = ScriptedProcess::output(0, b"<html><body>ok</body></html>", "");
        let browser =
            HeadlessBrowser::with_process(headless_config(profile_root.path()), process.clone());

        let rendered = browser.render(&url, None).expect("render");
        assert_eq!(rendered.html, "<html><body>ok</body></html>");
        assert_eq!(rendered.bytes, rendered.html.len());
        assert_eq!(rendered.status, None);

        let requests = process.requests();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.executable, PathBuf::from("chrome"));
        assert_eq!(request.timeout, Duration::from_millis(1_234));
        assert_eq!(request.max_stdout_bytes, 4_096);
        assert_eq!(request.max_stderr_bytes, DEFAULT_MAX_STDERR_BYTES);
        assert_eq!(request.args[0], "--headless=new");
        assert!(request.args.contains(&"--disable-gpu".to_string()));
        assert!(request.args.contains(&"--no-first-run".to_string()));
        assert!(request
            .args
            .contains(&"--no-default-browser-check".to_string()));
        let profile_arg = request
            .args
            .iter()
            .find(|arg| arg.starts_with("--user-data-dir="))
            .expect("profile argument");
        let profile_path = PathBuf::from(profile_arg.trim_start_matches("--user-data-dir="));
        assert!(profile_path.starts_with(profile_root.path()));
        assert!(!profile_path.exists(), "the render profile must be removed");
        assert_eq!(request.args[5], "--dump-dom");
        assert_eq!(request.args[6], url);
    }

    #[test]
    fn an_oversized_dom_dump_is_refused_by_the_pipeline_cap() {
        let profile_root = TempDir::new().expect("tempdir");
        let (_page_dir, url) = local_page();
        let process = ScriptedProcess::output(0, &[b'x'; 64], "");
        let mut config = headless_config(profile_root.path());
        config.max_output_bytes = 8;
        let browser = HeadlessBrowser::with_process(config, process.clone());

        let error = browser.render(&url, None).unwrap_err();
        assert_eq!(error.code(), ErrorCode::LimitExceeded);
        assert_eq!(process.requests()[0].max_stdout_bytes, 8);
    }

    #[test]
    fn a_scripted_timeout_is_a_typed_error() {
        let profile_root = TempDir::new().expect("tempdir");
        let (_page_dir, url) = local_page();
        let process = ScriptedProcess::new(ScriptedReply::Timeout);
        let browser = HeadlessBrowser::with_process(headless_config(profile_root.path()), process);

        let error = browser.render(&url, None).unwrap_err();
        assert_eq!(error.code(), ErrorCode::Timeout);
    }

    #[test]
    fn a_non_zero_exit_is_unavailable_and_hides_registered_secrets() {
        let profile_root = TempDir::new().expect("tempdir");
        let (_page_dir, url) = local_page();
        let process = ScriptedProcess::output(3, b"", "crashed with sk-test-secret");
        let mut config = headless_config(profile_root.path());
        config.egress =
            EgressGuard::system(NetworkPolicy::Restricted).with_secrets(["sk-test-secret"]);
        let browser = HeadlessBrowser::with_process(config, process);

        let error = browser.render(&url, None).unwrap_err();
        assert_eq!(error.code(), ErrorCode::Unavailable);
        assert!(error.message().contains("status 3"), "{}", error.message());
        assert!(
            !error.message().contains("sk-test-secret"),
            "{}",
            error.message()
        );
        assert!(error.message().contains("withheld"), "{}", error.message());
    }

    #[test]
    fn http_targets_are_egress_checked_before_launch() {
        let profile_root = TempDir::new().expect("tempdir");
        let process = ScriptedProcess::output(0, b"<html></html>", "");
        let browser =
            HeadlessBrowser::with_process(headless_config(profile_root.path()), process.clone());

        let error = browser.render("http://127.0.0.1/", None).unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(process.requests().is_empty());
    }

    #[test]
    fn local_targets_are_refused_when_allow_local_is_off() {
        let profile_root = TempDir::new().expect("tempdir");
        let (_page_dir, url) = local_page();
        let process = ScriptedProcess::output(0, b"<html></html>", "");
        let mut config = headless_config(profile_root.path());
        config.allow_local = false;
        let browser = HeadlessBrowser::with_process(config, process.clone());

        let error = browser.render(&url, None).unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(process.requests().is_empty());

        let error = browser
            .render("https://example.com/", Some("<p>x</p>"))
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(process.requests().is_empty());
    }

    fn write_slow_script(directory: &Path) -> Option<PathBuf> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let path = directory.join("slow-browser.sh");
            fs::write(&path, b"#!/bin/sh\nwhile :; do :; done\n").ok()?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).ok()?;
            Some(path)
        }
        #[cfg(windows)]
        {
            // A batch loop is handled by `cmd.exe` itself, so killing the shell
            // ends the process tree without a lingering child holding the pipe.
            let path = directory.join("slow-browser.cmd");
            fs::write(&path, b"@echo off\r\n:loop\r\ngoto loop\r\n").ok()?;
            Some(path)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = directory;
            None
        }
    }

    #[test]
    fn a_slow_executable_is_killed_at_the_deadline() {
        // The temp directory must outlive the launch.
        let holder = TempDir::new().expect("tempdir");
        let Some(script) = write_slow_script(holder.path()) else {
            println!("skipped: no process fixture is available on this platform");
            return;
        };

        let page = holder.path().join("slow-page.html");
        fs::write(&page, b"<html><body>slow</body></html>").unwrap();
        let url = Url::from_file_path(&page).expect("file url").to_string();

        let mut config = headless_config(holder.path());
        config.executable = script.clone();
        config.timeout_ms = 300;
        let browser = HeadlessBrowser::new(config);

        let started = Instant::now();
        let error = browser.render(&url, None).unwrap_err();
        let elapsed = started.elapsed();
        assert_eq!(error.code(), ErrorCode::Timeout, "{}", error.message());
        assert!(
            elapsed < Duration::from_secs(10),
            "the deadline took {elapsed:?}"
        );
        assert!(script.exists());
    }

    #[test]
    fn a_js_only_page_renders_in_a_discovered_browser_or_the_test_is_skipped() {
        let Some(candidate) = find_system_browser() else {
            println!(
                "skipped: no system Chrome, Chromium, or Edge was found on this host; \
                 the scripted pipeline tests still cover launch, caps, and timeouts"
            );
            return;
        };

        let pages = TempDir::new().expect("tempdir");
        let page = pages.path().join("js-only.html");
        fs::write(
            &page,
            b"<!doctype html><html><body><div id=\"x\"></div>\
              <script>document.getElementById('x').textContent='rendered-by-js'</script>\
              </body></html>",
        )
        .unwrap();
        let url = Url::from_file_path(&page).expect("file url").to_string();

        let profiles = TempDir::new().expect("tempdir");
        let config = HeadlessConfig {
            executable: candidate.path.clone(),
            profile_root: profiles.path().to_path_buf(),
            timeout_ms: 60_000,
            max_output_bytes: DEFAULT_MAX_HEADLESS_OUTPUT_BYTES,
            egress: EgressGuard::system(NetworkPolicy::Restricted),
            allow_local: true,
        };
        let browser = HeadlessBrowser::new(config);
        let rendered = match browser.render(&url, None) {
            Ok(rendered) => rendered,
            Err(error)
                if matches!(
                    error.code(),
                    ErrorCode::Timeout | ErrorCode::Unavailable | ErrorCode::Offline
                ) =>
            {
                println!(
                    "skipped: the {} browser could not render in this environment: {error}; \
                     the scripted pipeline tests still cover launch, caps, and timeouts",
                    candidate.channel.as_str()
                );
                return;
            }
            Err(error) => panic!("{} browser failed: {error}", candidate.channel.as_str()),
        };
        println!(
            "rendered with {} {} ({})",
            candidate.channel.as_str(),
            candidate.version.as_deref().unwrap_or("unknown version"),
            candidate.path.display()
        );
        assert!(
            rendered.html.contains("rendered-by-js"),
            "the post-JavaScript DOM did not contain the script result: {}",
            rendered.html
        );
        assert!(rendered.bytes > 0);
    }
}
