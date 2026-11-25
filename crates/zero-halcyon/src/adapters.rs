//! Runtime adapter detection and version negotiation (HAL-04, HAL-07, HAL-13).
//!
//! Halcyon drives three external tools: `tkb` (the task backend), `joker` (the
//! gate runner), and `epb` (the endpoint bridge). This module answers two
//! questions without trusting the tools:
//!
//! 1. **Is it installed?** [`detect`] searches `PATH` for the binary, applying
//!    `PATHEXT` on Windows. The first existing executable wins, in `PATH` order.
//!    Detection never runs the candidate.
//! 2. **Is the version usable?** [`negotiate`] compares the reported version
//!    with a [`Requirement`] and returns a [`Compatibility`]. The version comes
//!    from a [`VersionProbe`]; production uses [`CommandProbe`], which runs only
//!    `--version` with a timeout and an output cap, and tests use
//!    [`ScriptedProbe`].
//!
//! A missing, too-old, or unreadable tool is **not** an error. It produces an
//! [`Adapter`] with `executable`/`version` unset and a human-readable
//! [`Adapter::guidance`] naming the package and the minimum version, so the
//! caller can disable only the affected capability and show the remedy. Nothing
//! here installs, downloads, or invokes an installer (HAL-07's "no vendor
//! binding" and HAL-13's "degrade a missing CLI" both depend on that).
//!
//! Scope: one minimum per adapter. Per-feature degradation below that minimum is
//! the concern of the behaviour layer (T-HAL-05) and todo sync (T-HAL-07), which
//! read [`Adapter::compatibility`] rather than re-probing the binary.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use zero_types::{ErrorCode, ZeroError};

/// Documentation anchor referenced by every guidance string.
pub const ADAPTER_DOCS_ANCHOR: &str = "docs/halcyon.md#adapters";

/// Longest reported-version text copied into an error message.
pub const MAX_REPORTED_VERSION_BYTES: usize = 256;

/// Default `CommandProbe` timeout for one `--version` run.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Default `CommandProbe` cap on each captured stream.
pub const DEFAULT_PROBE_OUTPUT_BYTES: usize = 4 * 1024;

/// Minimum supported `tkb` version.
pub const TKB_MINIMUM_VERSION: Version = Version::new(1, 0, 0);

/// Minimum supported `joker` version.
pub const JOKER_MINIMUM_VERSION: Version = Version::new(1, 0, 0);

/// Minimum supported `epb` version.
pub const EPB_MINIMUM_VERSION: Version = Version::new(1, 0, 0);

/// The external tools Halcyon can drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AdapterKind {
    /// Task backend: `tkb add`, `tkb check`, and todo sync.
    Tkb,
    /// Gate runner: every gate goes through `joker`.
    Joker,
    /// Endpoint bridge: endpoints route through `epb`.
    Epb,
}

impl AdapterKind {
    /// Every adapter, in a stable order for reports and tests.
    pub const ALL: [Self; 3] = [Self::Tkb, Self::Joker, Self::Epb];

    /// Executable file name, without an extension.
    pub const fn binary_name(self) -> &'static str {
        match self {
            Self::Tkb => "tkb",
            Self::Joker => "joker",
            Self::Epb => "epb",
        }
    }

    /// Human-readable name used in guidance.
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Tkb => "tkb task backend",
            Self::Joker => "joker gate runner",
            Self::Epb => "epb endpoint bridge",
        }
    }

    /// Package or distribution text used in guidance.
    pub const fn package_name(self) -> &'static str {
        self.binary_name()
    }

    /// The minimum version this build supports.
    pub const fn minimum_version(self) -> Version {
        match self {
            Self::Tkb => TKB_MINIMUM_VERSION,
            Self::Joker => JOKER_MINIMUM_VERSION,
            Self::Epb => EPB_MINIMUM_VERSION,
        }
    }

    /// The default requirement for this adapter.
    pub const fn requirement(self) -> Requirement {
        Requirement::at_least(self.minimum_version())
    }
}

/// A semantic `MAJOR.MINOR.PATCH` version.
///
/// Build metadata and a prerelease suffix are ignored for comparison: `1.2.3`,
/// `v1.2.3`, `1.2.3-rc.1`, and `1.2.3+build.7` all compare as `1.2.3`. The
/// unmodified probe output is kept separately on [`Adapter::raw_version`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    /// Major version.
    pub major: u64,
    /// Minor version.
    pub minor: u64,
    /// Patch version.
    pub patch: u64,
}

impl Version {
    /// Construct a version from its three numeric components.
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parse one `MAJOR.MINOR.PATCH` token.
    ///
    /// A leading `v`/`V` is accepted, and anything from the first `-` or `+`
    /// onward is ignored, so `v1.2.3-rc.1+build` parses as `1.2.3`. Exactly
    /// three dot-separated numbers are required; `1.2`, `1.2.3.4`, `1.x.3`, and
    /// an empty string all return `None`.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let text = text
            .strip_prefix('v')
            .or_else(|| text.strip_prefix('V'))
            .unwrap_or(text)
            .trim_start();
        let core = text.split(['-', '+']).next().unwrap_or(text);
        let mut parts = core.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self::new(major, minor, patch))
    }

    /// Find the first version token in a `--version` style output.
    ///
    /// Common shapes such as `tkb 1.2.3`, `joker version: 2.0.1`,
    /// `v0.9.0`, and `epb/1.4.0` are accepted. The output is tokenised on
    /// whitespace and punctuation, and each token is handed to
    /// [`Version::parse`]; nothing else in the output is interpreted. The first
    /// token that parses wins, so output that prints a date such as
    /// `2026.11.25` before the real version is read as that date.
    pub fn parse_reported(output: &str) -> Option<Self> {
        output
            .split(|character: char| {
                character.is_whitespace()
                    || matches!(
                        character,
                        ',' | ';' | ':' | '=' | '(' | ')' | '[' | ']' | '/' | '|'
                    )
            })
            .find_map(|token| {
                Self::parse(
                    token.trim_matches(|character: char| !character.is_ascii_alphanumeric()),
                )
            })
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The version floor an adapter must meet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Requirement {
    /// Smallest accepted version, inclusive.
    pub min: Version,
}

impl Requirement {
    /// Require at least `min`.
    pub const fn at_least(min: Version) -> Self {
        Self { min }
    }
}

/// Result of comparing an adapter version with a requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compatibility {
    /// The reported version meets the requirement.
    Compatible,
    /// The reported version is below the requirement.
    TooOld {
        /// Version the adapter reported.
        found: Version,
        /// Version the caller required.
        min: Version,
    },
    /// The probe ran but its output contained no parseable version.
    Unparseable {
        /// Raw probe output, kept for the report and the guidance.
        raw: String,
    },
}

impl Compatibility {
    /// True only for [`Compatibility::Compatible`].
    pub fn is_compatible(&self) -> bool {
        matches!(self, Self::Compatible)
    }
}

/// One adapter's detection and negotiation state.
///
/// `compatibility` is `None` until [`negotiate`] or [`detect_and_negotiate`]
/// runs; [`detect`] alone only answers "is it on `PATH`?". A missing binary
/// already carries `guidance`, so a caller that never probes still has the
/// remedy to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adapter {
    /// Which tool this is.
    pub kind: AdapterKind,
    /// Absolute or `PATH`-relative executable path, when found.
    pub executable: Option<PathBuf>,
    /// Parsed version, when the probe reported one.
    pub version: Option<Version>,
    /// Exact probe output, retained even when parsing failed.
    pub raw_version: Option<String>,
    /// Negotiation result; `None` before negotiation or when the probe failed.
    pub compatibility: Option<Compatibility>,
    /// Install or upgrade guidance. `None` means the adapter is usable.
    pub guidance: Option<String>,
}

impl Adapter {
    /// True when an executable was found. Version may still be unknown.
    pub fn is_present(&self) -> bool {
        self.executable.is_some()
    }

    /// True only after negotiation found the adapter compatible.
    pub fn is_compatible(&self) -> bool {
        matches!(self.compatibility.as_ref(), Some(Compatibility::Compatible))
    }
}

/// The process environment a detection run searches.
///
/// Production uses [`Env::from_process`]; tests build one from explicit
/// directories, so nothing depends on the host's real `PATH`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Env {
    path: Vec<PathBuf>,
    path_ext: Vec<String>,
    windows: bool,
}

impl Env {
    /// Build an environment from `PATH` entries and executable extensions.
    ///
    /// Extensions are normalised to a leading dot. They are only consulted when
    /// the host is Windows; on other platforms the exact file name is used.
    pub fn new<I, P>(path: I, path_ext: Vec<String>) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        Self {
            path: path.into_iter().map(Into::into).collect(),
            path_ext: path_ext
                .iter()
                .filter_map(|extension| normalise_extension(extension))
                .collect(),
            windows: cfg!(windows),
        }
    }

    /// Read `PATH` and `PATHEXT` from the running process.
    ///
    /// A missing or empty `PATHEXT` on Windows falls back to
    /// `.COM;.EXE;.BAT;.CMD`, matching the platform default.
    pub fn from_process() -> Self {
        let path = std::env::var_os("PATH")
            .map(|value| std::env::split_paths(&value).collect())
            .unwrap_or_default();
        let path_ext = if cfg!(windows) {
            let configured = std::env::var_os("PATHEXT")
                .map(|value| parse_pathext(value.to_string_lossy().as_ref()))
                .unwrap_or_default();
            if configured.is_empty() {
                default_pathext()
            } else {
                configured
            }
        } else {
            Vec::new()
        };
        Self {
            path,
            path_ext,
            windows: cfg!(windows),
        }
    }

    /// `PATH` entries in search order.
    pub fn path(&self) -> &[PathBuf] {
        &self.path
    }

    /// Normalised executable extensions in search order.
    pub fn path_ext(&self) -> &[String] {
        &self.path_ext
    }

    /// Whether this environment applies `PATHEXT` rules.
    pub fn is_windows(&self) -> bool {
        self.windows
    }

    /// First executable for `name`, or `None`.
    fn find(&self, name: &str) -> Option<PathBuf> {
        for directory in &self.path {
            if directory.as_os_str().is_empty() {
                continue;
            }
            if self.windows && !self.path_ext.is_empty() {
                for extension in &self.path_ext {
                    let mut file_name = OsString::from(name);
                    file_name.push(extension);
                    let candidate = directory.join(file_name);
                    if is_executable_file(&candidate) {
                        return Some(candidate);
                    }
                }
            } else {
                let candidate = directory.join(name);
                if is_executable_file(&candidate) {
                    return Some(candidate);
                }
            }
        }
        None
    }
}

fn normalise_extension(extension: &str) -> Option<String> {
    let extension = extension.trim();
    if extension.is_empty() {
        return None;
    }
    if extension.starts_with('.') {
        Some(extension.to_string())
    } else {
        Some(format!(".{extension}"))
    }
}

fn parse_pathext(raw: &str) -> Vec<String> {
    raw.split(';').filter_map(normalise_extension).collect()
}

fn default_pathext() -> Vec<String> {
    [".COM", ".EXE", ".BAT", ".CMD"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// True for a regular file this process could execute.
///
/// On Windows the `PATHEXT` filter has already restricted the name, so file
/// existence is the test. On Unix the execute bit is required, so a readable
/// data file named like the tool is ignored rather than offered as a tool.
fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return false;
        }
    }
    true
}

/// Locate an adapter without running it.
///
/// The first existing executable in [`Env::path`] order wins, respecting
/// `PATHEXT` on Windows. A missing binary returns an adapter with
/// `executable: None` and install guidance; it is deliberately not an error, so
/// the caller can disable one tool and keep the rest of the mode working.
///
/// `compatibility` is `None`: use [`negotiate`] or [`detect_and_negotiate`] to
/// compare a version.
pub fn detect(kind: AdapterKind, environment: &Env) -> Adapter {
    match environment.find(kind.binary_name()) {
        Some(executable) => Adapter {
            kind,
            executable: Some(executable),
            version: None,
            raw_version: None,
            compatibility: None,
            guidance: None,
        },
        None => Adapter {
            kind,
            executable: None,
            version: None,
            raw_version: None,
            compatibility: None,
            guidance: Some(missing_guidance(kind, kind.minimum_version())),
        },
    }
}

/// Compare an adapter's version with `requirement` and (re)build its guidance.
///
/// Calling this again with a stricter requirement is supported: the previous
/// compatibility and guidance are replaced, not accumulated. An adapter with no
/// version information at all (no probe has run) is returned unchanged apart
/// from a missing-executable state, which always gets guidance.
pub fn negotiate(mut adapter: Adapter, requirement: Requirement) -> Adapter {
    if adapter.executable.is_none() {
        adapter.compatibility = None;
        adapter.guidance = Some(missing_guidance(adapter.kind, requirement.min));
        return adapter;
    }

    if let Some(version) = adapter.version {
        let (compatibility, guidance) = if version >= requirement.min {
            (Compatibility::Compatible, None)
        } else {
            (
                Compatibility::TooOld {
                    found: version,
                    min: requirement.min,
                },
                Some(too_old_guidance(adapter.kind, version, requirement.min)),
            )
        };
        adapter.compatibility = Some(compatibility);
        adapter.guidance = guidance;
        return adapter;
    }

    if let Some(raw) = adapter.raw_version.clone() {
        let compatibility = Compatibility::Unparseable { raw: raw.clone() };
        adapter.guidance = Some(unparseable_guidance(adapter.kind, &raw, requirement.min));
        adapter.compatibility = Some(compatibility);
        return adapter;
    }

    adapter
}

/// Detect an adapter, read its version through `probe`, and negotiate it.
///
/// The probe is called at most once and only for a found executable. A probe
/// failure (spawn error, timeout, empty output) keeps the adapter present but
/// unknown and replaces the guidance with the reason plus the minimum version,
/// so the caller can still show a remedy. Nothing is installed or downloaded.
pub fn detect_and_negotiate(
    kind: AdapterKind,
    environment: &Env,
    probe: &dyn VersionProbe,
) -> Adapter {
    let mut adapter = detect(kind, environment);
    let Some(executable) = adapter.executable.clone() else {
        return negotiate(adapter, kind.requirement());
    };

    match probe.version(&executable) {
        Ok(raw) => {
            adapter.version = Version::parse_reported(&raw);
            adapter.raw_version = Some(raw);
            negotiate(adapter, kind.requirement())
        }
        Err(error) => {
            adapter.compatibility = None;
            adapter.guidance = Some(probe_error_guidance(
                kind,
                kind.minimum_version(),
                &executable,
                &error,
            ));
            adapter
        }
    }
}

fn missing_guidance(kind: AdapterKind, min: Version) -> String {
    format!(
        "{} (`{}`) was not found on PATH. Install the `{}` package and put its directory on PATH (see {}). Minimum supported version: {min}. Confirm with `{} --version`.",
        kind.display_name(),
        kind.binary_name(),
        kind.package_name(),
        ADAPTER_DOCS_ANCHOR,
        kind.binary_name(),
    )
}

fn too_old_guidance(kind: AdapterKind, found: Version, min: Version) -> String {
    format!(
        "{} (`{}`) reported version {found}, below the minimum supported version {min}. Upgrade the `{}` package and put the new binary on PATH (see {}), then confirm with `{} --version`.",
        kind.display_name(),
        kind.binary_name(),
        kind.package_name(),
        ADAPTER_DOCS_ANCHOR,
        kind.binary_name(),
    )
}

fn unparseable_guidance(kind: AdapterKind, raw: &str, min: Version) -> String {
    format!(
        "{} (`{}`) reported `{}`, which is not a MAJOR.MINOR.PATCH version. This build requires {min} or newer; reinstall a release build whose `{} --version` prints a three-part version (see {}).",
        kind.display_name(),
        kind.binary_name(),
        display_raw(raw),
        kind.binary_name(),
        ADAPTER_DOCS_ANCHOR,
    )
}

fn probe_error_guidance(
    kind: AdapterKind,
    min: Version,
    executable: &Path,
    error: &ZeroError,
) -> String {
    format!(
        "{} (`{}`) was found at {}, but its version could not be read: {}. This build requires {min} or newer; run `{} --version` manually, then repair or reinstall the `{}` package (see {}).",
        kind.display_name(),
        kind.binary_name(),
        executable.display(),
        display_raw(error.message()),
        kind.binary_name(),
        kind.package_name(),
        ADAPTER_DOCS_ANCHOR,
    )
}

/// Make probe output safe to embed in a one-line guidance string.
fn display_raw(raw: &str) -> String {
    let text: String = raw
        .chars()
        .take(MAX_REPORTED_VERSION_BYTES)
        .map(|character| match character {
            '`' => '\'',
            character if character.is_control() => ' ',
            character => character,
        })
        .collect();
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.is_empty() {
        "<no output>".to_string()
    } else {
        text
    }
}

/// Seam for reading a tool's version.
///
/// Implementations must not install, download, or otherwise modify the tool.
/// The trait exists so tests never execute a fixture binary and so a host can
/// supply a different probe (for example one that understands a shell-script
/// launcher on Windows).
pub trait VersionProbe {
    /// Return the raw `--version` output for `executable`.
    fn version(&self, executable: &Path) -> Result<String, ZeroError>;
}

/// Production probe: run `<executable> --version` once.
///
/// The child gets no stdin. Stdout and stderr are captured on reader threads so
/// a chatty binary cannot fill a pipe and deadlock the probe, each stream is
/// capped at [`CommandProbe::max_output_bytes`] (`LimitExceeded` if either
/// exceeds it), and the process is killed after [`CommandProbe::timeout`]
/// (`Timeout`). Stdout wins when both streams are non-empty, because many tools
/// print the version there and a warning on stderr.
///
/// The candidate is spawned directly, never through a shell. Detection can find
/// a `.cmd`/`.bat` through `PATHEXT`, but Windows cannot spawn those without
/// `cmd.exe`; such a launcher fails the probe and the caller sees guidance.
/// That is a documented detection limitation, not a reason to run a shell.
#[derive(Debug, Clone, Copy)]
pub struct CommandProbe {
    timeout: Duration,
    max_output_bytes: usize,
}

impl CommandProbe {
    /// Build a probe with an explicit timeout and per-stream byte cap.
    pub fn new(timeout: Duration, max_output_bytes: usize) -> Self {
        Self {
            timeout,
            max_output_bytes,
        }
    }

    /// How long one `--version` run may take.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Largest number of bytes kept from each stream.
    pub fn max_output_bytes(&self) -> usize {
        self.max_output_bytes
    }
}

impl Default for CommandProbe {
    fn default() -> Self {
        Self::new(DEFAULT_PROBE_TIMEOUT, DEFAULT_PROBE_OUTPUT_BYTES)
    }
}

type CappedRead = io::Result<(Vec<u8>, bool)>;

impl VersionProbe for CommandProbe {
    fn version(&self, executable: &Path) -> Result<String, ZeroError> {
        let mut child = Command::new(executable)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| probe_io_error(executable, error))?;

        let cap = self.max_output_bytes;
        let stdout_reader = child
            .stdout
            .take()
            .map(|mut pipe| thread::spawn(move || read_capped(&mut pipe, cap)));
        let stderr_reader = child
            .stderr
            .take()
            .map(|mut pipe| thread::spawn(move || read_capped(&mut pipe, cap)));

        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if started.elapsed() >= self.timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        let _ = join_reader(stdout_reader, "stdout");
                        let _ = join_reader(stderr_reader, "stderr");
                        return Err(ZeroError::new(
                            ErrorCode::Timeout,
                            format!(
                                "`{} --version` did not finish within {} ms",
                                executable.display(),
                                self.timeout.as_millis()
                            ),
                        ));
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = join_reader(stdout_reader, "stdout");
                    let _ = join_reader(stderr_reader, "stderr");
                    return Err(probe_io_error(executable, error));
                }
            }
        };

        let (stdout, stdout_overflow) = join_reader(stdout_reader, "stdout")?;
        let (stderr, stderr_overflow) = join_reader(stderr_reader, "stderr")?;
        if stdout_overflow || stderr_overflow {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "`{} --version` printed more than {} bytes; refusing to parse it",
                    executable.display(),
                    self.max_output_bytes
                ),
            ));
        }

        let raw = if stdout.is_empty() { stderr } else { stdout };
        let text = String::from_utf8_lossy(&raw).trim().to_string();
        if text.is_empty() {
            return Err(ZeroError::new(
                ErrorCode::Internal,
                format!(
                    "`{} --version` exited {status} with no output",
                    executable.display()
                ),
            ));
        }
        Ok(text)
    }
}

fn read_capped(reader: &mut impl Read, cap: usize) -> CappedRead {
    let mut bytes = Vec::new();
    reader
        .take(cap.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    let overflow = bytes.len() > cap;
    if overflow {
        bytes.truncate(cap);
    }
    Ok((bytes, overflow))
}

fn join_reader(
    handle: Option<thread::JoinHandle<CappedRead>>,
    stream: &str,
) -> Result<(Vec<u8>, bool), ZeroError> {
    let Some(handle) = handle else {
        return Ok((Vec::new(), false));
    };
    let result = handle.join().map_err(|_| {
        ZeroError::new(
            ErrorCode::Internal,
            format!("the {stream} reader thread panicked while probing an adapter"),
        )
    })?;
    result.map_err(|error| {
        ZeroError::new(
            ErrorCode::Internal,
            format!("cannot read adapter {stream}: {error}"),
        )
    })
}

fn probe_io_error(executable: &Path, error: io::Error) -> ZeroError {
    let code = match error.kind() {
        io::ErrorKind::NotFound => ErrorCode::NotFound,
        io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        io::ErrorKind::TimedOut => ErrorCode::Timeout,
        _ => ErrorCode::Io,
    };
    ZeroError::new(
        code,
        format!("cannot run `{} --version`: {error}", executable.display()),
    )
}

/// Test double: scripted probe output, never a real process.
///
/// `with_output`/`with_error` key on the executable path; the `with_any_*`
/// variants are a fallback. `calls()` and `requested()` let a test prove the
/// probe ran once, on the path detection chose, and that no binary executed.
#[derive(Debug, Default)]
pub struct ScriptedProbe {
    outputs: BTreeMap<PathBuf, Result<String, ZeroError>>,
    fallback: Option<Result<String, ZeroError>>,
    calls: Cell<usize>,
    requested: RefCell<Vec<PathBuf>>,
}

impl ScriptedProbe {
    /// An empty script. Probing an unscripted path is an error.
    pub fn new() -> Self {
        Self::default()
    }

    /// Script `output` for one executable path.
    pub fn with_output(
        mut self,
        executable: impl Into<PathBuf>,
        output: impl Into<String>,
    ) -> Self {
        self.outputs.insert(executable.into(), Ok(output.into()));
        self
    }

    /// Script a probe failure for one executable path.
    pub fn with_error(mut self, executable: impl Into<PathBuf>, error: ZeroError) -> Self {
        self.outputs.insert(executable.into(), Err(error));
        self
    }

    /// Script `output` for any path without a specific entry.
    pub fn with_any_output(mut self, output: impl Into<String>) -> Self {
        self.fallback = Some(Ok(output.into()));
        self
    }

    /// Script a probe failure for any path without a specific entry.
    pub fn with_any_error(mut self, error: ZeroError) -> Self {
        self.fallback = Some(Err(error));
        self
    }

    /// Number of probe calls made.
    pub fn calls(&self) -> usize {
        self.calls.get()
    }

    /// Paths passed to the probe, in call order.
    pub fn requested(&self) -> Vec<PathBuf> {
        self.requested.borrow().clone()
    }
}

impl VersionProbe for ScriptedProbe {
    fn version(&self, executable: &Path) -> Result<String, ZeroError> {
        self.calls.set(self.calls.get() + 1);
        self.requested.borrow_mut().push(executable.to_path_buf());
        if let Some(result) = self.outputs.get(executable) {
            return result.clone();
        }
        if let Some(result) = &self.fallback {
            return result.clone();
        }
        Err(ZeroError::new(
            ErrorCode::Internal,
            format!("ScriptedProbe has no output for {}", executable.display()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn fixture() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn env_for(directories: &[&Path]) -> Env {
        if cfg!(windows) {
            Env::new(
                directories.iter().copied(),
                vec![".EXE".to_string(), ".CMD".to_string(), ".BAT".to_string()],
            )
        } else {
            Env::new(directories.iter().copied(), Vec::new())
        }
    }

    /// Create an executable-looking fixture. It is never run: every test uses a
    /// `ScriptedProbe`, and the content is deliberately not a valid program.
    fn install(dir: &Path, file_name: &str) -> PathBuf {
        let path = dir.join(file_name);
        fs::write(&path, b"#!/bin/sh\nexit 7\n").expect("write fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        path
    }

    fn windows_name(name: &str, extension: &str) -> String {
        if cfg!(windows) {
            format!("{name}{extension}")
        } else {
            name.to_string()
        }
    }

    fn guidance(adapter: &Adapter) -> &str {
        adapter.guidance.as_deref().expect("guidance")
    }

    #[test]
    fn a_missing_binary_shows_install_guidance() {
        let dir = fixture();
        let env = env_for(&[dir.path()]);
        let probe = ScriptedProbe::new();

        let adapter = detect_and_negotiate(AdapterKind::Tkb, &env, &probe);

        assert!(!adapter.is_present());
        assert_eq!(adapter.executable, None);
        assert_eq!(adapter.version, None);
        assert_eq!(adapter.compatibility, None);
        assert!(!adapter.is_compatible());
        let guidance = guidance(&adapter);
        assert!(guidance.contains("tkb"), "{guidance}");
        assert!(guidance.contains("1.0.0"), "{guidance}");
        assert!(guidance.contains("PATH"), "{guidance}");
        assert_eq!(probe.calls(), 0, "a missing binary must not be probed");
    }

    #[test]
    fn every_adapter_guidance_names_the_binary_and_minimum() {
        let dir = fixture();
        let env = env_for(&[dir.path()]);

        for kind in AdapterKind::ALL {
            let adapter = detect(kind, &env);
            let guidance = guidance(&adapter);

            assert!(guidance.contains(kind.binary_name()), "{guidance}");
            assert!(
                guidance.contains(&kind.minimum_version().to_string()),
                "{guidance}"
            );
            assert!(guidance.contains(kind.display_name()), "{guidance}");
            assert!(guidance.contains(kind.package_name()), "{guidance}");
            assert!(guidance.contains("Install"), "{guidance}");
            assert!(guidance.contains(ADAPTER_DOCS_ANCHOR), "{guidance}");
        }
    }

    #[test]
    fn a_found_compatible_binary_has_no_guidance() {
        let dir = fixture();
        let name = windows_name("tkb", ".EXE");
        let path = install(dir.path(), &name);
        let env = env_for(&[dir.path()]);
        let probe = ScriptedProbe::new().with_output(&path, "tkb 1.2.3");

        let adapter = detect_and_negotiate(AdapterKind::Tkb, &env, &probe);

        assert_eq!(adapter.executable.as_deref(), Some(path.as_path()));
        assert_eq!(adapter.version, Some(Version::new(1, 2, 3)));
        assert_eq!(adapter.raw_version.as_deref(), Some("tkb 1.2.3"));
        assert_eq!(adapter.compatibility, Some(Compatibility::Compatible));
        assert!(adapter.is_compatible());
        assert_eq!(adapter.guidance, None);
        assert_eq!(probe.calls(), 1);
        assert_eq!(probe.requested(), vec![path]);
    }

    #[test]
    fn a_too_old_binary_explains_the_minimum() {
        let dir = fixture();
        let name = windows_name("joker", ".EXE");
        let path = install(dir.path(), &name);
        let env = env_for(&[dir.path()]);
        let probe = ScriptedProbe::new().with_output(&path, "joker 0.9.0");

        let adapter = detect_and_negotiate(AdapterKind::Joker, &env, &probe);

        assert_eq!(adapter.version, Some(Version::new(0, 9, 0)));
        assert_eq!(
            adapter.compatibility,
            Some(Compatibility::TooOld {
                found: Version::new(0, 9, 0),
                min: JOKER_MINIMUM_VERSION,
            })
        );
        assert!(!adapter.is_compatible());
        let guidance = guidance(&adapter);
        assert!(guidance.contains("joker"), "{guidance}");
        assert!(guidance.contains("0.9.0"), "{guidance}");
        assert!(guidance.contains("1.0.0"), "{guidance}");
        assert!(guidance.contains("Upgrade"), "{guidance}");
    }

    #[test]
    fn an_unparseable_version_is_reported_with_guidance() {
        let dir = fixture();
        let name = windows_name("epb", ".EXE");
        let path = install(dir.path(), &name);
        let env = env_for(&[dir.path()]);
        let probe = ScriptedProbe::new().with_output(&path, "epb unknown build");

        let adapter = detect_and_negotiate(AdapterKind::Epb, &env, &probe);

        assert_eq!(adapter.version, None);
        assert_eq!(adapter.raw_version.as_deref(), Some("epb unknown build"));
        assert_eq!(
            adapter.compatibility,
            Some(Compatibility::Unparseable {
                raw: "epb unknown build".to_string(),
            })
        );
        let guidance = guidance(&adapter);
        assert!(guidance.contains("epb unknown build"), "{guidance}");
        assert!(guidance.contains("MAJOR.MINOR.PATCH"), "{guidance}");
        assert!(guidance.contains("1.0.0"), "{guidance}");
    }

    #[test]
    fn versions_parse_with_a_prefix_and_suffixes() {
        assert_eq!(Version::parse("1.2.3"), Some(Version::new(1, 2, 3)));
        assert_eq!(Version::parse(" v1.2.3 "), Some(Version::new(1, 2, 3)));
        assert_eq!(
            Version::parse("v1.2.3-rc.1+build.5"),
            Some(Version::new(1, 2, 3))
        );
        assert_eq!(Version::parse("1.2.3+build"), Some(Version::new(1, 2, 3)));
        assert_eq!(Version::parse("1.2"), None);
        assert_eq!(Version::parse("1.2.3.4"), None);
        assert_eq!(Version::parse("1.x.3"), None);
        assert_eq!(Version::parse(""), None);
        assert_eq!(Version::parse("v"), None);
    }

    #[test]
    fn reported_output_is_searched_for_a_version() {
        assert_eq!(
            Version::parse_reported("tkb 1.2.3\n"),
            Some(Version::new(1, 2, 3))
        );
        assert_eq!(
            Version::parse_reported("joker version: 2.0.1"),
            Some(Version::new(2, 0, 1))
        );
        assert_eq!(
            Version::parse_reported("v0.9.0"),
            Some(Version::new(0, 9, 0))
        );
        assert_eq!(
            Version::parse_reported("epb/1.4.0 (release)"),
            Some(Version::new(1, 4, 0))
        );
        assert_eq!(Version::parse_reported("no version here"), None);
        assert_eq!(Version::parse_reported(""), None);
    }

    #[test]
    fn path_order_decides_which_executable_is_used() {
        let first = fixture();
        let second = fixture();
        let first_path = install(first.path(), &windows_name("tkb", ".EXE"));
        let second_path = install(second.path(), &windows_name("tkb", ".EXE"));
        let env = env_for(&[first.path(), second.path()]);
        let probe = ScriptedProbe::new()
            .with_output(&first_path, "tkb 1.0.0")
            .with_output(&second_path, "tkb 9.9.9");

        let adapter = detect_and_negotiate(AdapterKind::Tkb, &env, &probe);

        assert_eq!(adapter.executable.as_deref(), Some(first_path.as_path()));
        assert_eq!(adapter.version, Some(Version::new(1, 0, 0)));
        assert_eq!(probe.requested(), vec![first_path]);
    }

    #[test]
    fn a_non_executable_file_is_ignored() {
        let dir = fixture();
        let env = env_for(&[dir.path()]);

        #[cfg(unix)]
        {
            let path = dir.path().join("tkb");
            fs::write(&path, b"#!/bin/sh\nexit 0\n").expect("write data file");
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");

            assert_eq!(detect(AdapterKind::Tkb, &env).executable, None);
        }

        #[cfg(windows)]
        {
            // No PATHEXT extension: a `tkb.txt` or a bare `tkb` is not a
            // candidate under Windows rules.
            fs::write(dir.path().join("tkb.txt"), b"data").expect("write text file");
            fs::write(dir.path().join("tkb"), b"data").expect("write bare file");

            assert_eq!(detect(AdapterKind::Tkb, &env).executable, None);
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_pathext_decides_which_extension_is_used() {
        let dir = fixture();
        let command = install(dir.path(), "tkb.CMD");
        let executable = install(dir.path(), "tkb.EXE");
        let cmd_first = Env::new([dir.path()], vec![".CMD".to_string(), ".EXE".to_string()]);
        let exe_first = Env::new([dir.path()], vec![".EXE".to_string(), ".CMD".to_string()]);

        assert_eq!(
            detect(AdapterKind::Tkb, &cmd_first).executable,
            Some(command.clone())
        );
        assert_eq!(
            detect(AdapterKind::Tkb, &exe_first).executable,
            Some(executable)
        );

        fs::remove_file(&command).expect("remove cmd fixture");
        assert_eq!(
            detect(AdapterKind::Tkb, &cmd_first).executable,
            Some(dir.path().join("tkb.EXE"))
        );
    }

    #[test]
    fn a_probe_error_shows_guidance_instead_of_failing_detection() {
        let dir = fixture();
        let name = windows_name("tkb", ".EXE");
        let path = install(dir.path(), &name);
        let env = env_for(&[dir.path()]);
        let probe = ScriptedProbe::new().with_error(
            &path,
            ZeroError::new(ErrorCode::Timeout, "probe clock expired"),
        );

        let adapter = detect_and_negotiate(AdapterKind::Tkb, &env, &probe);

        assert!(adapter.is_present());
        assert_eq!(adapter.version, None);
        assert_eq!(adapter.compatibility, None);
        let guidance = guidance(&adapter);
        assert!(guidance.contains("tkb"), "{guidance}");
        assert!(guidance.contains("probe clock expired"), "{guidance}");
        assert!(guidance.contains("1.0.0"), "{guidance}");
        assert_eq!(probe.calls(), 1);
    }

    #[test]
    fn negotiation_uses_an_explicit_requirement() {
        let dir = fixture();
        let name = windows_name("tkb", ".EXE");
        let path = install(dir.path(), &name);
        let env = env_for(&[dir.path()]);
        let probe = ScriptedProbe::new().with_output(&path, "tkb 1.5.0");

        let adapter = detect_and_negotiate(AdapterKind::Tkb, &env, &probe);
        assert!(adapter.is_compatible());

        let stricter = negotiate(adapter, Requirement::at_least(Version::new(2, 0, 0)));

        assert_eq!(
            stricter.compatibility,
            Some(Compatibility::TooOld {
                found: Version::new(1, 5, 0),
                min: Version::new(2, 0, 0),
            })
        );
        assert!(guidance(&stricter).contains("2.0.0"));
        assert!(guidance(&stricter).contains("1.5.0"));

        let relaxed = negotiate(stricter, Requirement::at_least(Version::new(1, 0, 0)));
        assert_eq!(relaxed.compatibility, Some(Compatibility::Compatible));
        assert_eq!(relaxed.guidance, None);
    }

    #[test]
    fn detection_does_not_execute_the_binary() {
        let dir = fixture();
        let name = windows_name("tkb", ".EXE");
        let path = install(dir.path(), &name);
        let marker = dir.path().join("executed.marker");
        let env = env_for(&[dir.path()]);
        let probe = ScriptedProbe::new().with_output(&path, "tkb 1.2.3");

        let adapter = detect_and_negotiate(AdapterKind::Tkb, &env, &probe);

        assert!(adapter.is_compatible());
        assert_eq!(
            probe.calls(),
            1,
            "the scripted probe is the only version run"
        );
        assert!(
            !marker.exists(),
            "detection must not run the fixture executable"
        );

        // The install helper writes a shell script on Unix; it would create the
        // marker if anything executed it instead of using the probe.
        #[cfg(unix)]
        {
            fs::write(
                &path,
                format!("#!/bin/sh\ntouch {}\nexit 0\n", marker.display()),
            )
            .expect("rewrite fixture");
            let mut permissions = fs::metadata(&path).expect("metadata").permissions();
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(0o755);
            fs::set_permissions(&path, permissions).expect("chmod");

            let adapter = detect_and_negotiate(AdapterKind::Tkb, &env, &probe);
            assert!(adapter.is_compatible());
            assert!(!marker.exists(), "the fixture must never be executed");
        }
    }
}
