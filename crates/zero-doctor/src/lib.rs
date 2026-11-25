//! `zero-doctor` — see `architecture.md` section 5 for the module contract.
//!
//! The doctor must run while the daemon, kernel, and mesh are dead (DOC-09), so
//! the core is plugin-free and never opens a daemon socket. Every check reads an
//! injectable [`DoctorContext`] rather than a live service; the default context
//! derives local paths from a root directory and reports absent inputs as a
//! warning instead of inventing a pass.
//!
//! Details are deliberately short and redaction-safe: paths, counts, status
//! names, and line numbers may appear; key bytes, tokens, config values, and
//! identity values never do.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// The crate version, shared by the binary banner and the report.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The stable names and order of every check in the core.
pub const CHECK_NAMES: [&str; 13] = [
    "versions", "config", "keys", "workers", "kernel", "auth", "network", "mesh", "ports", "disk",
    "locks", "journals", "mcp",
];

/// Locks older than this are reported as stale.
pub const DEFAULT_LOCK_STALE_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

/// Free space below this is a failure.
const DISK_FAIL_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB
/// Free space below this is a warning.
const DISK_WARN_BYTES: u64 = 5 * 1024 * 1024 * 1024; // 5 GiB

/// Whether the core reached the daemon.
///
/// The core never contacts the daemon on its own: diagnosis has to work with
/// the daemon dead. A later task may fill in the contacted states from a
/// caller-supplied probe, never from the core itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonStatus {
    /// The core did not try to reach the daemon.
    NotContacted,
    /// A caller-supplied probe reached the daemon.
    Reachable,
    /// A caller-supplied probe found the daemon dead or unresponsive.
    Unreachable,
}

impl DaemonStatus {
    /// Human wording for the CLI, stable enough to assert on.
    pub fn label(self) -> &'static str {
        match self {
            DaemonStatus::NotContacted => "not contacted",
            DaemonStatus::Reachable => "reachable",
            DaemonStatus::Unreachable => "unreachable",
        }
    }
}

/// Outcome of one doctor check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// The check passed.
    Ok,
    /// The check passed with something worth reading.
    Warn,
    /// The check failed.
    Fail,
}

impl CheckStatus {
    /// Stable short label used by the human renderer.
    pub fn label(self) -> &'static str {
        match self {
            CheckStatus::Ok => "ok",
            CheckStatus::Warn => "warn",
            CheckStatus::Fail => "fail",
        }
    }
}

/// One check result: a stable name, an outcome, and a redaction-safe detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
}

/// The diagnosis report. Serialized as `--json` and rendered for humans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub version: String,
    pub independent: bool,
    pub daemon: DaemonStatus,
    pub checks: Vec<CheckResult>,
}

impl DoctorReport {
    /// Human rendering. Keeps one `name: value` line per field so tests and
    /// operators can grep it, then one `status  name  detail` line per check.
    pub fn render_human(&self) -> String {
        let mut out = format!(
            "zero-doctor {}\nindependent: {}\ndaemon: {}\nchecks: {}\n",
            self.version,
            if self.independent { "yes" } else { "no" },
            self.daemon.label(),
            self.checks.len(),
        );
        for check in &self.checks {
            out.push_str(&format!(
                "  {:<4}  {:<10}  {}\n",
                check.status.label(),
                check.name,
                check.detail,
            ));
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Injectable snapshots
// ---------------------------------------------------------------------------

/// A file captured before the checks run: the path plus its text, if present.
///
/// Text is `None` for an absent or unreadable file. Checks then report
/// `skipped` instead of pretending the file was healthy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSnapshot {
    pub path: PathBuf,
    pub text: Option<String>,
}

impl FileSnapshot {
    /// Capture a file if it exists and is valid UTF-8.
    pub fn read(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let text = std::fs::read_to_string(&path).ok();
        Self { path, text }
    }

    /// A snapshot for a path that is known to be absent.
    pub fn absent(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            text: None,
        }
    }

    /// A snapshot with injected text, used by fixtures and probes.
    pub fn with_text(path: impl Into<PathBuf>, text: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            text: Some(text.into()),
        }
    }
}

/// Version inputs captured once.
#[derive(Debug, Clone)]
pub struct VersionsSnapshot {
    pub zero_version: String,
    pub toolchain: Option<String>,
}

/// Kernel state as supplied by the caller. The core never probes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelState {
    Running,
    Stopped,
    Unknown,
}

/// Kernel snapshot: state and the socket path that should accompany it.
#[derive(Debug, Clone)]
pub struct KernelSnapshot {
    pub state: KernelState,
    pub socket: Option<PathBuf>,
}

/// Which credential backend the installation is configured to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialBackend {
    /// The platform OS store, named for display.
    OsStore(String),
    /// The AES-256-GCM encrypted file fallback.
    EncryptedFile,
    /// Neither backend is usable.
    Unavailable,
    /// Not probed (for example, the daemon that owns the choice is dead).
    Unknown,
}

/// Network inputs. Only names and validity are reported, never values.
#[derive(Debug, Clone, Default)]
pub struct NetworkSnapshot {
    pub proxy: Option<String>,
    pub base_url: Option<String>,
    pub offline: bool,
}

/// Expected and actual listening ports.
#[derive(Debug, Clone, Default)]
pub struct PortsSnapshot {
    pub expected: Vec<u16>,
    pub listening: Vec<u16>,
}

/// Disk capacity in bytes, injected because `std` has no portable free-space API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskSnapshot {
    pub free_bytes: u64,
    pub total_bytes: u64,
}

/// One lock file and the modification time observed for it.
#[derive(Debug, Clone)]
pub struct LockEntry {
    pub path: PathBuf,
    pub modified: Option<SystemTime>,
}

/// Lock inputs: the files, the staleness threshold, and a fixed `now`.
#[derive(Debug, Clone)]
pub struct LocksSnapshot {
    pub entries: Vec<LockEntry>,
    pub stale_after: Duration,
    pub now: SystemTime,
}

impl Default for LocksSnapshot {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            stale_after: DEFAULT_LOCK_STALE_AFTER,
            now: SystemTime::now(),
        }
    }
}

/// Everything the checks may look at. Construction is pure: no daemon socket,
/// no network, and no check can mutate the installation.
#[derive(Debug, Clone)]
pub struct DoctorContext {
    /// Root used to derive default paths.
    pub root: PathBuf,
    pub versions: VersionsSnapshot,
    pub config: FileSnapshot,
    pub project_key_path: PathBuf,
    pub workers_journal: FileSnapshot,
    pub kernel: KernelSnapshot,
    pub credential_backend: CredentialBackend,
    pub network: NetworkSnapshot,
    pub mesh_registry: FileSnapshot,
    pub ports: PortsSnapshot,
    pub disk: Option<DiskSnapshot>,
    pub locks: LocksSnapshot,
    pub journals: Vec<PathBuf>,
    pub mcp_config: FileSnapshot,
}

impl Default for DoctorContext {
    fn default() -> Self {
        let root = std::env::var_os("ZERO_DATA_DIR")
            .map(PathBuf::from)
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        Self::from_root(root)
    }
}

impl DoctorContext {
    /// Derive the default layout from one root.
    ///
    /// The project layout is `.zero/{config.toml,key,workers.json,journal,
    /// locks,mcp.json}` plus `.zero/mesh/registry.json`. Everything is captured
    /// once so every check sees the same snapshot. Inputs the core cannot know
    /// without a live service (kernel state, credential backend, ports, disk)
    /// stay unknown and produce a warning.
    pub fn from_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let zero = root.join(".zero");
        Self {
            root,
            versions: VersionsSnapshot {
                zero_version: VERSION.to_string(),
                toolchain: rustc_version(),
            },
            config: FileSnapshot::read(zero.join("config.toml")),
            project_key_path: zero.join("key"),
            workers_journal: FileSnapshot::read(zero.join("workers.json")),
            kernel: KernelSnapshot {
                state: KernelState::Unknown,
                socket: Some(zero.join("kernel.sock")),
            },
            credential_backend: CredentialBackend::Unknown,
            network: NetworkSnapshot::default(),
            mesh_registry: FileSnapshot::read(zero.join("mesh").join("registry.json")),
            ports: PortsSnapshot::default(),
            disk: None,
            locks: LocksSnapshot {
                entries: lock_files(&zero.join("locks")),
                stale_after: DEFAULT_LOCK_STALE_AFTER,
                now: SystemTime::now(),
            },
            journals: journal_files(&zero.join("journal")),
            mcp_config: FileSnapshot::read(zero.join("mcp.json")),
        }
    }
}

/// Capture `rustc --version` once. No network; absence is reported, not fatal.
fn rustc_version() -> Option<String> {
    let output = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let first = text.lines().next()?.trim();
    (!first.is_empty()).then(|| first.to_string())
}

fn journal_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .collect();
    paths.sort();
    paths
}

fn lock_files(dir: &Path) -> Vec<LockEntry> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "lock"))
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let modified = std::fs::metadata(&path)
                .and_then(|meta| meta.modified())
                .ok();
            LockEntry { path, modified }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------

/// Run the plugin-free core with the default context: no daemon socket and no
/// network. Checks that need a live service say `skipped` instead of guessing.
pub fn run_core() -> DoctorReport {
    run_core_with(&DoctorContext::default())
}

/// Run every check against an injected context. Never panics and never contacts
/// the daemon, so callers can run it while the whole stack is dead.
pub fn run_core_with(ctx: &DoctorContext) -> DoctorReport {
    DoctorReport {
        version: VERSION.to_string(),
        independent: true,
        daemon: DaemonStatus::NotContacted,
        checks: vec![
            check_versions(ctx),
            check_config(ctx),
            check_keys(ctx),
            check_workers(ctx),
            check_kernel(ctx),
            check_auth(ctx),
            check_network(ctx),
            check_mesh(ctx),
            check_ports(ctx),
            check_disk(ctx),
            check_locks(ctx),
            check_journals(ctx),
            check_mcp(ctx),
        ],
    }
}

fn result(name: &str, status: CheckStatus, detail: impl Into<String>) -> CheckResult {
    CheckResult {
        name: name.to_string(),
        status,
        detail: detail.into(),
    }
}

fn ok(name: &str, detail: impl Into<String>) -> CheckResult {
    result(name, CheckStatus::Ok, detail)
}

fn warn(name: &str, detail: impl Into<String>) -> CheckResult {
    result(name, CheckStatus::Warn, detail)
}

fn fail(name: &str, detail: impl Into<String>) -> CheckResult {
    result(name, CheckStatus::Fail, detail)
}

/// Keep arbitrary file-supplied text short, printable, and single-line.
fn clean(text: &str, max: usize) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        if out.chars().count() >= max {
            out.push('…');
            break;
        }
        out.push(if ch.is_control() { '?' } else { ch });
    }
    out
}

fn short_list<T: std::fmt::Display>(items: &[T], limit: usize) -> String {
    let shown: Vec<String> = items.iter().take(limit).map(ToString::to_string).collect();
    let mut out = shown.join(", ");
    if items.len() > limit {
        out.push_str(&format!(" (+{} more)", items.len() - limit));
    }
    out
}

// ---------------------------------------------------------------------------
// 1. versions
// ---------------------------------------------------------------------------

fn check_versions(ctx: &DoctorContext) -> CheckResult {
    let version = ctx.versions.zero_version.trim();
    if version.is_empty() {
        return fail("versions", "zero version is unknown");
    }
    match ctx
        .versions
        .toolchain
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(toolchain) => ok(
            "versions",
            format!(
                "zero {version}; {} [{}]",
                clean(toolchain, 80),
                std::env::consts::OS
            ),
        ),
        None => warn(
            "versions",
            format!("zero {version}; toolchain not detected"),
        ),
    }
}

// ---------------------------------------------------------------------------
// 2. config
// ---------------------------------------------------------------------------

fn check_config(ctx: &DoctorContext) -> CheckResult {
    let Some(text) = ctx.config.text.as_deref() else {
        return warn(
            "config",
            format!(
                "config skipped: no readable file at {}",
                ctx.config.path.display()
            ),
        );
    };
    match validate_toml(text) {
        Ok(()) => ok(
            "config",
            format!("config parses: {}", ctx.config.path.display()),
        ),
        Err(line) => fail(
            "config",
            format!(
                "config malformed at line {line}: {}",
                ctx.config.path.display()
            ),
        ),
    }
}

/// Minimal structural TOML validation.
///
/// There is no TOML parser in the allowed dependency set, so this validates the
/// shape that matters for diagnosis: balanced brackets, closed strings, table
/// headers, and a key before `=`. It intentionally does not interpret values.
fn validate_toml(text: &str) -> Result<(), usize> {
    let mut quote = TomlQuote::None;
    let mut depth: i32 = 0;
    let mut last = 1;
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        last = number;
        if quote == TomlQuote::None && depth == 0 {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if trimmed.starts_with('[') {
                let inner = trimmed.trim_start_matches('[').trim_end_matches(']').trim();
                if !trimmed.contains(']') || inner.is_empty() {
                    return Err(number);
                }
            } else if !line_has_assignment(trimmed) {
                return Err(number);
            }
        }
        quote = scan_toml_line(line, quote, &mut depth, number)?;
    }
    if quote != TomlQuote::None || depth != 0 {
        return Err(last);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TomlQuote {
    None,
    Basic,
    Literal,
    MultiBasic,
    MultiLiteral,
}

fn scan_toml_line(
    line: &str,
    mut quote: TomlQuote,
    depth: &mut i32,
    number: usize,
) -> Result<TomlQuote, usize> {
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        match quote {
            TomlQuote::None => {
                if ch == '#' {
                    break;
                } else if ch == '"' {
                    if chars.get(i + 1) == Some(&'"') && chars.get(i + 2) == Some(&'"') {
                        quote = TomlQuote::MultiBasic;
                        i += 3;
                    } else {
                        quote = TomlQuote::Basic;
                        i += 1;
                    }
                } else if ch == '\'' {
                    if chars.get(i + 1) == Some(&'\'') && chars.get(i + 2) == Some(&'\'') {
                        quote = TomlQuote::MultiLiteral;
                        i += 3;
                    } else {
                        quote = TomlQuote::Literal;
                        i += 1;
                    }
                } else {
                    if ch == '[' || ch == '{' {
                        *depth += 1;
                    } else if ch == ']' || ch == '}' {
                        *depth -= 1;
                        if *depth < 0 {
                            return Err(number);
                        }
                    }
                    i += 1;
                }
            }
            TomlQuote::Basic => {
                if ch == '\\' {
                    i += 2;
                } else {
                    if ch == '"' {
                        quote = TomlQuote::None;
                    }
                    i += 1;
                }
            }
            TomlQuote::Literal => {
                if ch == '\'' {
                    quote = TomlQuote::None;
                }
                i += 1;
            }
            TomlQuote::MultiBasic => {
                if ch == '"' && chars.get(i + 1) == Some(&'"') && chars.get(i + 2) == Some(&'"') {
                    quote = TomlQuote::None;
                    i += 3;
                } else {
                    i += 1;
                }
            }
            TomlQuote::MultiLiteral => {
                if ch == '\'' && chars.get(i + 1) == Some(&'\'') && chars.get(i + 2) == Some(&'\'')
                {
                    quote = TomlQuote::None;
                    i += 3;
                } else {
                    i += 1;
                }
            }
        }
    }
    if quote == TomlQuote::Basic || quote == TomlQuote::Literal {
        return Err(number);
    }
    Ok(quote)
}

fn line_has_assignment(line: &str) -> bool {
    let chars: Vec<char> = line.chars().collect();
    let mut quote = TomlQuote::None;
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        match quote {
            TomlQuote::None => {
                if ch == '#' {
                    return false;
                } else if ch == '=' {
                    return true;
                } else if ch == '"' {
                    if chars.get(i + 1) == Some(&'"') && chars.get(i + 2) == Some(&'"') {
                        quote = TomlQuote::MultiBasic;
                        i += 3;
                    } else {
                        quote = TomlQuote::Basic;
                        i += 1;
                    }
                } else if ch == '\'' {
                    if chars.get(i + 1) == Some(&'\'') && chars.get(i + 2) == Some(&'\'') {
                        quote = TomlQuote::MultiLiteral;
                        i += 3;
                    } else {
                        quote = TomlQuote::Literal;
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            TomlQuote::Basic => {
                if ch == '\\' {
                    i += 2;
                } else {
                    if ch == '"' {
                        quote = TomlQuote::None;
                    }
                    i += 1;
                }
            }
            TomlQuote::Literal => {
                if ch == '\'' {
                    quote = TomlQuote::None;
                }
                i += 1;
            }
            TomlQuote::MultiBasic => {
                if ch == '"' && chars.get(i + 1) == Some(&'"') && chars.get(i + 2) == Some(&'"') {
                    quote = TomlQuote::None;
                    i += 3;
                } else {
                    i += 1;
                }
            }
            TomlQuote::MultiLiteral => {
                if ch == '\'' && chars.get(i + 1) == Some(&'\'') && chars.get(i + 2) == Some(&'\'')
                {
                    quote = TomlQuote::None;
                    i += 3;
                } else {
                    i += 1;
                }
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// 3. keys
// ---------------------------------------------------------------------------

fn check_keys(ctx: &DoctorContext) -> CheckResult {
    let path = &ctx.project_key_path;
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(_) => {
            return fail("keys", format!("project key missing: {}", path.display()));
        }
    };
    if !meta.is_file() {
        return fail(
            "keys",
            format!("project key is not a regular file: {}", path.display()),
        );
    }
    if meta.len() == 0 {
        return fail("keys", format!("project key is empty: {}", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return fail(
                "keys",
                format!("project key is group/world-readable: {}", path.display()),
            );
        }
        ok(
            "keys",
            format!(
                "project key present ({} bytes), permissions restricted",
                meta.len()
            ),
        )
    }
    #[cfg(not(unix))]
    {
        ok(
            "keys",
            format!(
                "project key present ({} bytes); permissions not checked on this platform",
                meta.len()
            ),
        )
    }
}

// ---------------------------------------------------------------------------
// 4. workers
// ---------------------------------------------------------------------------

fn check_workers(ctx: &DoctorContext) -> CheckResult {
    let Some(text) = ctx.workers_journal.text.as_deref() else {
        return warn(
            "workers",
            format!(
                "workers skipped: no readable journal at {}",
                ctx.workers_journal.path.display()
            ),
        );
    };
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(_) => {
            return fail(
                "workers",
                format!(
                    "workers journal malformed: {}",
                    ctx.workers_journal.path.display()
                ),
            );
        }
    };
    let Some(entries) = worker_entries(&value) else {
        return fail(
            "workers",
            format!(
                "workers journal has an unexpected shape: {}",
                ctx.workers_journal.path.display()
            ),
        );
    };
    if entries.is_empty() {
        return warn(
            "workers",
            format!(
                "workers journal has no records: {}",
                ctx.workers_journal.path.display()
            ),
        );
    }
    let mut states: BTreeMap<String, usize> = BTreeMap::new();
    let mut unknown = 0;
    for entry in &entries {
        let state = entry
            .get("status")
            .or_else(|| entry.get("state"))
            .and_then(serde_json::Value::as_str);
        match state {
            Some(state) => *states.entry(clean(state, 24)).or_default() += 1,
            None => unknown += 1,
        }
    }
    let mut summary: Vec<String> = states
        .into_iter()
        .map(|(state, count)| format!("{state}={count}"))
        .collect();
    if unknown > 0 {
        summary.push(format!("unknown={unknown}"));
    }
    ok(
        "workers",
        format!("{} workers; {}", entries.len(), summary.join(", ")),
    )
}

fn worker_entries(value: &serde_json::Value) -> Option<Vec<&serde_json::Value>> {
    if let Some(array) = value.as_array() {
        return Some(array.iter().collect());
    }
    let object = value.as_object()?;
    if let Some(list) = object.get("workers") {
        if let Some(array) = list.as_array() {
            return Some(array.iter().collect());
        }
        if let Some(map) = list.as_object() {
            return Some(map.values().collect());
        }
        return None;
    }
    // A bare journal object is a worker map only when every value is a record.
    if object.values().all(serde_json::Value::is_object) {
        Some(object.values().collect())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// 5. kernel
// ---------------------------------------------------------------------------

fn check_kernel(ctx: &DoctorContext) -> CheckResult {
    match ctx.kernel.state {
        KernelState::Running => match &ctx.kernel.socket {
            Some(socket) if socket.exists() => ok("kernel", "kernel running; socket present"),
            Some(socket) => fail(
                "kernel",
                format!("kernel running but socket missing: {}", socket.display()),
            ),
            None => warn("kernel", "kernel running; socket path unknown"),
        },
        KernelState::Stopped => match &ctx.kernel.socket {
            Some(socket) if socket.exists() => warn(
                "kernel",
                format!("kernel stopped; stale socket file: {}", socket.display()),
            ),
            _ => ok("kernel", "kernel stopped"),
        },
        KernelState::Unknown => warn("kernel", "kernel state unknown"),
    }
}

// ---------------------------------------------------------------------------
// 6. auth
// ---------------------------------------------------------------------------

fn check_auth(ctx: &DoctorContext) -> CheckResult {
    match &ctx.credential_backend {
        CredentialBackend::OsStore(name) => {
            ok("auth", format!("OS credential store: {}", clean(name, 40)))
        }
        CredentialBackend::EncryptedFile => warn(
            "auth",
            "encrypted-file fallback; OS credential store unavailable",
        ),
        CredentialBackend::Unavailable => fail("auth", "no credential backend available"),
        CredentialBackend::Unknown => warn("auth", "credential backend not probed"),
    }
}

// ---------------------------------------------------------------------------
// 7. network
// ---------------------------------------------------------------------------

fn check_network(ctx: &DoctorContext) -> CheckResult {
    let mut configured = Vec::new();
    let mut malformed = false;
    let mut illegal = false;
    for (label, value) in [
        ("proxy", &ctx.network.proxy),
        ("base URL", &ctx.network.base_url),
    ] {
        let Some(value) = value.as_deref().filter(|v| !v.trim().is_empty()) else {
            continue;
        };
        configured.push(label);
        match validate_url(value) {
            UrlState::Valid => {}
            UrlState::Malformed => malformed = true,
            UrlState::Illegal => illegal = true,
        }
    }
    if illegal {
        return fail(
            "network",
            "proxy or base URL contains whitespace or control characters",
        );
    }
    if malformed {
        return warn("network", "proxy or base URL is not a valid URL");
    }
    if ctx.network.offline {
        return warn(
            "network",
            "offline mode is enabled; network-dependent checks are limited",
        );
    }
    if configured.is_empty() {
        ok("network", "default endpoints; no proxy configured")
    } else {
        ok(
            "network",
            format!("{} configured; default endpoints", configured.join(" and ")),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UrlState {
    Valid,
    Malformed,
    Illegal,
}

fn validate_url(value: &str) -> UrlState {
    if value
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return UrlState::Illegal;
    }
    let lower = value.to_ascii_lowercase();
    let Some((scheme, rest)) = lower.split_once("://") else {
        return UrlState::Malformed;
    };
    if !matches!(scheme, "http" | "https" | "socks5" | "socks5h") {
        return UrlState::Malformed;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = if host.starts_with('[') {
        host.split(']').next().unwrap_or_default()
    } else {
        host.split(':').next().unwrap_or_default()
    };
    if host.is_empty() {
        return UrlState::Malformed;
    }
    UrlState::Valid
}

// ---------------------------------------------------------------------------
// 8. mesh
// ---------------------------------------------------------------------------

fn check_mesh(ctx: &DoctorContext) -> CheckResult {
    let Some(text) = ctx.mesh_registry.text.as_deref() else {
        return warn(
            "mesh",
            format!(
                "mesh skipped: no readable registry at {}",
                ctx.mesh_registry.path.display()
            ),
        );
    };
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(_) => {
            return fail(
                "mesh",
                format!(
                    "mesh registry malformed: {}",
                    ctx.mesh_registry.path.display()
                ),
            );
        }
    };
    let Some(count) = mesh_entry_count(&value) else {
        return fail(
            "mesh",
            format!(
                "mesh registry has an unexpected shape: {}",
                ctx.mesh_registry.path.display()
            ),
        );
    };
    if count == 0 {
        warn(
            "mesh",
            format!(
                "mesh registry is empty: {}",
                ctx.mesh_registry.path.display()
            ),
        )
    } else {
        ok(
            "mesh",
            format!(
                "mesh registry parses; {count} entries: {}",
                ctx.mesh_registry.path.display()
            ),
        )
    }
}

fn mesh_entry_count(value: &serde_json::Value) -> Option<usize> {
    if let Some(array) = value.as_array() {
        return Some(array.len());
    }
    let object = value.as_object()?;
    for key in ["devices", "peers", "nodes"] {
        if let Some(list) = object.get(key) {
            return list
                .as_array()
                .map(Vec::len)
                .or_else(|| list.as_object().map(|m| m.len()));
        }
    }
    Some(object.len())
}

// ---------------------------------------------------------------------------
// 9. ports
// ---------------------------------------------------------------------------

fn check_ports(ctx: &DoctorContext) -> CheckResult {
    let mut expected = ctx.ports.expected.clone();
    expected.sort_unstable();
    expected.dedup();
    let mut listening = ctx.ports.listening.clone();
    listening.sort_unstable();
    listening.dedup();

    if expected.is_empty() {
        return warn(
            "ports",
            format!(
                "ports skipped: no expected ports configured ({} listening)",
                listening.len()
            ),
        );
    }
    let missing: Vec<u16> = expected
        .iter()
        .copied()
        .filter(|port| !listening.contains(port))
        .collect();
    let extra: Vec<u16> = listening
        .iter()
        .copied()
        .filter(|port| !expected.contains(port))
        .collect();
    if !missing.is_empty() {
        let mut detail = format!("missing listening ports: {}", short_list(&missing, 8));
        if !extra.is_empty() {
            detail.push_str(&format!("; extra: {}", short_list(&extra, 8)));
        }
        return fail("ports", detail);
    }
    if !extra.is_empty() {
        return warn(
            "ports",
            format!("unexpected listening ports: {}", short_list(&extra, 8)),
        );
    }
    ok(
        "ports",
        format!("all {} expected ports listening", expected.len()),
    )
}

// ---------------------------------------------------------------------------
// 10. disk
// ---------------------------------------------------------------------------

fn check_disk(ctx: &DoctorContext) -> CheckResult {
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;
    let Some(disk) = ctx.disk else {
        return warn("disk", "disk skipped: free/total bytes not provided");
    };
    if disk.total_bytes == 0 {
        return fail("disk", "disk total is zero");
    }
    if disk.free_bytes > disk.total_bytes {
        return fail("disk", "disk snapshot inconsistent: free exceeds total");
    }
    if disk.free_bytes < DISK_FAIL_BYTES {
        return fail(
            "disk",
            format!("free space {} MiB, below 1 GiB", disk.free_bytes / MIB),
        );
    }
    if disk.free_bytes < DISK_WARN_BYTES {
        return warn(
            "disk",
            format!("free space {} GiB, below 5 GiB", disk.free_bytes / GIB),
        );
    }
    ok(
        "disk",
        format!(
            "{} GiB free of {} GiB",
            disk.free_bytes / GIB,
            disk.total_bytes / GIB
        ),
    )
}

// ---------------------------------------------------------------------------
// 11. locks
// ---------------------------------------------------------------------------

fn check_locks(ctx: &DoctorContext) -> CheckResult {
    let locks = &ctx.locks;
    if locks.entries.is_empty() {
        return ok("locks", "no lock files");
    }
    let stale: Vec<&Path> = locks
        .entries
        .iter()
        .filter(|entry| {
            entry
                .modified
                .is_some_and(|modified| age_exceeds(locks.now, modified, locks.stale_after))
        })
        .map(|entry| entry.path.as_path())
        .collect();
    let unknown = locks
        .entries
        .iter()
        .filter(|entry| entry.modified.is_none())
        .count();
    if stale.len() > 5 {
        let paths: Vec<String> = stale
            .iter()
            .take(3)
            .map(|path| path.display().to_string())
            .collect();
        return fail(
            "locks",
            format!(
                "{} stale locks; first: {}{}",
                stale.len(),
                paths.join(", "),
                if unknown > 0 {
                    format!("; {unknown} with unknown age")
                } else {
                    String::new()
                }
            ),
        );
    }
    if !stale.is_empty() {
        let paths: Vec<String> = stale
            .iter()
            .take(3)
            .map(|path| path.display().to_string())
            .collect();
        return warn(
            "locks",
            format!(
                "{} stale lock(s): {}{}",
                stale.len(),
                paths.join(", "),
                if unknown > 0 {
                    format!("; {unknown} with unknown age")
                } else {
                    String::new()
                }
            ),
        );
    }
    if unknown > 0 {
        return warn(
            "locks",
            format!(
                "{} lock file(s); {unknown} with unknown age",
                locks.entries.len()
            ),
        );
    }
    ok(
        "locks",
        format!("{} lock file(s); none stale", locks.entries.len()),
    )
}

fn age_exceeds(now: SystemTime, modified: SystemTime, limit: Duration) -> bool {
    now.duration_since(modified).is_ok_and(|age| age > limit)
}

// ---------------------------------------------------------------------------
// 12. journals
// ---------------------------------------------------------------------------

fn check_journals(ctx: &DoctorContext) -> CheckResult {
    if ctx.journals.is_empty() {
        return warn("journals", "journals skipped: none configured");
    }
    let mut records = 0usize;
    let mut bad: Vec<String> = Vec::new();
    let mut unreadable: Vec<String> = Vec::new();
    for path in &ctx.journals {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                for (index, line) in text.lines().enumerate() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    records += 1;
                    if serde_json::from_str::<serde_json::Value>(line).is_err() && bad.len() < 5 {
                        bad.push(format!("{}:{}", path.display(), index + 1));
                    }
                }
            }
            Err(_) => unreadable.push(path.display().to_string()),
        }
    }
    if !unreadable.is_empty() {
        return fail(
            "journals",
            format!("cannot read journal: {}", short_list(&unreadable, 3)),
        );
    }
    if !bad.is_empty() {
        return fail("journals", format!("invalid JSONL at {}", bad.join(", ")));
    }
    ok(
        "journals",
        format!("{records} records in {} journal(s)", ctx.journals.len()),
    )
}

// ---------------------------------------------------------------------------
// 13. MCP
// ---------------------------------------------------------------------------

fn check_mcp(ctx: &DoctorContext) -> CheckResult {
    let Some(text) = ctx.mcp_config.text.as_deref() else {
        return warn(
            "mcp",
            format!(
                "mcp skipped: no readable config at {}",
                ctx.mcp_config.path.display()
            ),
        );
    };
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(_) => {
            return fail(
                "mcp",
                format!(
                    "mcp config does not parse: {}",
                    ctx.mcp_config.path.display()
                ),
            );
        }
    };
    let Some(object) = value.as_object() else {
        return fail(
            "mcp",
            format!(
                "mcp config is not an object: {}",
                ctx.mcp_config.path.display()
            ),
        );
    };
    let Some(list) = object.get("servers").or_else(|| object.get("mcpServers")) else {
        return warn(
            "mcp",
            format!(
                "mcp config has no server list: {}",
                ctx.mcp_config.path.display()
            ),
        );
    };
    let Some(servers) = mcp_server_list(list) else {
        return fail(
            "mcp",
            format!(
                "mcp server list has an unexpected shape: {}",
                ctx.mcp_config.path.display()
            ),
        );
    };
    let mut invalid: Vec<String> = Vec::new();
    let mut secret: Vec<String> = Vec::new();
    for (name, entry) in &servers {
        let command_ok = entry
            .get("command")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|command| !command.trim().is_empty());
        let args_ok = match entry.get("args") {
            None => true,
            Some(args) => args
                .as_array()
                .is_some_and(|args| args.iter().all(serde_json::Value::is_string)),
        };
        if !command_ok || !args_ok {
            invalid.push(clean(name, 40));
        }
        if let Some(env) = entry.get("env").and_then(serde_json::Value::as_object) {
            if env.iter().any(|(key, value)| {
                looks_secret_key(key) || value.as_str().is_some_and(looks_secret_value)
            }) {
                secret.push(clean(name, 40));
            }
        }
    }
    if !invalid.is_empty() {
        return fail(
            "mcp",
            format!("invalid MCP server entries: {}", invalid.join(", ")),
        );
    }
    if !secret.is_empty() {
        return warn(
            "mcp",
            format!("inline secret-looking env for: {}", secret.join(", ")),
        );
    }
    ok("mcp", format!("{} MCP servers configured", servers.len()))
}

fn mcp_server_list(list: &serde_json::Value) -> Option<Vec<(String, &serde_json::Value)>> {
    if let Some(array) = list.as_array() {
        return Some(
            array
                .iter()
                .enumerate()
                .map(|(index, entry)| {
                    let name = entry
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .map(|name| name.to_string())
                        .unwrap_or_else(|| format!("server #{}", index + 1));
                    (name, entry)
                })
                .collect(),
        );
    }
    list.as_object().map(|map| {
        map.iter()
            .map(|(name, entry)| (name.clone(), entry))
            .collect()
    })
}

fn looks_secret_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "passwd",
        "api_key",
        "apikey",
        "authorization",
        "credential",
        "private_key",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn looks_secret_value(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    if lower.starts_with("sk-")
        || lower.starts_with("ghp_")
        || lower.starts_with("xox")
        || lower.starts_with("bearer ")
    {
        return true;
    }
    lower.len() >= 32
        && lower
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "+/=_-".contains(ch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn fixture(root: &Path) -> DoctorContext {
        DoctorContext {
            root: root.to_path_buf(),
            versions: VersionsSnapshot {
                zero_version: VERSION.to_string(),
                toolchain: Some("rustc 1.88.0 (fixture)".to_string()),
            },
            config: FileSnapshot::absent(root.join("config.toml")),
            project_key_path: root.join("key"),
            workers_journal: FileSnapshot::absent(root.join("workers.json")),
            kernel: KernelSnapshot {
                state: KernelState::Stopped,
                socket: None,
            },
            credential_backend: CredentialBackend::OsStore("fixture-store".to_string()),
            network: NetworkSnapshot::default(),
            mesh_registry: FileSnapshot::absent(root.join("registry.json")),
            ports: PortsSnapshot::default(),
            disk: None,
            locks: LocksSnapshot {
                entries: Vec::new(),
                stale_after: Duration::from_secs(60 * 60),
                now: UNIX_EPOCH + Duration::from_secs(1_000_000),
            },
            journals: Vec::new(),
            mcp_config: FileSnapshot::absent(root.join("mcp.json")),
        }
    }

    // -- versions ---------------------------------------------------------

    #[test]
    fn versions_pass_with_a_toolchain() {
        let dir = dir();
        let check = check_versions(&fixture(dir.path()));
        assert_eq!(check.name, "versions");
        assert_eq!(check.status, CheckStatus::Ok, "{}", check.detail);
    }

    #[test]
    fn versions_warn_without_a_toolchain() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.versions.toolchain = None;
        let check = check_versions(&ctx);
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(
            check.detail.contains("toolchain not detected"),
            "{}",
            check.detail
        );
    }

    #[test]
    fn versions_fail_without_a_zero_version() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.versions.zero_version = "  ".to_string();
        let check = check_versions(&ctx);
        assert_eq!(check.status, CheckStatus::Fail);
    }

    // -- config -----------------------------------------------------------

    #[test]
    fn config_pass_for_a_valid_toml_file() {
        let dir = dir();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[core]\nmodel = \"local\"\n[mesh]\nport = 7100\n").unwrap();
        let mut ctx = fixture(dir.path());
        ctx.config = FileSnapshot::read(&path);
        let check = check_config(&ctx);
        assert_eq!(check.status, CheckStatus::Ok, "{}", check.detail);
        assert!(check.detail.contains("config.toml"));
    }

    #[test]
    fn config_warn_when_the_file_is_absent() {
        let dir = dir();
        let check = check_config(&fixture(dir.path()));
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.detail.contains("skipped"), "{}", check.detail);
    }

    #[test]
    fn config_fail_reports_the_line_and_not_the_contents() {
        let dir = dir();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[core\nsecret_value = \"TOPSECRET\"\n").unwrap();
        let mut ctx = fixture(dir.path());
        ctx.config = FileSnapshot::read(&path);
        let check = check_config(&ctx);
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.detail.contains("line 1"), "{}", check.detail);
        assert!(!check.detail.contains("TOPSECRET"), "{}", check.detail);
    }

    #[test]
    fn config_fail_for_an_unterminated_string() {
        let dir = dir();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "model = \"local\n").unwrap();
        let mut ctx = fixture(dir.path());
        ctx.config = FileSnapshot::read(&path);
        let check = check_config(&ctx);
        assert_eq!(check.status, CheckStatus::Fail);
    }

    #[test]
    fn config_pass_for_a_multiline_array() {
        let dir = dir();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[core]\nmodels = [\n  \"local\",\n  \"remote\",\n]\n",
        )
        .unwrap();
        let mut ctx = fixture(dir.path());
        ctx.config = FileSnapshot::read(&path);
        let check = check_config(&ctx);
        assert_eq!(check.status, CheckStatus::Ok, "{}", check.detail);
    }

    // -- keys -------------------------------------------------------------

    #[cfg(unix)]
    fn restrict(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(not(unix))]
    fn restrict(_path: &Path) {}

    #[test]
    fn keys_pass_for_a_readable_non_empty_key() {
        let dir = dir();
        let path = dir.path().join("key");
        std::fs::write(&path, b"key-material").unwrap();
        restrict(&path);
        let check = check_keys(&fixture(dir.path()));
        assert_eq!(check.status, CheckStatus::Ok, "{}", check.detail);
        assert!(!check.detail.contains("key-material"));
    }

    #[test]
    fn keys_fail_when_missing() {
        let dir = dir();
        let check = check_keys(&fixture(dir.path()));
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.detail.contains("missing"), "{}", check.detail);
    }

    #[test]
    fn keys_fail_when_empty() {
        let dir = dir();
        let path = dir.path().join("key");
        std::fs::write(&path, b"").unwrap();
        restrict(&path);
        let check = check_keys(&fixture(dir.path()));
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.detail.contains("empty"), "{}", check.detail);
    }

    #[cfg(unix)]
    #[test]
    fn keys_fail_when_group_or_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = dir();
        let path = dir.path().join("key");
        std::fs::write(&path, b"key-material").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let check = check_keys(&fixture(dir.path()));
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.detail.contains("readable"), "{}", check.detail);
    }

    // -- workers ----------------------------------------------------------

    #[test]
    fn workers_pass_with_records() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.workers_journal = FileSnapshot::with_text(
            dir.path().join("workers.json"),
            r#"{"workers":[{"status":"running"},{"status":"stopped"}]}"#,
        );
        let check = check_workers(&ctx);
        assert_eq!(check.status, CheckStatus::Ok, "{}", check.detail);
        assert!(check.detail.contains("2 workers"), "{}", check.detail);
    }

    #[test]
    fn workers_warn_when_the_journal_is_empty() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.workers_journal =
            FileSnapshot::with_text(dir.path().join("workers.json"), r#"{"workers":[]}"#);
        let check = check_workers(&ctx);
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.detail.contains("no records"), "{}", check.detail);
    }

    #[test]
    fn workers_fail_on_malformed_json() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.workers_journal = FileSnapshot::with_text(dir.path().join("workers.json"), "not json");
        let check = check_workers(&ctx);
        assert_eq!(check.status, CheckStatus::Fail);
    }

    #[test]
    fn workers_fail_on_an_unexpected_shape() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.workers_journal =
            FileSnapshot::with_text(dir.path().join("workers.json"), r#"{"workers":5}"#);
        let check = check_workers(&ctx);
        assert_eq!(check.status, CheckStatus::Fail);
    }

    // -- kernel -----------------------------------------------------------

    #[test]
    fn kernel_pass_when_running_with_its_socket() {
        let dir = dir();
        let socket = dir.path().join("kernel.sock");
        std::fs::write(&socket, b"").unwrap();
        let mut ctx = fixture(dir.path());
        ctx.kernel = KernelSnapshot {
            state: KernelState::Running,
            socket: Some(socket),
        };
        let check = check_kernel(&ctx);
        assert_eq!(check.status, CheckStatus::Ok, "{}", check.detail);
    }

    #[test]
    fn kernel_fail_when_running_without_its_socket() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.kernel = KernelSnapshot {
            state: KernelState::Running,
            socket: Some(dir.path().join("missing.sock")),
        };
        let check = check_kernel(&ctx);
        assert_eq!(check.status, CheckStatus::Fail);
    }

    #[test]
    fn kernel_warn_when_state_is_unknown() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.kernel = KernelSnapshot {
            state: KernelState::Unknown,
            socket: None,
        };
        let check = check_kernel(&ctx);
        assert_eq!(check.status, CheckStatus::Warn);
    }

    #[test]
    fn kernel_warn_when_stopped_with_a_stale_socket() {
        let dir = dir();
        let socket = dir.path().join("kernel.sock");
        std::fs::write(&socket, b"").unwrap();
        let mut ctx = fixture(dir.path());
        ctx.kernel = KernelSnapshot {
            state: KernelState::Stopped,
            socket: Some(socket),
        };
        let check = check_kernel(&ctx);
        assert_eq!(check.status, CheckStatus::Warn);
    }

    // -- auth -------------------------------------------------------------

    #[test]
    fn auth_pass_for_the_os_store() {
        let dir = dir();
        let check = check_auth(&fixture(dir.path()));
        assert_eq!(check.status, CheckStatus::Ok, "{}", check.detail);
    }

    #[test]
    fn auth_warn_for_the_encrypted_fallback() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.credential_backend = CredentialBackend::EncryptedFile;
        let check = check_auth(&ctx);
        assert_eq!(check.status, CheckStatus::Warn);
    }

    #[test]
    fn auth_fail_when_no_backend_is_available() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.credential_backend = CredentialBackend::Unavailable;
        let check = check_auth(&ctx);
        assert_eq!(check.status, CheckStatus::Fail);
    }

    // -- network ----------------------------------------------------------

    #[test]
    fn network_pass_with_valid_endpoints() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.network.proxy = Some("http://127.0.0.1:7890".to_string());
        ctx.network.base_url = Some("https://api.example.com/v1".to_string());
        let check = check_network(&ctx);
        assert_eq!(check.status, CheckStatus::Ok, "{}", check.detail);
    }

    #[test]
    fn network_warn_for_a_malformed_url() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.network.proxy = Some("not-a-url".to_string());
        let check = check_network(&ctx);
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.detail.contains("not a valid URL"), "{}", check.detail);
    }

    #[test]
    fn network_warn_in_offline_mode() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.network.offline = true;
        let check = check_network(&ctx);
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.detail.contains("offline"), "{}", check.detail);
    }

    #[test]
    fn network_fail_for_illegal_url_characters() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.network.base_url = Some("https://api example.com".to_string());
        let check = check_network(&ctx);
        assert_eq!(check.status, CheckStatus::Fail);
    }

    // -- mesh -------------------------------------------------------------

    #[test]
    fn mesh_pass_with_registry_entries() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.mesh_registry = FileSnapshot::with_text(
            dir.path().join("registry.json"),
            r#"{"devices":{"device-secret-name":{"role":"peer"}}}"#,
        );
        let check = check_mesh(&ctx);
        assert_eq!(check.status, CheckStatus::Ok, "{}", check.detail);
        assert!(
            !check.detail.contains("device-secret-name"),
            "{}",
            check.detail
        );
    }

    #[test]
    fn mesh_warn_when_the_registry_is_empty() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.mesh_registry =
            FileSnapshot::with_text(dir.path().join("registry.json"), r#"{"devices":{}}"#);
        let check = check_mesh(&ctx);
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.detail.contains("empty"), "{}", check.detail);
    }

    #[test]
    fn mesh_fail_on_malformed_json() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.mesh_registry = FileSnapshot::with_text(dir.path().join("registry.json"), "{not json");
        let check = check_mesh(&ctx);
        assert_eq!(check.status, CheckStatus::Fail);
    }

    // -- ports ------------------------------------------------------------

    #[test]
    fn ports_pass_when_expectations_are_met() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.ports = PortsSnapshot {
            expected: vec![8080, 8081],
            listening: vec![8081, 8080],
        };
        let check = check_ports(&ctx);
        assert_eq!(check.status, CheckStatus::Ok, "{}", check.detail);
    }

    #[test]
    fn ports_warn_on_an_unexpected_listener() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.ports = PortsSnapshot {
            expected: vec![8080],
            listening: vec![8080, 9000],
        };
        let check = check_ports(&ctx);
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.detail.contains("9000"), "{}", check.detail);
    }

    #[test]
    fn ports_fail_when_an_expected_port_is_missing() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.ports = PortsSnapshot {
            expected: vec![8080, 8081],
            listening: vec![8080],
        };
        let check = check_ports(&ctx);
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.detail.contains("8081"), "{}", check.detail);
    }

    // -- disk -------------------------------------------------------------

    #[test]
    fn disk_pass_with_room_to_spare() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.disk = Some(DiskSnapshot {
            free_bytes: 50 * 1024 * 1024 * 1024,
            total_bytes: 100 * 1024 * 1024 * 1024,
        });
        let check = check_disk(&ctx);
        assert_eq!(check.status, CheckStatus::Ok, "{}", check.detail);
    }

    #[test]
    fn disk_warn_below_five_gib() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.disk = Some(DiskSnapshot {
            free_bytes: 3 * 1024 * 1024 * 1024,
            total_bytes: 100 * 1024 * 1024 * 1024,
        });
        let check = check_disk(&ctx);
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.detail.contains("3 GiB"), "{}", check.detail);
    }

    #[test]
    fn disk_fail_below_one_gib() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.disk = Some(DiskSnapshot {
            free_bytes: 512 * 1024 * 1024,
            total_bytes: 100 * 1024 * 1024 * 1024,
        });
        let check = check_disk(&ctx);
        assert_eq!(check.status, CheckStatus::Fail);
    }

    // -- locks ------------------------------------------------------------

    #[test]
    fn locks_pass_when_none_exist() {
        let dir = dir();
        let check = check_locks(&fixture(dir.path()));
        assert_eq!(check.status, CheckStatus::Ok, "{}", check.detail);
    }

    #[test]
    fn locks_warn_for_one_stale_lock() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        let now = ctx.locks.now;
        ctx.locks.entries = vec![LockEntry {
            path: dir.path().join("stale.lock"),
            modified: Some(now - Duration::from_secs(2 * 60 * 60)),
        }];
        let check = check_locks(&ctx);
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.detail.contains("stale.lock"), "{}", check.detail);
    }

    #[test]
    fn locks_fail_for_many_stale_locks() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        let now = ctx.locks.now;
        ctx.locks.entries = (0..6)
            .map(|index| LockEntry {
                path: dir.path().join(format!("stale-{index}.lock")),
                modified: Some(now - Duration::from_secs(2 * 60 * 60)),
            })
            .collect();
        let check = check_locks(&ctx);
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.detail.contains("6 stale"), "{}", check.detail);
    }

    // -- journals ---------------------------------------------------------

    #[test]
    fn journals_pass_for_valid_jsonl() {
        let dir = dir();
        let path = dir.path().join("turn.jsonl");
        std::fs::write(&path, "{\"turn\":1}\n{\"turn\":2}\n").unwrap();
        let mut ctx = fixture(dir.path());
        ctx.journals = vec![path];
        let check = check_journals(&ctx);
        assert_eq!(check.status, CheckStatus::Ok, "{}", check.detail);
        assert!(check.detail.contains("2 records"), "{}", check.detail);
    }

    #[test]
    fn journals_warn_when_none_are_configured() {
        let dir = dir();
        let check = check_journals(&fixture(dir.path()));
        assert_eq!(check.status, CheckStatus::Warn);
    }

    #[test]
    fn journals_fail_and_report_the_bad_line_number() {
        let dir = dir();
        let path = dir.path().join("turn.jsonl");
        std::fs::write(&path, "{\"turn\":1}\nnot-json\n").unwrap();
        let mut ctx = fixture(dir.path());
        ctx.journals = vec![path];
        let check = check_journals(&ctx);
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.detail.contains(":2"), "{}", check.detail);
    }

    // -- MCP --------------------------------------------------------------

    #[test]
    fn mcp_pass_for_a_valid_server() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.mcp_config = FileSnapshot::with_text(
            dir.path().join("mcp.json"),
            r#"{"servers":{"files":{"command":"npx","args":["-y","server-files"]}}}"#,
        );
        let check = check_mcp(&ctx);
        assert_eq!(check.status, CheckStatus::Ok, "{}", check.detail);
    }

    #[test]
    fn mcp_warn_for_a_secret_looking_env_without_echoing_it() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.mcp_config = FileSnapshot::with_text(
            dir.path().join("mcp.json"),
            r#"{"servers":{"files":{"command":"npx","args":[],"env":{"API_TOKEN":"sk-super-secret-value"}}}}"#,
        );
        let check = check_mcp(&ctx);
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.detail.contains("files"), "{}", check.detail);
        assert!(
            !check.detail.contains("sk-super-secret-value"),
            "{}",
            check.detail
        );
    }

    #[test]
    fn mcp_fail_when_a_server_has_no_command() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.mcp_config = FileSnapshot::with_text(
            dir.path().join("mcp.json"),
            r#"{"servers":{"broken":{"args":[]}}}"#,
        );
        let check = check_mcp(&ctx);
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.detail.contains("broken"), "{}", check.detail);
    }

    #[test]
    fn mcp_fail_on_malformed_json() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.mcp_config = FileSnapshot::with_text(dir.path().join("mcp.json"), "{not json");
        let check = check_mcp(&ctx);
        assert_eq!(check.status, CheckStatus::Fail);
    }

    #[test]
    fn mcp_fail_on_an_unexpected_server_list() {
        let dir = dir();
        let mut ctx = fixture(dir.path());
        ctx.mcp_config =
            FileSnapshot::with_text(dir.path().join("mcp.json"), r#"{"servers":"nope"}"#);
        let check = check_mcp(&ctx);
        assert_eq!(check.status, CheckStatus::Fail);
    }

    // -- report -----------------------------------------------------------

    #[test]
    fn every_named_check_runs_exactly_once_in_order() {
        let dir = dir();
        let report = run_core_with(&fixture(dir.path()));
        assert_eq!(report.checks.len(), CHECK_NAMES.len());
        let names: Vec<&str> = report
            .checks
            .iter()
            .map(|check| check.name.as_str())
            .collect();
        assert_eq!(names, CHECK_NAMES.as_slice());
    }

    #[test]
    fn the_core_is_independent_and_does_not_contact_the_daemon() {
        let dir = dir();
        let report = run_core_with(&fixture(dir.path()));
        assert!(report.independent);
        assert_eq!(report.daemon, DaemonStatus::NotContacted);
        assert_eq!(report.version, VERSION);
        assert_eq!(report.checks.len(), CHECK_NAMES.len());
    }

    #[test]
    fn human_output_names_the_version_and_the_dead_daemon() {
        let dir = dir();
        let text = run_core_with(&fixture(dir.path())).render_human();
        assert!(text.contains("zero-doctor 0.1.0"), "{text}");
        assert!(text.contains("daemon: not contacted"), "{text}");
        assert!(text.contains("checks: 13"), "{text}");
        assert!(text.contains("ok    versions"), "{text}");
    }

    #[test]
    fn the_default_root_captures_paths_without_panicking() {
        let dir = dir();
        let ctx = DoctorContext::from_root(dir.path());
        assert_eq!(
            ctx.config.path,
            dir.path().join(".zero").join("config.toml")
        );
        assert_eq!(ctx.project_key_path, dir.path().join(".zero").join("key"));
        assert_eq!(
            ctx.mesh_registry.path,
            dir.path().join(".zero").join("mesh").join("registry.json")
        );
        assert!(ctx.config.text.is_none());
        assert!(ctx.journals.is_empty());
        assert!(ctx.locks.entries.is_empty());
    }
}
