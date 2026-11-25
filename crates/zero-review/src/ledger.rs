//! Security-review mode gate, trust-boundary seeding, and coverage ledger.
//!
//! This module implements the checklist-first half of the security review
//! (SR-01, SR-02, SR-03):
//!
//! - [`gate`] decides whether a request is guidance, an audit, or a full
//!   report. A plain question never starts a full audit; guidance never runs a
//!   hunting wave.
//! - [`seed`] walks a bounded repository tree, classifies files into surfaces
//!   and subsystems, detects trust boundaries from content markers, and emits
//!   one [`LedgerUnit`] per applicable `(surface, boundary, subsystem, attack
//!   class)`.
//! - [`validate`] enforces the ledger invariants before any unit is assigned
//!   (SR-02). Every failure is a typed `zero.fnd.invalid_input` error that
//!   names the offending unit and never repeats file contents.
//!
//! Details are deliberately structural: paths, line numbers, and attack-class
//! names may appear; scanned file text never does.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Read;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, Result, ZeroError};

use crate::schema::{validate_history, CanonicalRef, UnitEvent};

/// Schema version written by [`seed`] and accepted by [`validate`].
pub const LEDGER_SCHEMA_VERSION: u32 = 1;

/// Canonical artifact name used by SR-06 when the ledger is written to disk.
pub const LEDGER_FILE: &str = "coverage-ledger.json";

/// Default cap on regular files visited by a seed walk.
pub const DEFAULT_MAX_FILES: usize = 512;
/// Default cap on directory depth visited by a seed walk.
pub const DEFAULT_MAX_DEPTH: usize = 8;
/// Default cap on bytes read from one file while scanning markers.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 256 * 1024;
/// Cap on canonical refs recorded per unit.
pub const MAX_REFS_PER_UNIT: usize = 8;
/// Cap on selected companions recorded per unit.
pub const MAX_COMPANIONS_PER_UNIT: usize = 16;
/// Cap on excluded companions recorded per unit before the orphan fallback.
pub const MAX_EXCLUSIONS_PER_UNIT: usize = 32;
/// Cap on trust-boundary evidence entries.
pub const MAX_BOUNDARY_EVIDENCE: usize = 16;

// ---------------------------------------------------------------------------
// Mode gate (SR-01)
// ---------------------------------------------------------------------------

/// What kind of security review the user asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewMode {
    /// Checklist only: the trust-boundary summary and a validated ledger.
    Guidance,
    /// Coverage-led hunting without derived report artifacts.
    Audit,
    /// Audit plus the derived report set (SR-14).
    FullReport,
}

impl ReviewMode {
    /// Stable wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            ReviewMode::Guidance => "guidance",
            ReviewMode::Audit => "audit",
            ReviewMode::FullReport => "full_report",
        }
    }
}

/// One ordered phase of a security review (SR-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Recon,
    CoverageHunt,
    Validation,
    Output,
    RecordVerification,
    Report,
}

impl Phase {
    /// Stable wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Phase::Recon => "recon",
            Phase::CoverageHunt => "coverage_hunt",
            Phase::Validation => "validation",
            Phase::Output => "output",
            Phase::RecordVerification => "record_verification",
            Phase::Report => "report",
        }
    }
}

/// The request as the user made it, before the gate narrows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRequest {
    pub mode: ReviewMode,
    /// True only when the user explicitly asked for an audit or full review.
    pub user_asked_for_audit: bool,
    /// True only when the user explicitly asked for report artifacts.
    pub wants_report_artifacts: bool,
}

impl Default for ReviewRequest {
    fn default() -> Self {
        Self {
            mode: ReviewMode::Guidance,
            user_asked_for_audit: false,
            wants_report_artifacts: false,
        }
    }
}

impl ReviewRequest {
    /// A plain, unspecified question. Always guidance.
    pub fn plain_question() -> Self {
        Self::default()
    }
}

/// The narrowed plan: the mode that will actually run and its ordered phases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewPlan {
    pub mode: ReviewMode,
    pub phases: Vec<Phase>,
    pub guidance_only: bool,
}

/// Apply the SR-01 mode gate.
///
/// Guidance is always guidance. An audit requires an explicit audit request
/// (`user_asked_for_audit`) or an explicit report-artifact request. A full
/// report additionally requires `wants_report_artifacts`; a full-report request
/// without that flag narrows to an audit. Anything else, including a plain
/// question that merely arrives with `mode = FullReport`, narrows to guidance.
pub fn gate(request: &ReviewRequest) -> ReviewPlan {
    let explicit = request.user_asked_for_audit || request.wants_report_artifacts;
    let mode = match request.mode {
        ReviewMode::Guidance => ReviewMode::Guidance,
        ReviewMode::Audit | ReviewMode::FullReport if explicit => {
            if request.wants_report_artifacts {
                ReviewMode::FullReport
            } else {
                ReviewMode::Audit
            }
        }
        _ => ReviewMode::Guidance,
    };
    ReviewPlan {
        mode,
        phases: phases_for(mode),
        guidance_only: mode == ReviewMode::Guidance,
    }
}

fn phases_for(mode: ReviewMode) -> Vec<Phase> {
    match mode {
        // The checklist is recon plus output; validation is part of producing
        // the ledger and needs no hunting wave.
        ReviewMode::Guidance => vec![Phase::Recon, Phase::Output],
        ReviewMode::Audit => vec![
            Phase::Recon,
            Phase::CoverageHunt,
            Phase::Validation,
            Phase::Output,
            Phase::RecordVerification,
        ],
        ReviewMode::FullReport => vec![
            Phase::Recon,
            Phase::CoverageHunt,
            Phase::Validation,
            Phase::Output,
            Phase::RecordVerification,
            Phase::Report,
        ],
    }
}

// ---------------------------------------------------------------------------
// Trust-boundary and ledger types (SR-03)
// ---------------------------------------------------------------------------

/// A review surface: a named part of the target with its starting files.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Surface {
    pub name: String,
    pub kind: String,
    pub starting_paths: Vec<String>,
}

/// A crossing from a lower-trust principal into a higher-trust one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustBoundary {
    pub name: String,
    pub lower_trust: String,
    pub higher_trust: String,
    /// Canonical `path:line` references that demonstrate the boundary.
    pub evidence: Vec<String>,
}

/// A companion file deliberately left out of a unit, with the reason.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExcludedCompanion {
    pub path: String,
    pub reason: String,
}

/// Lifecycle status of one ledger unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnitStatus {
    Pending,
    Assigned,
    Reviewed,
    Confirmed,
    Refuted,
    OutOfScope,
    Deferred,
    Blocked,
}

impl UnitStatus {
    /// Stable wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            UnitStatus::Pending => "pending",
            UnitStatus::Assigned => "assigned",
            UnitStatus::Reviewed => "reviewed",
            UnitStatus::Confirmed => "confirmed",
            UnitStatus::Refuted => "refuted",
            UnitStatus::OutOfScope => "out_of_scope",
            UnitStatus::Deferred => "deferred",
            UnitStatus::Blocked => "blocked",
        }
    }

    /// Statuses that need a named owner (SR-03).
    pub const fn requires_owner(self) -> bool {
        matches!(
            self,
            UnitStatus::Assigned
                | UnitStatus::Reviewed
                | UnitStatus::Confirmed
                | UnitStatus::Refuted
        )
    }

    /// Statuses that need reviewed paths.
    pub const fn requires_reviewed_paths(self) -> bool {
        matches!(self, UnitStatus::Reviewed | UnitStatus::Confirmed)
    }
}

/// A unit of review work: one attack class on one boundary inside one
/// surface and subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerUnit {
    pub id: String,
    pub surface: String,
    pub boundary: String,
    pub subsystem: String,
    pub attack_class: String,
    /// Canonical root-relative `path:line` references.
    pub refs: Vec<String>,
    /// Root-relative starting files for the unit.
    pub starting_paths: Vec<String>,
    pub selected_companions: Vec<String>,
    pub excluded_companions: Vec<ExcludedCompanion>,
    pub status: UnitStatus,
    /// Append-only status history. Empty for a freshly seeded unit.
    #[serde(default)]
    pub history: Vec<UnitEvent>,
    pub owner: String,
    pub reviewed_paths: Vec<String>,
    pub checks: Vec<String>,
    /// Stable hash of the unit's fields (FNV-1a 64, lowercase hex).
    pub fingerprint: String,
    /// Content fingerprint recorded when a confirmation is carried (SR-11).
    ///
    /// Absent in seeded artifacts and on units that were never confirmed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_fingerprint: Option<String>,
}

/// Counts and walk bounds recorded with a ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerSummary {
    pub units: usize,
    pub pending: usize,
    pub assigned: usize,
    pub reviewed: usize,
    pub confirmed: usize,
    pub refuted: usize,
    pub out_of_scope: usize,
    pub deferred: usize,
    pub blocked: usize,
    pub surfaces: usize,
    pub boundaries: usize,
    pub subsystems: usize,
    pub attack_classes: usize,
    pub files_scanned: usize,
    pub files_excluded: usize,
    pub files_size_capped: usize,
    pub walk_truncated: bool,
    pub truncation: Vec<String>,
    pub max_files: usize,
    pub max_depth: usize,
    pub max_file_bytes: u64,
}

/// The coverage ledger produced by seeding and consumed by validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageLedger {
    pub schema_version: u32,
    pub units: Vec<LedgerUnit>,
    pub summary: LedgerSummary,
}

/// Result of validating a ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationReport {
    pub units: usize,
    /// Reviewed plus confirmed. `out_of_scope` is never counted here.
    pub covered: usize,
    pub pending: usize,
    pub out_of_scope: usize,
    /// Truncation notes carried from the seed walk.
    pub warnings: Vec<String>,
}

/// A bounded seed walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeedLimits {
    pub max_files: usize,
    pub max_depth: usize,
    pub max_file_bytes: u64,
}

impl Default for SeedLimits {
    fn default() -> Self {
        Self {
            max_files: DEFAULT_MAX_FILES,
            max_depth: DEFAULT_MAX_DEPTH,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
        }
    }
}

/// Everything a seed produces: the ledger plus the boundary summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedReport {
    pub ledger: CoverageLedger,
    pub surfaces: Vec<Surface>,
    pub boundaries: Vec<TrustBoundary>,
}

// ---------------------------------------------------------------------------
// Attack classes
// ---------------------------------------------------------------------------

/// An applicable attack class detected from content markers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AttackClass {
    CommandInjection,
    PathTraversal,
    SsrfEgress,
    UnsafeDeserialization,
    Injection,
    CredentialExposure,
    MemorySafety,
    PermissionIssues,
}

impl AttackClass {
    /// All classes in declaration order.
    pub const ALL: [AttackClass; 8] = [
        AttackClass::CommandInjection,
        AttackClass::PathTraversal,
        AttackClass::SsrfEgress,
        AttackClass::UnsafeDeserialization,
        AttackClass::Injection,
        AttackClass::CredentialExposure,
        AttackClass::MemorySafety,
        AttackClass::PermissionIssues,
    ];

    /// Stable wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            AttackClass::CommandInjection => "command_injection",
            AttackClass::PathTraversal => "path_traversal",
            AttackClass::SsrfEgress => "ssrf_egress",
            AttackClass::UnsafeDeserialization => "unsafe_deserialization",
            AttackClass::Injection => "injection",
            AttackClass::CredentialExposure => "credential_exposure",
            AttackClass::MemorySafety => "memory_safety",
            AttackClass::PermissionIssues => "permission_issues",
        }
    }

    /// The class's trust boundary: `(name, lower trust, higher trust)`.
    const fn boundary(self) -> (&'static str, &'static str, &'static str) {
        match self {
            AttackClass::CommandInjection => (
                "process-exec",
                "repository content or model output",
                "operating-system process",
            ),
            AttackClass::PathTraversal => (
                "filesystem-path",
                "untrusted path component",
                "filesystem namespace",
            ),
            AttackClass::SsrfEgress => {
                ("network-egress", "local process", "remote network service")
            }
            AttackClass::UnsafeDeserialization => (
                "untrusted-input",
                "untrusted bytes or text",
                "parsed application data",
            ),
            AttackClass::Injection => (
                "database-query",
                "untrusted input string",
                "database engine",
            ),
            AttackClass::CredentialExposure => (
                "credential-store",
                "repository or configuration file",
                "credential secret",
            ),
            AttackClass::MemorySafety => ("memory-model", "safe Rust code", "raw memory"),
            AttackClass::PermissionIssues => (
                "permission-model",
                "unprivileged file",
                "filesystem metadata",
            ),
        }
    }

    /// Lowercase content markers. Matching is case-insensitive on the line.
    const fn markers(self) -> &'static [&'static str] {
        match self {
            AttackClass::CommandInjection => &[
                "command::new",
                "std::process",
                "subprocess.",
                "child_process",
                "os/exec",
                "runtime.getruntime().exec",
                "shell_exec",
                "popen(",
                "system(",
                "execve(",
                "spawn(",
            ],
            AttackClass::PathTraversal => &[
                "os.path.join",
                "path.join",
                "pathbuf",
                "path::new",
                "fs::read",
                "fs::write",
                "file::open",
                "file::create",
                "readfilesync",
                "writefilesync",
                "shutil.",
                "canonicalize(",
                "../",
            ],
            AttackClass::SsrfEgress => &[
                "reqwest",
                "tcpstream",
                "tokio::net",
                "hyper::client",
                "ureq",
                "axios",
                "fetch(",
                "urllib",
                "requests.get",
                "httpx",
                "http://",
                "https://",
                "net/http",
            ],
            AttackClass::UnsafeDeserialization => &[
                "from_str",
                "serde_json",
                "serde_yaml",
                "toml::from_str",
                "pickle",
                "yaml.load",
                "unserialize",
                "json.parse",
                "objectinputstream",
                "bincode",
                "deserialize",
                "marshalloads",
                "readobject(",
            ],
            AttackClass::Injection => &[
                "select ",
                "insert into",
                "update ",
                "delete from",
                "where ",
                "cursor.execute",
                ".query(",
                "db.execute",
                "prepare(",
                "sql!",
                "raw_sql",
                "executescript",
            ],
            AttackClass::CredentialExposure => &[
                "password",
                "passwd",
                "secret",
                "api_key",
                "apikey",
                "api-key",
                "access_token",
                "private_key",
                "privatekey",
                "credential",
                "authorization",
                "bearer ",
            ],
            AttackClass::MemorySafety => &[
                "unsafe ",
                "unsafe{",
                "transmute",
                "from_raw_parts",
                "as *mut",
                "as *const",
                "mem::uninitialized",
                "mem::zeroed",
                "set_len(",
                "get_unchecked",
            ],
            AttackClass::PermissionIssues => &[
                "chmod",
                "set_permissions",
                "permissions::from_mode",
                "permissionsset",
                "chown",
                "0o777",
                "0o666",
                "0o755",
                "umask",
                "setuid",
                "setgid",
                "setwritable",
                "os.chmod",
            ],
        }
    }

    /// Checks a reviewer must answer for this class.
    const fn checks(self) -> &'static [&'static str] {
        match self {
            AttackClass::CommandInjection => &[
                "untrusted input never reaches an argument list",
                "no shell-string interpolation",
                "the executable and arguments come from an allowlist",
            ],
            AttackClass::PathTraversal => &[
                "the path is canonicalized and confined to its root",
                "no parent component survives the join",
                "symlinks are rejected before use",
            ],
            AttackClass::SsrfEgress => &[
                "the destination is resolved once and pinned",
                "loopback, private, and metadata ranges are refused",
                "every redirect is re-checked",
            ],
            AttackClass::UnsafeDeserialization => &[
                "input is schema-validated with size limits",
                "unknown fields fail closed",
                "no executable object construction",
            ],
            AttackClass::Injection => &[
                "queries are parameterized",
                "no string concatenation into a statement",
                "identifiers come from an allowlist",
            ],
            AttackClass::CredentialExposure => &[
                "secrets are never logged or serialized",
                "values come from the credential store",
                "errors redact the value",
            ],
            AttackClass::MemorySafety => &[
                "every unsafe block documents its invariant",
                "lengths are bounds-checked",
                "raw pointers do not outlive their allocation",
            ],
            AttackClass::PermissionIssues => &[
                "created files use least privilege",
                "no world-writable bits",
                "ownership changes are explicit",
            ],
        }
    }
}

// ---------------------------------------------------------------------------
// Seeding
// ---------------------------------------------------------------------------

/// Seed a coverage ledger with the default bounds.
pub fn seed(root: impl AsRef<Path>) -> Result<CoverageLedger> {
    Ok(seed_report(root)?.ledger)
}

/// Seed a ledger and its trust-boundary summary with the default bounds.
pub fn seed_report(root: impl AsRef<Path>) -> Result<SeedReport> {
    seed_report_with_limits(root, &SeedLimits::default())
}

/// Seed a coverage ledger with explicit bounds.
pub fn seed_with_limits(root: impl AsRef<Path>, limits: &SeedLimits) -> Result<CoverageLedger> {
    Ok(seed_report_with_limits(root, limits)?.ledger)
}

/// Seed a ledger and boundary summary with explicit bounds.
pub fn seed_report_with_limits(root: impl AsRef<Path>, limits: &SeedLimits) -> Result<SeedReport> {
    if limits.max_files == 0 || limits.max_depth == 0 || limits.max_file_bytes == 0 {
        return Err(invalid("seed limits must all be greater than zero"));
    }
    let root = root.as_ref();
    let metadata = std::fs::metadata(root)?;
    if !metadata.is_dir() {
        return Err(invalid("review seed root is not a directory"));
    }
    let walk = walk_tree(root, limits)?;
    Ok(build_report(walk, limits))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SurfaceKind {
    Network,
    Parser,
    Process,
    Storage,
    Filesystem,
    Web,
    Credentials,
    Library,
}

impl SurfaceKind {
    fn classify(rel: &str) -> Self {
        let lower = rel.to_ascii_lowercase();
        let hits = |needles: &[&str]| needles.iter().any(|needle| lower.contains(needle));
        if hits(&["/net/", "network", "client", "http", "webhook", "api/"]) {
            SurfaceKind::Network
        } else if hits(&["parser", "parse", "decode", "deserialize", "serde"]) {
            SurfaceKind::Parser
        } else if hits(&["shell", "spawn", "process", "exec", "command", "cli"]) {
            SurfaceKind::Process
        } else if hits(&["db", "sql", "storage", "store", "database"]) {
            SurfaceKind::Storage
        } else if hits(&["fs/", "file", "filesystem", "/io/"]) {
            SurfaceKind::Filesystem
        } else if hits(&["web/", "ui/", "route", "handler", "server"]) {
            SurfaceKind::Web
        } else if hits(&["auth", "secret", "credential", "token", "crypto"]) {
            SurfaceKind::Credentials
        } else {
            SurfaceKind::Library
        }
    }

    const fn name(self) -> &'static str {
        match self {
            SurfaceKind::Network => "network",
            SurfaceKind::Parser => "parser",
            SurfaceKind::Process => "process",
            SurfaceKind::Storage => "storage",
            SurfaceKind::Filesystem => "filesystem",
            SurfaceKind::Web => "web",
            SurfaceKind::Credentials => "credentials",
            SurfaceKind::Library => "library",
        }
    }

    const fn kind(self) -> &'static str {
        match self {
            SurfaceKind::Network => "network",
            SurfaceKind::Parser => "parser",
            SurfaceKind::Process => "process",
            SurfaceKind::Storage => "storage",
            SurfaceKind::Filesystem => "filesystem",
            SurfaceKind::Web => "web",
            SurfaceKind::Credentials => "credentials",
            SurfaceKind::Library => "library",
        }
    }
}

#[derive(Debug)]
struct ScannedFile {
    rel: String,
    surface: SurfaceKind,
    subsystem: String,
    hits: Vec<(AttackClass, usize)>,
}

#[derive(Debug, Default)]
struct Walk {
    included: Vec<ScannedFile>,
    excluded: Vec<ExcludedCompanion>,
    files_size_capped: usize,
    truncation: Vec<String>,
}

fn walk_tree(root: &Path, limits: &SeedLimits) -> Result<Walk> {
    let mut walk = Walk::default();
    let mut seen = 0usize;
    visit_dir(root, root, 0, limits, &mut seen, &mut walk)?;
    walk.truncation.sort();
    walk.truncation.dedup();
    Ok(walk)
}

/// Returns `false` when the file cap stopped the walk.
fn visit_dir(
    root: &Path,
    dir: &Path,
    depth: usize,
    limits: &SeedLimits,
    seen: &mut usize,
    walk: &mut Walk,
) -> Result<bool> {
    let mut entries = std::fs::read_dir(dir)?
        .filter_map(|entry| entry.ok())
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        if *seen >= limits.max_files {
            walk.truncation
                .push(format!("file cap {} reached", limits.max_files));
            return Ok(false);
        }
        let path = entry.path();
        let Some(rel) = relative_path(root, &path) else {
            continue;
        };
        let name = entry.file_name().to_string_lossy().to_string();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => {
                walk.excluded.push(ExcludedCompanion {
                    path: rel,
                    reason: "unreadable directory entry".to_string(),
                });
                continue;
            }
        };

        if file_type.is_symlink() {
            walk.excluded.push(ExcludedCompanion {
                path: rel,
                reason: "symlink not followed".to_string(),
            });
            continue;
        }
        if file_type.is_dir() {
            if is_excluded_dir(&name) {
                walk.excluded.push(ExcludedCompanion {
                    path: rel,
                    reason: "vendored or generated directory".to_string(),
                });
                continue;
            }
            if depth + 1 > limits.max_depth {
                walk.truncation
                    .push(format!("max depth {} reached", limits.max_depth));
                continue;
            }
            if !visit_dir(root, &path, depth + 1, limits, seen, walk)? {
                return Ok(false);
            }
            continue;
        }
        if !file_type.is_file() {
            walk.excluded.push(ExcludedCompanion {
                path: rel,
                reason: "not a regular file".to_string(),
            });
            continue;
        }

        *seen += 1;
        if is_lock_file(&name) {
            walk.excluded.push(ExcludedCompanion {
                path: rel,
                reason: "lock file".to_string(),
            });
            continue;
        }
        if is_generated(&name, &rel) {
            walk.excluded.push(ExcludedCompanion {
                path: rel,
                reason: "generated file".to_string(),
            });
            continue;
        }
        if is_binary_name(&name) {
            walk.excluded.push(ExcludedCompanion {
                path: rel,
                reason: "binary file".to_string(),
            });
            continue;
        }
        if !is_scannable(&name) {
            walk.excluded.push(ExcludedCompanion {
                path: rel,
                reason: "not a source or configuration file".to_string(),
            });
            continue;
        }

        let bytes = match read_prefix(&path, limits.max_file_bytes) {
            Ok(bytes) => bytes,
            Err(_) => {
                walk.excluded.push(ExcludedCompanion {
                    path: rel,
                    reason: "unreadable file".to_string(),
                });
                continue;
            }
        };
        if bytes.contains(&0) {
            walk.excluded.push(ExcludedCompanion {
                path: rel,
                reason: "binary content".to_string(),
            });
            continue;
        }
        let length = std::fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
        if length > limits.max_file_bytes {
            walk.files_size_capped += 1;
        }
        let text = String::from_utf8_lossy(&bytes);
        let surface = SurfaceKind::classify(&rel);
        let subsystem = subsystem_of(&rel);
        let mut hits = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            for class in AttackClass::ALL {
                if class.markers().iter().any(|marker| lower.contains(marker)) {
                    hits.push((class, index + 1));
                }
            }
        }
        walk.included.push(ScannedFile {
            rel,
            surface,
            subsystem,
            hits,
        });
    }
    Ok(true)
}

fn read_prefix(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(limit).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn relative_path(root: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    let mut parts = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            _ => return None,
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

fn is_excluded_dir(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        ".git"
            | ".zero"
            | ".hg"
            | ".svn"
            | "node_modules"
            | "vendor"
            | "third_party"
            | "third-party"
            | "target"
            | "dist"
            | "build"
            | "__pycache__"
            | ".venv"
            | "venv"
            | ".tox"
    )
}

fn is_lock_file(name: &str) -> bool {
    matches!(
        name,
        "Cargo.lock"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "poetry.lock"
            | "Pipfile.lock"
            | "composer.lock"
            | "Gemfile.lock"
            | "go.sum"
    ) || Path::new(name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("lock"))
}

fn is_generated(name: &str, rel: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let rel_lower = rel.to_ascii_lowercase();
    lower.ends_with(".min.js")
        || lower.ends_with("_pb2.py")
        || lower.ends_with(".g.dart")
        || lower.ends_with(".generated.rs")
        || lower.ends_with(".gen.rs")
        || rel_lower.starts_with("generated/")
        || rel_lower.contains("/generated/")
}

fn is_binary_name(name: &str) -> bool {
    let ext = Path::new(name)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "bmp"
            | "ico"
            | "pdf"
            | "zip"
            | "gz"
            | "tar"
            | "7z"
            | "rar"
            | "exe"
            | "dll"
            | "so"
            | "dylib"
            | "bin"
            | "wasm"
            | "class"
            | "jar"
            | "pyc"
            | "o"
            | "a"
            | "obj"
            | "mp4"
            | "mp3"
            | "wav"
            | "woff"
            | "woff2"
            | "ttf"
            | "otf"
    )
}

fn is_scannable(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "dockerfile" | "makefile" | "cmakelists.txt" | "build.gradle" | "gemfile"
    ) || lower.starts_with(".env")
    {
        return true;
    }
    let ext = Path::new(name)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "rs" | "py"
            | "pyi"
            | "js"
            | "jsx"
            | "mjs"
            | "cjs"
            | "ts"
            | "tsx"
            | "go"
            | "java"
            | "kt"
            | "kts"
            | "cs"
            | "c"
            | "h"
            | "cc"
            | "cpp"
            | "hpp"
            | "rb"
            | "php"
            | "sh"
            | "bash"
            | "zsh"
            | "ps1"
            | "bat"
            | "cmd"
            | "lua"
            | "swift"
            | "scala"
            | "toml"
            | "yaml"
            | "yml"
            | "json"
            | "ini"
            | "cfg"
            | "env"
            | "sql"
            | "proto"
    )
}

fn subsystem_of(rel: &str) -> String {
    match rel.rsplit_once('/') {
        Some((parent, _)) => parent.to_string(),
        None => ".".to_string(),
    }
}

struct PendingUnit {
    surface: &'static str,
    boundary: &'static str,
    subsystem: String,
    class: AttackClass,
    refs: Vec<String>,
    starting_paths: Vec<String>,
    selected_companions: Vec<String>,
    excluded_companions: Vec<ExcludedCompanion>,
}

/// The fields hashed into a unit fingerprint.
struct FingerprintParts<'a> {
    surface: &'a str,
    boundary: &'a str,
    subsystem: &'a str,
    class: &'a str,
    refs: &'a [String],
    starting_paths: &'a [String],
    selected_companions: &'a [String],
    excluded_companions: &'a [ExcludedCompanion],
}

fn build_report(walk: Walk, limits: &SeedLimits) -> SeedReport {
    let mut surface_map: BTreeMap<&'static str, Surface> = BTreeMap::new();
    for file in &walk.included {
        let surface = surface_map
            .entry(file.surface.name())
            .or_insert_with(|| Surface {
                name: file.surface.name().to_string(),
                kind: file.surface.kind().to_string(),
                starting_paths: Vec::new(),
            });
        surface.starting_paths.push(file.rel.clone());
    }
    for surface in surface_map.values_mut() {
        surface.starting_paths.sort();
        surface.starting_paths.dedup();
    }

    let mut exclusion_map: BTreeMap<&'static str, Vec<ExcludedCompanion>> = BTreeMap::new();
    for excluded in &walk.excluded {
        exclusion_map
            .entry(SurfaceKind::classify(&excluded.path).name())
            .or_default()
            .push(excluded.clone());
    }
    for list in exclusion_map.values_mut() {
        list.sort();
        list.dedup();
    }

    #[derive(Default)]
    struct Draft {
        refs: BTreeSet<String>,
        paths: BTreeSet<String>,
    }

    let mut drafts: BTreeMap<(&'static str, &'static str, String, &'static str), Draft> =
        BTreeMap::new();
    for file in &walk.included {
        let mut by_class: BTreeMap<AttackClass, Vec<usize>> = BTreeMap::new();
        for (class, line) in &file.hits {
            by_class.entry(*class).or_default().push(*line);
        }
        for (class, lines) in by_class {
            let boundary = class.boundary().0;
            let key = (
                file.surface.name(),
                boundary,
                file.subsystem.clone(),
                class.as_str(),
            );
            let draft = drafts.entry(key).or_default();
            for line in lines {
                draft.refs.insert(format!("{}:{}", file.rel, line));
            }
            draft.paths.insert(file.rel.clone());
        }
    }

    let mut pending: Vec<PendingUnit> = Vec::new();
    for ((surface, boundary, subsystem, class_name), draft) in drafts {
        let Some(class) = AttackClass::ALL
            .iter()
            .copied()
            .find(|class| class.as_str() == class_name)
        else {
            continue;
        };
        let starting_paths: Vec<String> = draft.paths.into_iter().collect();
        let starting_set: BTreeSet<&str> = starting_paths.iter().map(String::as_str).collect();
        let refs: Vec<String> = draft.refs.into_iter().take(MAX_REFS_PER_UNIT).collect();
        let mut selected_companions: Vec<String> = walk
            .included
            .iter()
            .filter(|file| file.subsystem == subsystem && !starting_set.contains(file.rel.as_str()))
            .map(|file| file.rel.clone())
            .collect();
        selected_companions.sort();
        selected_companions.dedup();
        selected_companions.truncate(MAX_COMPANIONS_PER_UNIT);
        let mut excluded_companions = exclusion_map.get(surface).cloned().unwrap_or_default();
        excluded_companions.retain(|excluded| {
            !starting_set.contains(excluded.path.as_str())
                && !selected_companions
                    .iter()
                    .any(|selected| selected == &excluded.path)
        });
        excluded_companions.truncate(MAX_EXCLUSIONS_PER_UNIT);
        pending.push(PendingUnit {
            surface,
            boundary,
            subsystem,
            class,
            refs,
            starting_paths,
            selected_companions,
            excluded_companions,
        });
    }

    pending.sort_by(|left, right| {
        (
            left.surface,
            left.subsystem.as_str(),
            left.class.as_str(),
            left.boundary,
        )
            .cmp(&(
                right.surface,
                right.subsystem.as_str(),
                right.class.as_str(),
                right.boundary,
            ))
    });

    // Never drop an exclusion: anything not attached to a surface unit is
    // attached to the first unit, deterministically.
    let attached: BTreeSet<String> = pending
        .iter()
        .flat_map(|unit| unit.excluded_companions.iter().map(|ex| ex.path.clone()))
        .collect();
    let leftovers: Vec<ExcludedCompanion> = walk
        .excluded
        .iter()
        .filter(|excluded| !attached.contains(&excluded.path))
        .cloned()
        .collect();
    let mut truncation = walk.truncation.clone();
    if !leftovers.is_empty() {
        if let Some(first) = pending.first_mut() {
            for excluded in leftovers {
                if !first
                    .excluded_companions
                    .iter()
                    .any(|existing| existing.path == excluded.path)
                {
                    first.excluded_companions.push(excluded);
                }
            }
            first.excluded_companions.sort();
        } else {
            truncation.push(format!(
                "{} exclusion(s) have no unit to attach to",
                leftovers.len()
            ));
        }
    }

    let mut units = Vec::with_capacity(pending.len());
    let mut boundary_evidence: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
    for unit in &pending {
        let fingerprint = unit_fingerprint(FingerprintParts {
            surface: unit.surface,
            boundary: unit.boundary,
            subsystem: &unit.subsystem,
            class: unit.class.as_str(),
            refs: &unit.refs,
            starting_paths: &unit.starting_paths,
            selected_companions: &unit.selected_companions,
            excluded_companions: &unit.excluded_companions,
        });
        let id = unit_id(unit.surface, unit.class.as_str(), &fingerprint);
        let evidence = boundary_evidence.entry(unit.boundary).or_default();
        for reference in &unit.refs {
            evidence.insert(reference.clone());
        }
        units.push(LedgerUnit {
            id,
            surface: unit.surface.to_string(),
            boundary: unit.boundary.to_string(),
            subsystem: unit.subsystem.clone(),
            attack_class: unit.class.as_str().to_string(),
            refs: unit.refs.clone(),
            starting_paths: unit.starting_paths.clone(),
            selected_companions: unit.selected_companions.clone(),
            excluded_companions: unit.excluded_companions.clone(),
            status: UnitStatus::Pending,
            history: Vec::new(),
            owner: String::new(),
            reviewed_paths: Vec::new(),
            checks: unit
                .class
                .checks()
                .iter()
                .map(|check| format!("{}: {check}", unit.class.as_str()))
                .collect(),
            fingerprint,
            content_fingerprint: None,
        });
    }
    units.sort_by(|left, right| left.id.cmp(&right.id));

    let counts = StatusCounts::of(&units);
    let summary = LedgerSummary {
        units: units.len(),
        pending: counts.pending,
        assigned: counts.assigned,
        reviewed: counts.reviewed,
        confirmed: counts.confirmed,
        refuted: counts.refuted,
        out_of_scope: counts.out_of_scope,
        deferred: counts.deferred,
        blocked: counts.blocked,
        surfaces: distinct_count(units.iter().map(|unit| unit.surface.as_str())),
        boundaries: distinct_count(units.iter().map(|unit| unit.boundary.as_str())),
        subsystems: distinct_count(units.iter().map(|unit| unit.subsystem.as_str())),
        attack_classes: distinct_count(units.iter().map(|unit| unit.attack_class.as_str())),
        files_scanned: walk.included.len(),
        files_excluded: walk.excluded.len(),
        files_size_capped: walk.files_size_capped,
        walk_truncated: !truncation.is_empty(),
        truncation,
        max_files: limits.max_files,
        max_depth: limits.max_depth,
        max_file_bytes: limits.max_file_bytes,
    };

    let mut surfaces: Vec<Surface> = surface_map.into_values().collect();
    surfaces.sort_by(|left, right| left.name.cmp(&right.name));

    let mut boundaries: Vec<TrustBoundary> = boundary_evidence
        .into_iter()
        .map(|(name, evidence)| {
            let spec = AttackClass::ALL
                .iter()
                .find(|class| class.boundary().0 == name)
                .copied()
                .unwrap_or(AttackClass::MemorySafety);
            let (_, lower_trust, higher_trust) = spec.boundary();
            TrustBoundary {
                name: name.to_string(),
                lower_trust: lower_trust.to_string(),
                higher_trust: higher_trust.to_string(),
                evidence: evidence.into_iter().take(MAX_BOUNDARY_EVIDENCE).collect(),
            }
        })
        .collect();
    boundaries.sort_by(|left, right| left.name.cmp(&right.name));

    SeedReport {
        ledger: CoverageLedger {
            schema_version: LEDGER_SCHEMA_VERSION,
            units,
            summary,
        },
        surfaces,
        boundaries,
    }
}

fn distinct_count<'a>(values: impl Iterator<Item = &'a str>) -> usize {
    values.collect::<BTreeSet<&str>>().len()
}

fn unit_id(surface: &str, class: &str, fingerprint: &str) -> String {
    let suffix = fingerprint.get(..8).unwrap_or(fingerprint);
    format!("sr-{}-{}-{suffix}", slug(surface), slug(class))
}

fn slug(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "x".to_string()
    } else {
        trimmed.to_string()
    }
}

fn unit_fingerprint(parts: FingerprintParts<'_>) -> String {
    let FingerprintParts {
        surface,
        boundary,
        subsystem,
        class,
        refs,
        starting_paths,
        selected_companions,
        excluded_companions,
    } = parts;
    let mut canonical = String::new();
    for field in [surface, boundary, subsystem, class] {
        push_field(&mut canonical, field);
    }
    canonical.push('\u{1e}');
    for reference in refs {
        push_field(&mut canonical, reference);
    }
    canonical.push('\u{1e}');
    for path in starting_paths {
        push_field(&mut canonical, path);
    }
    canonical.push('\u{1e}');
    for path in selected_companions {
        push_field(&mut canonical, path);
    }
    canonical.push('\u{1e}');
    for excluded in excluded_companions {
        push_field(&mut canonical, &excluded.path);
        push_field(&mut canonical, &excluded.reason);
    }
    format!("{:016x}", fnv1a64(canonical.as_bytes()))
}

fn push_field(buffer: &mut String, value: &str) {
    let _ = write!(buffer, "{}:{value};", value.len());
}

pub(crate) fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

// ---------------------------------------------------------------------------
// Validation (SR-02)
// ---------------------------------------------------------------------------

/// Validate a ledger before any unit is assigned.
///
/// Every rejection is `zero.fnd.invalid_input`. Messages name the unit id and
/// the failed invariant; they never include scanned file text.
pub fn validate(ledger: &CoverageLedger) -> Result<ValidationReport> {
    if ledger.schema_version != LEDGER_SCHEMA_VERSION {
        return Err(invalid(format!(
            "coverage ledger schema version {} is not supported (expected {LEDGER_SCHEMA_VERSION})",
            ledger.schema_version
        )));
    }

    let mut ids: BTreeSet<&str> = BTreeSet::new();
    let mut tuples: BTreeSet<(&str, &str, &str, &str)> = BTreeSet::new();
    let mut status_counts = StatusCounts::default();

    for unit in &ledger.units {
        if unit.id.trim().is_empty() {
            return Err(invalid("coverage ledger has a unit with an empty id"));
        }
        if !ids.insert(unit.id.as_str()) {
            return Err(invalid(format!("duplicate unit id `{}`", unit.id)));
        }
        for (label, value) in [
            ("surface", unit.surface.as_str()),
            ("boundary", unit.boundary.as_str()),
            ("subsystem", unit.subsystem.as_str()),
            ("attack class", unit.attack_class.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(invalid(format!("unit `{}` has an empty {label}", unit.id)));
            }
        }
        if unit.refs.is_empty() {
            return Err(invalid(format!("unit `{}` has no refs", unit.id)));
        }
        let mut seen_refs: BTreeSet<CanonicalRef> = BTreeSet::new();
        for reference in &unit.refs {
            let parsed = CanonicalRef::parse(reference).map_err(|error| {
                invalid(format!(
                    "unit `{}` has an invalid ref `{}`: {}",
                    unit.id,
                    reference,
                    error.message()
                ))
            })?;
            if !seen_refs.insert(parsed) {
                return Err(invalid(format!(
                    "unit `{}` lists duplicate ref `{}`",
                    unit.id, reference
                )));
            }
        }
        if unit.starting_paths.is_empty() {
            return Err(invalid(format!("unit `{}` has no starting paths", unit.id)));
        }
        for path in &unit.starting_paths {
            if !is_root_relative(path) {
                return Err(invalid(format!(
                    "unit `{}` has a starting path that is not root-relative",
                    unit.id
                )));
            }
        }
        if unit.checks.is_empty() || unit.checks.iter().any(|check| check.trim().is_empty()) {
            return Err(invalid(format!("unit `{}` has an empty check", unit.id)));
        }
        if unit.fingerprint.len() != 16
            || !unit.fingerprint.chars().all(|ch| ch.is_ascii_hexdigit())
            || unit.fingerprint.chars().any(|ch| ch.is_ascii_uppercase())
        {
            return Err(invalid(format!(
                "unit `{}` has an invalid fingerprint",
                unit.id
            )));
        }
        if let Some(content) = &unit.content_fingerprint {
            if content.len() != 16
                || !content.chars().all(|ch| ch.is_ascii_hexdigit())
                || content.chars().any(|ch| ch.is_ascii_uppercase())
            {
                return Err(invalid(format!(
                    "unit `{}` has an invalid content fingerprint",
                    unit.id
                )));
            }
        }
        if unit.status.requires_owner() && unit.owner.trim().is_empty() {
            return Err(invalid(format!(
                "unit `{}` is {} but has no owner",
                unit.id,
                unit.status.as_str()
            )));
        }
        if unit.status.requires_reviewed_paths() && unit.reviewed_paths.is_empty() {
            return Err(invalid(format!(
                "unit `{}` is {} but lists no reviewed paths",
                unit.id,
                unit.status.as_str()
            )));
        }
        if unit.status == UnitStatus::OutOfScope && !unit.reviewed_paths.is_empty() {
            return Err(invalid(format!(
                "unit `{}` is out_of_scope and must not list reviewed paths",
                unit.id
            )));
        }
        validate_history(unit)?;

        let selected: BTreeSet<&str> = unit
            .selected_companions
            .iter()
            .map(String::as_str)
            .collect();
        if selected.len() != unit.selected_companions.len() {
            return Err(invalid(format!(
                "unit `{}` lists a duplicate selected companion",
                unit.id
            )));
        }
        if selected.iter().any(|path| !is_root_relative(path)) {
            return Err(invalid(format!(
                "unit `{}` has a selected companion that is not root-relative",
                unit.id
            )));
        }
        for excluded in &unit.excluded_companions {
            if excluded.path.trim().is_empty() {
                return Err(invalid(format!(
                    "unit `{}` has an excluded companion with an empty path",
                    unit.id
                )));
            }
            if excluded.reason.trim().is_empty() {
                return Err(invalid(format!(
                    "unit `{}` excludes `{}` without a reason",
                    unit.id, excluded.path
                )));
            }
            if !is_root_relative(&excluded.path) {
                return Err(invalid(format!(
                    "unit `{}` excludes a path that is not root-relative",
                    unit.id
                )));
            }
            if selected.contains(excluded.path.as_str())
                || unit
                    .starting_paths
                    .iter()
                    .any(|path| path == &excluded.path)
            {
                return Err(invalid(format!(
                    "unit `{}` both selects and excludes `{}`",
                    unit.id, excluded.path
                )));
            }
        }

        let key = (
            unit.surface.as_str(),
            unit.boundary.as_str(),
            unit.subsystem.as_str(),
            unit.attack_class.as_str(),
        );
        if !tuples.insert(key) {
            return Err(invalid(format!(
                "duplicate unit for {} / {} / {} / {} (`{}`)",
                unit.surface, unit.boundary, unit.subsystem, unit.attack_class, unit.id
            )));
        }
        status_counts.add(unit.status);
    }

    if ledger.summary.units != ledger.units.len() {
        return Err(invalid(format!(
            "summary counts {} units but the ledger has {}",
            ledger.summary.units,
            ledger.units.len()
        )));
    }
    if let Some((field, recorded, actual)) = ledger.summary.status_mismatch(&status_counts) {
        return Err(invalid(format!(
            "summary records {recorded} {field} units but the ledger has {actual}"
        )));
    }
    for (field, recorded, actual) in [
        (
            "surface",
            ledger.summary.surfaces,
            distinct_count(ledger.units.iter().map(|unit| unit.surface.as_str())),
        ),
        (
            "boundary",
            ledger.summary.boundaries,
            distinct_count(ledger.units.iter().map(|unit| unit.boundary.as_str())),
        ),
        (
            "subsystem",
            ledger.summary.subsystems,
            distinct_count(ledger.units.iter().map(|unit| unit.subsystem.as_str())),
        ),
        (
            "attack class",
            ledger.summary.attack_classes,
            distinct_count(ledger.units.iter().map(|unit| unit.attack_class.as_str())),
        ),
    ] {
        if recorded != actual {
            return Err(invalid(format!(
                "summary records {recorded} {field} counts but the ledger has {actual}"
            )));
        }
    }

    let attached: BTreeSet<&str> = ledger
        .units
        .iter()
        .flat_map(|unit| unit.excluded_companions.iter().map(|ex| ex.path.as_str()))
        .collect();
    if attached.len() > ledger.summary.files_excluded {
        return Err(invalid(format!(
            "summary records {} exclusions but the ledger attaches {}",
            ledger.summary.files_excluded,
            attached.len()
        )));
    }
    if attached.len() < ledger.summary.files_excluded && ledger.summary.truncation.is_empty() {
        return Err(invalid(format!(
            "{} exclusion(s) are not attached to any unit and no truncation is reported",
            ledger.summary.files_excluded - attached.len()
        )));
    }
    if ledger.summary.walk_truncated && ledger.summary.truncation.is_empty() {
        return Err(invalid(
            "summary reports truncation but names no truncated bound",
        ));
    }
    if !ledger.summary.walk_truncated && !ledger.summary.truncation.is_empty() {
        return Err(invalid(
            "summary names truncation without setting walk_truncated",
        ));
    }
    if ledger.summary.max_files == 0
        || ledger.summary.max_depth == 0
        || ledger.summary.max_file_bytes == 0
    {
        return Err(invalid("summary records a zero walk bound"));
    }

    Ok(ValidationReport {
        units: ledger.units.len(),
        covered: status_counts.reviewed + status_counts.confirmed,
        pending: status_counts.pending,
        out_of_scope: status_counts.out_of_scope,
        warnings: ledger.summary.truncation.clone(),
    })
}

impl CoverageLedger {
    /// Assign one unit to an owner. The ledger is validated first (SR-02).
    pub fn assign(&mut self, unit_id: &str, owner: &str) -> Result<()> {
        validate(self)?;
        let owner = owner.trim();
        if owner.is_empty() {
            return Err(invalid("owner must not be empty"));
        }
        let unit = self
            .units
            .iter_mut()
            .find(|unit| unit.id == unit_id)
            .ok_or_else(|| invalid(format!("unknown unit id `{unit_id}`")))?;
        match unit.status {
            UnitStatus::Assigned => {
                unit.owner = owner.to_string();
            }
            UnitStatus::Pending | UnitStatus::Deferred | UnitStatus::Blocked => {
                let now_ms = crate::schema::unix_now_ms()
                    .max(unit.history.last().map_or(0, |event| event.at_ms));
                crate::schema::advance(unit, UnitStatus::Assigned, owner, None, now_ms)?;
            }
            UnitStatus::Reviewed | UnitStatus::Confirmed | UnitStatus::Refuted => {
                return Err(invalid(format!(
                    "unit `{unit_id}` is already {} and cannot be reassigned",
                    unit.status.as_str()
                )));
            }
            UnitStatus::OutOfScope => {
                return Err(invalid(format!(
                    "unit `{unit_id}` is out_of_scope and cannot be assigned"
                )));
            }
        }
        StatusCounts::of(&self.units).write_into(&mut self.summary);
        Ok(())
    }

    /// Advance one unit through the status matrix (SR-03).
    ///
    /// The transition is appended to the unit's history and the status counts
    /// are refreshed. Call [`validate`] afterwards to enforce the ledger-wide
    /// invariants (an owner, reviewed paths, and summary counts).
    pub fn advance(
        &mut self,
        unit_id: &str,
        to: UnitStatus,
        actor: &str,
        note: Option<&str>,
        now_ms: u64,
    ) -> Result<()> {
        let unit = self
            .units
            .iter_mut()
            .find(|unit| unit.id == unit_id)
            .ok_or_else(|| invalid(format!("unknown unit id `{unit_id}`")))?;
        crate::schema::advance(unit, to, actor, note, now_ms)?;
        StatusCounts::of(&self.units).write_into(&mut self.summary);
        Ok(())
    }

    /// Parse and validate a ledger artifact (SR-06).
    pub fn from_json_str(text: &str) -> Result<Self> {
        let ledger: Self = serde_json::from_str(text)?;
        validate(&ledger)?;
        Ok(ledger)
    }

    /// Serialize the ledger artifact (SR-06).
    pub fn to_json_pretty(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct StatusCounts {
    pending: usize,
    assigned: usize,
    reviewed: usize,
    confirmed: usize,
    refuted: usize,
    out_of_scope: usize,
    deferred: usize,
    blocked: usize,
}

impl StatusCounts {
    fn of(units: &[LedgerUnit]) -> Self {
        let mut counts = Self::default();
        for unit in units {
            counts.add(unit.status);
        }
        counts
    }

    fn add(&mut self, status: UnitStatus) {
        match status {
            UnitStatus::Pending => self.pending += 1,
            UnitStatus::Assigned => self.assigned += 1,
            UnitStatus::Reviewed => self.reviewed += 1,
            UnitStatus::Confirmed => self.confirmed += 1,
            UnitStatus::Refuted => self.refuted += 1,
            UnitStatus::OutOfScope => self.out_of_scope += 1,
            UnitStatus::Deferred => self.deferred += 1,
            UnitStatus::Blocked => self.blocked += 1,
        }
    }

    fn write_into(self, summary: &mut LedgerSummary) {
        summary.pending = self.pending;
        summary.assigned = self.assigned;
        summary.reviewed = self.reviewed;
        summary.confirmed = self.confirmed;
        summary.refuted = self.refuted;
        summary.out_of_scope = self.out_of_scope;
        summary.deferred = self.deferred;
        summary.blocked = self.blocked;
    }
}

impl LedgerSummary {
    fn status_mismatch(&self, counts: &StatusCounts) -> Option<(&'static str, usize, usize)> {
        [
            ("pending", self.pending, counts.pending),
            ("assigned", self.assigned, counts.assigned),
            ("reviewed", self.reviewed, counts.reviewed),
            ("confirmed", self.confirmed, counts.confirmed),
            ("refuted", self.refuted, counts.refuted),
            ("out_of_scope", self.out_of_scope, counts.out_of_scope),
            ("deferred", self.deferred, counts.deferred),
            ("blocked", self.blocked, counts.blocked),
        ]
        .into_iter()
        .find(|(_, recorded, actual)| recorded != actual)
    }
}

fn is_root_relative(path: &str) -> bool {
    !path.trim().is_empty()
        && !path.starts_with('/')
        && !path.starts_with('\\')
        && !path.contains('\\')
        && !Path::new(path).is_absolute()
        && !path.split('/').any(|part| part == "..")
}

pub(crate) fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        write(
            dir.path(),
            "src/parser.rs",
            "pub fn parse(input: &str) -> serde_json::Value {\n    serde_json::from_str(input).expect(\"json\")\n}\n",
        );
        write(
            dir.path(),
            "src/shell.rs",
            "use std::process::Command;\n\npub fn run(argv: &[String]) {\n    Command::new(\"sh\").args(argv).spawn().expect(\"spawn\");\n}\n",
        );
        write(
            dir.path(),
            "src/files.rs",
            "use std::path::Path;\n\npub fn write(path: &Path, data: &[u8]) {\n    std::fs::write(path, data).expect(\"write\");\n}\n",
        );
        write(
            dir.path(),
            "src/client.rs",
            "pub fn fetch(url: &str) -> Result<String, reqwest::Error> {\n    reqwest::blocking::get(url)?.text()\n}\n",
        );
        write(
            dir.path(),
            "src/config.rs",
            "pub const API_PASSWORD: &str = \"change-me\";\n",
        );
        write(
            dir.path(),
            "src/lib.rs",
            "pub mod client;\npub mod config;\npub mod files;\npub mod parser;\npub mod shell;\n",
        );
        write(dir.path(), "Cargo.lock", "version = 3\n");
        write(dir.path(), "target/generated.rs", "pub fn generated() {}\n");
        write(dir.path(), "assets/logo.png", "\u{0}PNG\n");
        write(dir.path(), "README.md", "# fixture\n");
        dir
    }

    fn write(root: &Path, rel: &str, contents: &str) {
        let path = root.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    fn seeded() -> (tempfile::TempDir, CoverageLedger) {
        let dir = fixture();
        let ledger = seed(dir.path()).expect("seed");
        (dir, ledger)
    }

    fn issue(code: ErrorCode, message: &str) -> bool {
        code == ErrorCode::InvalidInput && !message.trim().is_empty()
    }

    // -- mode gate --------------------------------------------------------

    #[test]
    fn guidance_is_the_default_and_never_hunts() {
        let plan = gate(&ReviewRequest::plain_question());
        assert_eq!(plan.mode, ReviewMode::Guidance);
        assert!(plan.guidance_only);
        assert_eq!(plan.phases, vec![Phase::Recon, Phase::Output]);
        assert!(!plan.phases.contains(&Phase::CoverageHunt));
        assert!(!plan.phases.contains(&Phase::Validation));
        assert!(!plan.phases.contains(&Phase::Report));
    }

    #[test]
    fn an_unrequested_audit_narrows_to_guidance() {
        let request = ReviewRequest {
            mode: ReviewMode::Audit,
            ..ReviewRequest::default()
        };
        let plan = gate(&request);
        assert_eq!(plan.mode, ReviewMode::Guidance);
        assert!(plan.guidance_only);
        assert!(!plan.phases.contains(&Phase::CoverageHunt));

        let plain_full_report = ReviewRequest {
            mode: ReviewMode::FullReport,
            user_asked_for_audit: false,
            wants_report_artifacts: false,
        };
        let plan = gate(&plain_full_report);
        assert_eq!(plan.mode, ReviewMode::Guidance);
        assert!(plan.guidance_only);
        assert!(!plan.phases.contains(&Phase::Report));
    }

    #[test]
    fn an_explicit_audit_runs_the_hunting_phases() {
        let request = ReviewRequest {
            mode: ReviewMode::Audit,
            user_asked_for_audit: true,
            wants_report_artifacts: false,
        };
        let plan = gate(&request);
        assert_eq!(plan.mode, ReviewMode::Audit);
        assert!(!plan.guidance_only);
        assert_eq!(
            plan.phases,
            vec![
                Phase::Recon,
                Phase::CoverageHunt,
                Phase::Validation,
                Phase::Output,
                Phase::RecordVerification,
            ]
        );
        assert!(!plan.phases.contains(&Phase::Report));
    }

    #[test]
    fn report_artifacts_select_the_full_path() {
        let request = ReviewRequest {
            mode: ReviewMode::FullReport,
            user_asked_for_audit: true,
            wants_report_artifacts: true,
        };
        let plan = gate(&request);
        assert_eq!(plan.mode, ReviewMode::FullReport);
        assert!(!plan.guidance_only);
        assert_eq!(
            plan.phases,
            vec![
                Phase::Recon,
                Phase::CoverageHunt,
                Phase::Validation,
                Phase::Output,
                Phase::RecordVerification,
                Phase::Report,
            ]
        );
    }

    #[test]
    fn a_full_report_request_without_artifacts_narrows_to_an_audit() {
        let request = ReviewRequest {
            mode: ReviewMode::FullReport,
            user_asked_for_audit: true,
            wants_report_artifacts: false,
        };
        let plan = gate(&request);
        assert_eq!(plan.mode, ReviewMode::Audit);
        assert!(!plan.phases.contains(&Phase::Report));
    }

    // -- seeding ----------------------------------------------------------

    #[test]
    fn fixture_repo_produces_a_valid_ledger() {
        let (_dir, ledger) = seeded();
        let report = validate(&ledger).expect("seeded ledger validates");
        assert_eq!(ledger.summary.units, ledger.units.len());
        assert_eq!(report.units, ledger.units.len());
        assert_eq!(report.covered, 0);
        assert!(ledger.summary.files_scanned >= 5);
        assert!(ledger.summary.files_excluded >= 3);
        assert!(!ledger.summary.walk_truncated);
        for unit in &ledger.units {
            assert_eq!(unit.status, UnitStatus::Pending);
            assert!(unit.owner.is_empty());
            assert!(unit.reviewed_paths.is_empty());
            assert!(!unit.refs.is_empty());
            assert!(!unit.checks.is_empty());
            assert_eq!(unit.fingerprint.len(), 16);
        }
    }

    #[test]
    fn fixture_repo_detects_the_expected_boundaries_and_attack_classes() {
        let dir = fixture();
        let report = seed_report(dir.path()).expect("seed");
        let boundaries: BTreeSet<&str> = report
            .boundaries
            .iter()
            .map(|boundary| boundary.name.as_str())
            .collect();
        for expected in [
            "process-exec",
            "filesystem-path",
            "network-egress",
            "untrusted-input",
            "credential-store",
        ] {
            assert!(boundaries.contains(expected), "missing boundary {expected}");
        }
        let classes: BTreeSet<&str> = report
            .ledger
            .units
            .iter()
            .map(|unit| unit.attack_class.as_str())
            .collect();
        for expected in [
            "command_injection",
            "path_traversal",
            "ssrf_egress",
            "unsafe_deserialization",
            "credential_exposure",
        ] {
            assert!(classes.contains(expected), "missing class {expected}");
        }
        assert!(
            report
                .surfaces
                .iter()
                .any(|surface| surface.name == "parser"),
            "parser surface missing"
        );
        assert!(
            report
                .surfaces
                .iter()
                .any(|surface| surface.name == "network"),
            "network surface missing"
        );
        assert!(
            report.ledger.units.iter().any(|unit| unit
                .excluded_companions
                .iter()
                .any(|ex| ex.reason == "lock file")
                || unit
                    .excluded_companions
                    .iter()
                    .any(|ex| ex.reason == "binary file")),
            "exclusions are not attached to any unit"
        );
    }

    #[test]
    fn two_seeds_of_the_same_tree_are_identical() {
        let dir = fixture();
        let first = seed(dir.path()).expect("first seed");
        let second = seed(dir.path()).expect("second seed");
        assert_eq!(first, second);
        let ids: BTreeSet<&str> = first.units.iter().map(|unit| unit.id.as_str()).collect();
        let fingerprints: BTreeSet<&str> = first
            .units
            .iter()
            .map(|unit| unit.fingerprint.as_str())
            .collect();
        assert_eq!(ids.len(), first.units.len());
        assert_eq!(fingerprints.len(), first.units.len());
    }

    #[test]
    fn a_tree_over_the_file_cap_truncates_and_reports() {
        let dir = tempfile::tempdir().unwrap();
        for index in 0..6 {
            write(
                dir.path(),
                &format!("src/run{index}.rs"),
                "pub fn run() { let _ = std::process::Command::new(\"sh\"); }\n",
            );
        }
        let limits = SeedLimits {
            max_files: 2,
            max_depth: 8,
            max_file_bytes: 4096,
        };
        let report = seed_report_with_limits(dir.path(), &limits).expect("seed");
        assert!(report.ledger.summary.walk_truncated);
        assert!(
            report
                .ledger
                .summary
                .truncation
                .iter()
                .any(|note| note.contains("file cap")),
            "truncation does not name the file cap: {:?}",
            report.ledger.summary.truncation
        );
        assert_eq!(report.ledger.summary.files_scanned, 2);
        validate(&report.ledger).expect("truncated ledger still validates");
    }

    #[test]
    fn depth_cap_truncates_and_reports() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "a/b/c/deep.rs",
            "pub fn run() { let _ = std::process::Command::new(\"sh\"); }\n",
        );
        let limits = SeedLimits {
            max_files: 16,
            max_depth: 1,
            max_file_bytes: 4096,
        };
        let report = seed_report_with_limits(dir.path(), &limits).expect("seed");
        assert!(report.ledger.summary.walk_truncated);
        assert!(report
            .ledger
            .summary
            .truncation
            .iter()
            .any(|note| note.contains("max depth")));
        assert_eq!(report.ledger.summary.files_scanned, 0);
    }

    // -- validation -------------------------------------------------------

    #[test]
    fn duplicate_unit_id_is_rejected() {
        let (_dir, mut ledger) = seeded();
        let duplicate = ledger.units[0].clone();
        ledger.units.push(duplicate);
        ledger.summary.units = ledger.units.len();
        let error = validate(&ledger).expect_err("duplicate id");
        assert!(issue(error.code(), error.message()));
        assert!(error.message().contains("duplicate unit id"));
    }

    #[test]
    fn empty_refs_are_rejected() {
        let (_dir, mut ledger) = seeded();
        let id = ledger.units[0].id.clone();
        ledger.units[0].refs.clear();
        let error = validate(&ledger).expect_err("empty refs");
        assert!(issue(error.code(), error.message()));
        assert!(error.message().contains(&id));
        assert!(error.message().contains("no refs"));
    }

    #[test]
    fn missing_exclusion_reason_is_rejected() {
        let (_dir, mut ledger) = seeded();
        let index = ledger
            .units
            .iter()
            .position(|unit| !unit.excluded_companions.is_empty())
            .expect("fixture attaches exclusions");
        let id = ledger.units[index].id.clone();
        ledger.units[index].excluded_companions[0].reason = "  ".to_string();
        let error = validate(&ledger).expect_err("missing reason");
        assert!(issue(error.code(), error.message()));
        assert!(error.message().contains(&id));
        assert!(error.message().contains("without a reason"));
    }

    #[test]
    fn the_same_path_cannot_be_selected_and_excluded() {
        let (_dir, mut ledger) = seeded();
        let id = ledger.units[0].id.clone();
        let path = ledger.units[0].starting_paths[0].clone();
        ledger.units[0].excluded_companions.push(ExcludedCompanion {
            path,
            reason: "fixture".to_string(),
        });
        let error = validate(&ledger).expect_err("overlap");
        assert!(issue(error.code(), error.message()));
        assert!(error.message().contains(&id));
        assert!(error.message().contains("both selects and excludes"));
    }

    #[test]
    fn out_of_scope_is_never_counted_as_covered() {
        let (_dir, mut ledger) = seeded();
        let id = ledger.units[0].id.clone();
        let path = ledger.units[0].starting_paths[0].clone();
        ledger.units[0].status = UnitStatus::OutOfScope;
        ledger.units[0].reviewed_paths = vec![path];
        ledger.summary.pending -= 1;
        ledger.summary.out_of_scope += 1;
        let error = validate(&ledger).expect_err("out_of_scope cannot be reviewed");
        assert!(issue(error.code(), error.message()));
        assert!(error.message().contains(&id));
        assert!(error.message().contains("out_of_scope"));

        // A well-formed out_of_scope unit stays out of the covered count.
        ledger.units[0].reviewed_paths.clear();
        let report = validate(&ledger).expect("out_of_scope alone is valid");
        assert_eq!(report.out_of_scope, 1);
        assert_eq!(report.covered, 0);
    }

    #[test]
    fn assigned_unit_without_owner_is_rejected() {
        let (_dir, mut ledger) = seeded();
        let id = ledger.units[0].id.clone();
        ledger.units[0].status = UnitStatus::Assigned;
        ledger.summary.pending -= 1;
        ledger.summary.assigned += 1;
        let error = validate(&ledger).expect_err("assigned without owner");
        assert!(issue(error.code(), error.message()));
        assert!(error.message().contains(&id));
        assert!(error.message().contains("no owner"));
    }

    #[test]
    fn reviewed_unit_without_reviewed_paths_is_rejected() {
        let (_dir, mut ledger) = seeded();
        let id = ledger.units[0].id.clone();
        ledger.units[0].status = UnitStatus::Reviewed;
        ledger.units[0].owner = "reviewer-1".to_string();
        ledger.summary.pending -= 1;
        ledger.summary.reviewed += 1;
        let error = validate(&ledger).expect_err("reviewed without paths");
        assert!(issue(error.code(), error.message()));
        assert!(error.message().contains(&id));
        assert!(error.message().contains("no reviewed paths"));
    }

    #[test]
    fn summary_mismatch_is_rejected() {
        let (_dir, mut ledger) = seeded();
        ledger.units.pop();
        let error = validate(&ledger).expect_err("summary mismatch");
        assert!(issue(error.code(), error.message()));
        assert!(error.message().contains("summary"));
    }

    #[test]
    fn unknown_schema_version_is_rejected() {
        let (_dir, mut ledger) = seeded();
        ledger.schema_version = 999;
        let error = validate(&ledger).expect_err("unknown schema");
        assert!(issue(error.code(), error.message()));
        assert!(error.message().contains("schema version 999"));
    }

    #[test]
    fn duplicate_tuple_is_rejected() {
        let (_dir, mut ledger) = seeded();
        let mut copy = ledger.units[0].clone();
        copy.id = format!("{}-copy", copy.id);
        copy.fingerprint = "0123456789abcdef".to_string();
        ledger.units.push(copy);
        ledger.summary.units = ledger.units.len();
        ledger.summary.pending = ledger.units.len();
        let error = validate(&ledger).expect_err("duplicate tuple");
        assert!(issue(error.code(), error.message()));
        assert!(error.message().contains("duplicate unit for"));
    }

    #[test]
    fn assignment_validates_first_and_names_the_unit() {
        let (_dir, mut ledger) = seeded();
        let id = ledger.units[0].id.clone();
        ledger.units[0].fingerprint = "not-a-fingerprint".to_string();
        let error = ledger
            .assign(&id, "reviewer-1")
            .expect_err("invalid ledger cannot be assigned");
        assert!(issue(error.code(), error.message()));
        assert!(error.message().contains(&id));
    }

    #[test]
    fn assignment_sets_the_owner_and_updates_the_summary() {
        let (_dir, mut ledger) = seeded();
        let id = ledger.units[0].id.clone();
        ledger.assign(&id, "reviewer-1").expect("assign");
        let unit = ledger
            .units
            .iter()
            .find(|unit| unit.id == id)
            .expect("unit");
        assert_eq!(unit.status, UnitStatus::Assigned);
        assert_eq!(unit.owner, "reviewer-1");
        assert_eq!(ledger.summary.assigned, 1);
        assert_eq!(ledger.summary.pending, ledger.units.len() - 1);
        validate(&ledger).expect("assigned ledger validates");
    }

    #[test]
    fn json_round_trip_preserves_the_ledger() {
        let (_dir, ledger) = seeded();
        let text = ledger.to_json_pretty().expect("serialize");
        let parsed = CoverageLedger::from_json_str(&text).expect("parse and validate");
        assert_eq!(parsed, ledger);
    }

    #[test]
    fn an_empty_tree_yields_an_empty_valid_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = seed(dir.path()).expect("seed");
        assert!(ledger.units.is_empty());
        let report = validate(&ledger).expect("empty ledger validates");
        assert_eq!(report.units, 0);
        assert_eq!(report.covered, 0);
    }

    #[test]
    fn zero_limits_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let limits = SeedLimits {
            max_files: 0,
            max_depth: 0,
            max_file_bytes: 0,
        };
        let error = seed_with_limits(dir.path(), &limits).expect_err("zero limits");
        assert!(issue(error.code(), error.message()));
    }

    #[test]
    fn a_non_directory_root_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.txt");
        std::fs::write(&path, "x").unwrap();
        let error = seed(&path).expect_err("not a directory");
        assert!(issue(error.code(), error.message()));
    }

    #[test]
    fn relative_paths_are_root_relative_and_posix() {
        let dir = fixture();
        let ledger = seed(dir.path()).expect("seed");
        let root_string = dir.path().to_string_lossy().to_lowercase();
        for unit in &ledger.units {
            for path in unit
                .starting_paths
                .iter()
                .chain(unit.selected_companions.iter())
                .chain(unit.excluded_companions.iter().map(|ex| &ex.path))
            {
                assert!(!path.contains('\\'), "{path} is not posix");
                assert!(!path.contains(':'), "{path} looks absolute");
                assert!(
                    !path.to_lowercase().contains(&root_string),
                    "{path} leaked the fixture root"
                );
            }
        }
    }

    #[test]
    fn fingerprint_is_a_stable_function_of_the_unit_fields() {
        let dir = fixture();
        let first = seed(dir.path()).expect("first seed");
        let mut changed = first.clone();
        changed.units[0].status = UnitStatus::Deferred;
        // Status is not part of the identity fingerprint.
        assert_eq!(changed.units[0].fingerprint, first.units[0].fingerprint);
        let mut renamed = first.clone();
        renamed.units[0].refs.push("src/other.rs:1".to_string());
        let recomputed = unit_fingerprint(FingerprintParts {
            surface: &renamed.units[0].surface,
            boundary: &renamed.units[0].boundary,
            subsystem: &renamed.units[0].subsystem,
            class: &renamed.units[0].attack_class,
            refs: &renamed.units[0].refs,
            starting_paths: &renamed.units[0].starting_paths,
            selected_companions: &renamed.units[0].selected_companions,
            excluded_companions: &renamed.units[0].excluded_companions,
        });
        assert_ne!(recomputed, first.units[0].fingerprint);
    }

    #[test]
    fn ledger_paths_are_relative_to_the_requested_root() {
        let dir = fixture();
        let ledger = seed(dir.path()).expect("seed");
        let expected: PathBuf = PathBuf::from("src");
        assert!(ledger
            .units
            .iter()
            .any(|unit| unit.subsystem == expected.to_string_lossy()));
    }
}
