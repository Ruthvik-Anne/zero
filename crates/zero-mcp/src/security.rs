//! MCP security controls (T-MCP-08, MCP-08, MCP-14).
//!
//! Five independent controls live here. Each one is a small, scriptable policy
//! with no network access, so callers can enforce it at the seam that owns the
//! data:
//!
//! - [`SchemaPinStore`] remembers a schema hash per `(server, tool)` and reports
//!   a changed definition as [`PinOutcome::Changed`], which asks the host. It
//!   never silently accepts a changed schema.
//! - [`classify`] and [`decide`] map MCP tool annotations (or name/description
//!   markers when annotations are absent) onto a [`PolicyMode`] risk matrix.
//!   Tools that never state read-only intent default to [`ToolDecision::Ask`].
//! - [`ResponseLimits`] rejects an oversized tool result without echoing it.
//! - [`TimeoutPolicy`] validates request and total bounds and checks elapsed
//!   time.
//! - [`check_resource_url`] is a self-contained SSRF policy for MCP resource
//!   URLs; it does not depend on `zero-web`.
//! - [`ReplayGuard`] is a bounded TTL set of request ids for callers that need
//!   replay protection.
//!
//! Everything is deterministic and testable without a socket or a child
//! process. No error message in this module contains a token, tool result
//! payload, or the rejected URL. See `docs/mcp.md` for the policy rationale and
//! the deferred items.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::client::{Tool, ToolCallResult, ToolCatalog};

/// Default cap on the serialised `content` array of one tool result (1 MiB).
pub const DEFAULT_MAX_CONTENT_BYTES: usize = 1024 * 1024;
/// Default cap on the serialised `structuredContent` value of one result (1 MiB).
pub const DEFAULT_MAX_STRUCTURED_BYTES: usize = 1024 * 1024;
/// Default cap on the number of content blocks in one result.
pub const DEFAULT_MAX_ITEMS: usize = 1024;

/// Default per-request timeout, in milliseconds.
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 30_000;
/// Default total budget for one logical call including retries, in milliseconds.
pub const DEFAULT_TOTAL_TIMEOUT_MS: u64 = 300_000;
/// Largest accepted per-request timeout, in milliseconds (10 minutes).
pub const MAX_REQUEST_TIMEOUT_MS: u64 = 600_000;
/// Largest accepted total budget, in milliseconds (1 hour).
pub const MAX_TOTAL_TIMEOUT_MS: u64 = 3_600_000;

/// Default bound on the number of request ids a [`ReplayGuard`] retains.
pub const DEFAULT_REPLAY_CAPACITY: usize = 4096;
/// Default replay window, in milliseconds (10 minutes).
pub const DEFAULT_REPLAY_TTL_MS: u64 = 10 * 60 * 1000;

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyDenied, message)
}

fn ask(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyAskRequired, message)
}

fn limit(dimension: &str, value: usize, cap: usize) -> ZeroError {
    ZeroError::new(
        ErrorCode::LimitExceeded,
        format!("MCP tool result {dimension} {value} exceeds limit {cap}"),
    )
}

fn timed_out(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Timeout, message)
}

// ---------------------------------------------------------------------------
// Schema pinning
// ---------------------------------------------------------------------------

/// One tool whose schema differs from the pinned baseline.
///
/// `pinned` is the previous hash and `current` is the hash just observed.
/// `current: None` means the tool disappeared; `pinned: None` means it is new.
/// Only the tool name and hashes are carried here, never a schema, description,
/// or argument value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangedTool {
    /// Tool name.
    pub name: String,
    /// Hash recorded by the previous pin, when the tool existed.
    pub pinned: Option<u64>,
    /// Hash observed now, when the tool still exists.
    pub current: Option<u64>,
}

impl ChangedTool {
    /// Whether the tool is newly advertised.
    pub fn is_added(&self) -> bool {
        self.pinned.is_none() && self.current.is_some()
    }

    /// Whether the tool disappeared from the catalogue.
    pub fn is_removed(&self) -> bool {
        self.pinned.is_some() && self.current.is_none()
    }

    /// Whether the tool still exists but its schema changed.
    pub fn is_redefined(&self) -> bool {
        self.pinned.is_some() && self.current.is_some()
    }
}

/// What pinning a catalogue found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinOutcome {
    /// The server had no pins; this catalogue was recorded as the baseline.
    New,
    /// Every tool matched its pinned hash (and the tool set was identical).
    Unchanged,
    /// At least one tool was added, removed, or redefined. The store keeps the
    /// old baseline until the host approves the new hashes.
    Changed {
        /// The changed tools, in catalogue order followed by removed names.
        tools: Vec<ChangedTool>,
    },
}

impl PinOutcome {
    /// Whether this was the first pin for the server.
    pub fn is_new(&self) -> bool {
        matches!(self, PinOutcome::New)
    }

    /// Whether every tool matched.
    pub fn is_unchanged(&self) -> bool {
        matches!(self, PinOutcome::Unchanged)
    }

    /// Whether the catalogue differs from the pinned baseline.
    pub fn is_changed(&self) -> bool {
        matches!(self, PinOutcome::Changed { .. })
    }

    /// The changed tools, or an empty slice for `New`/`Unchanged`.
    pub fn changed_tools(&self) -> &[ChangedTool] {
        match self {
            PinOutcome::Changed { tools } => tools,
            PinOutcome::New | PinOutcome::Unchanged => &[],
        }
    }

    /// The host-facing decision for this outcome.
    ///
    /// A changed schema is always [`ToolDecision::Ask`]; only a first pin or an
    /// unchanged catalogue is [`ToolDecision::Allow`].
    pub fn decision(&self) -> ToolDecision {
        if self.is_changed() {
            ToolDecision::Ask
        } else {
            ToolDecision::Allow
        }
    }
}

/// A host approval for one server's schema hashes.
///
/// The host builds this after seeing the [`PinOutcome::Changed`] prompt. The
/// map holds `tool -> observed hash`; a removed tool maps to `None`. The only
/// way to create a non-empty approval is through [`Self::approve_catalog`] or
/// [`Self::approve_changes`], so an approval is tied to hashes the host was
/// actually shown.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaApproval {
    #[serde(default)]
    server: String,
    #[serde(default)]
    tool_hashes: BTreeMap<String, Option<u64>>,
}

impl SchemaApproval {
    /// An empty approval for `server`: no hash was approved.
    pub fn empty(server: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            tool_hashes: BTreeMap::new(),
        }
    }

    /// Approve every hash in the catalogue the host just observed.
    pub fn approve_catalog(server: impl Into<String>, catalog: &ToolCatalog) -> Self {
        let tool_hashes = catalog
            .tools
            .iter()
            .map(|tool| (tool.name.clone(), Some(tool.schema_hash())))
            .collect();
        Self {
            server: server.into(),
            tool_hashes,
        }
    }

    /// Approve exactly the changed hashes reported by one outcome.
    pub fn approve_changes(server: impl Into<String>, outcome: &PinOutcome) -> Self {
        let tool_hashes = outcome
            .changed_tools()
            .iter()
            .map(|tool| (tool.name.clone(), tool.current))
            .collect();
        Self {
            server: server.into(),
            tool_hashes,
        }
    }

    /// The server this approval names.
    pub fn server(&self) -> &str {
        &self.server
    }

    /// Whether no hash was approved.
    pub fn is_empty(&self) -> bool {
        self.tool_hashes.is_empty()
    }

    /// The approved `tool -> hash` map (`None` approves a removal).
    pub fn tool_hashes(&self) -> &BTreeMap<String, Option<u64>> {
        &self.tool_hashes
    }

    fn matches(&self, server: &str, changed: &[ChangedTool]) -> bool {
        if self.server != server || self.tool_hashes.is_empty() {
            return false;
        }
        changed
            .iter()
            .all(|tool| self.tool_hashes.get(&tool.name) == Some(&tool.current))
    }
}

/// Pinned schema hashes per `(server, tool)`.
///
/// The store is serialisable JSON. [`Self::open`] loads an existing file (or
/// starts empty when the file is absent) and [`Self::save`] writes it back.
/// [`Self::default`] is in-memory only and is what tests use.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaPinStore {
    #[serde(default)]
    pins: BTreeMap<String, BTreeMap<String, u64>>,
    #[serde(skip)]
    path: Option<PathBuf>,
}

impl SchemaPinStore {
    /// An in-memory store with no file path.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a store backed by `path`.
    ///
    /// A missing file starts an empty store, which the next [`Self::save`]
    /// creates. A malformed file is a `zero.fnd.serialization` error.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        match std::fs::read(&path) {
            Ok(bytes) => {
                let mut store: Self = serde_json::from_slice(&bytes)?;
                store.path = Some(path);
                Ok(store)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                path: Some(path),
                ..Self::default()
            }),
            Err(error) => Err(error.into()),
        }
    }

    /// The backing file path, when one is set.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Write the store to its backing path, creating parent directories.
    pub fn save(&self) -> Result<()> {
        let path = self
            .path
            .as_deref()
            .ok_or_else(|| invalid("MCP schema pin store has no file path"))?;
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(self)?;
        std::fs::write(path, bytes)?;
        Ok(())
    }

    /// Record the catalogue on a first pin and report what changed afterwards.
    ///
    /// A `New` outcome records every tool hash. `Unchanged` and `Changed` leave
    /// the baseline untouched: a changed schema must go through
    /// [`Self::require_approval`] before it becomes the new baseline.
    pub fn pin_catalog(&mut self, server: &str, catalog: &ToolCatalog) -> PinOutcome {
        let outcome = self.diff(server, catalog);
        if outcome.is_new() {
            self.replace(server, catalog);
        }
        outcome
    }

    /// Require host approval for a changed catalogue and, when it matches,
    /// update the baseline.
    ///
    /// The approval must name the same server and contain the exact hash (or
    /// removal) of every changed tool. An empty approval returns
    /// `zero.pol.ask`; a non-empty but stale or mismatched approval returns
    /// `zero.pol.denied`. Neither message contains a schema or description,
    /// only tool names. A first pin and an unchanged catalogue proceed without
    /// approval.
    pub fn require_approval(
        &mut self,
        server: &str,
        catalog: &ToolCatalog,
        approval: &SchemaApproval,
    ) -> Result<()> {
        match self.diff(server, catalog) {
            PinOutcome::New => {
                self.replace(server, catalog);
                Ok(())
            }
            PinOutcome::Unchanged => Ok(()),
            PinOutcome::Changed { tools } => {
                if approval.matches(server, &tools) {
                    self.replace(server, catalog);
                    Ok(())
                } else if approval.is_empty() {
                    Err(ask(format!(
                        "MCP tool schemas changed for `{server}` ({}); host approval required",
                        tool_names(&tools)
                    )))
                } else {
                    Err(denied(format!(
                        "MCP schema approval does not match the changed tools for `{server}` ({}); refusing",
                        tool_names(&tools)
                    )))
                }
            }
        }
    }

    /// The pinned hash for one tool, when present.
    pub fn pinned_hash(&self, server: &str, tool: &str) -> Option<u64> {
        self.pins
            .get(server)
            .and_then(|tools| tools.get(tool))
            .copied()
    }

    /// The pinned tools for one server, when the server has been pinned.
    pub fn pinned_tools(&self, server: &str) -> Option<&BTreeMap<String, u64>> {
        self.pins.get(server)
    }

    /// Forget every pin for one server.
    pub fn unpin(&mut self, server: &str) -> bool {
        self.pins.remove(server).is_some()
    }

    /// Whether the store has no pins.
    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }

    /// Number of pinned tools across all servers.
    pub fn len(&self) -> usize {
        self.pins.values().map(BTreeMap::len).sum()
    }

    fn diff(&self, server: &str, catalog: &ToolCatalog) -> PinOutcome {
        let Some(pinned) = self.pins.get(server) else {
            return PinOutcome::New;
        };

        let mut changed = Vec::new();
        for tool in &catalog.tools {
            let current = tool.schema_hash();
            match pinned.get(&tool.name) {
                Some(previous) if *previous == current => {}
                Some(previous) => changed.push(ChangedTool {
                    name: tool.name.clone(),
                    pinned: Some(*previous),
                    current: Some(current),
                }),
                None => changed.push(ChangedTool {
                    name: tool.name.clone(),
                    pinned: None,
                    current: Some(current),
                }),
            }
        }
        for (name, previous) in pinned {
            if catalog.tool(name).is_none() {
                changed.push(ChangedTool {
                    name: name.clone(),
                    pinned: Some(*previous),
                    current: None,
                });
            }
        }

        if changed.is_empty() {
            PinOutcome::Unchanged
        } else {
            PinOutcome::Changed { tools: changed }
        }
    }

    fn replace(&mut self, server: &str, catalog: &ToolCatalog) {
        let pins = catalog
            .tools
            .iter()
            .map(|tool| (tool.name.clone(), tool.schema_hash()))
            .collect();
        self.pins.insert(server.to_string(), pins);
    }
}

fn tool_names(tools: &[ChangedTool]) -> String {
    tools
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------------------
// Destructive-tool defaults
// ---------------------------------------------------------------------------

/// Risk of calling one tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolRisk {
    /// Declared read-only.
    ReadOnly,
    /// Modifies state but is not destructive.
    Write,
    /// May delete, remove, overwrite, or otherwise destroy state.
    Destructive,
}

/// Policy mode for tool calls.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PolicyMode {
    /// Strictest: reads only; destructive tools are denied outright.
    Restricted,
    /// Default: reads are allowed; writes and destructive tools ask.
    #[default]
    Manual,
    /// Writes are allowed; destructive tools still ask.
    Auto,
}

/// Result of applying the policy matrix to one tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolDecision {
    /// Run the tool.
    Allow,
    /// Ask the host before running the tool.
    Ask,
    /// Refuse to run the tool.
    Deny,
}

/// Name and description markers that imply a destructive action.
const DESTRUCTIVE_MARKERS: &[&str] = &[
    "delete",
    "remove",
    "drop",
    "purge",
    "overwrite",
    "destroy",
    "erase",
    "truncate",
    "wipe",
    "unlink",
    "rm",
];

/// Name and description markers that imply a state-changing action.
const WRITE_MARKERS: &[&str] = &[
    "write", "execute", "exec", "shell", "command", "upload", "create", "update", "patch",
    "insert", "set", "put", "post", "move", "rename", "copy", "run", "install", "deploy", "send",
];

/// Classify a tool from explicit MCP annotations, then name/description markers.
///
/// `destructiveHint: true` wins over `readOnlyHint: true` when a hostile or
/// confused server sets both. A tool with no usable hint and no marker is
/// reported as [`ToolRisk::Write`] because that is the conservative risk to
/// display; [`decide`] still asks for it.
pub fn classify(tool: &Tool) -> ToolRisk {
    if let Some(annotations) = &tool.annotations {
        if annotations.destructive_hint == Some(true) {
            return ToolRisk::Destructive;
        }
        if annotations.read_only_hint == Some(true) {
            return ToolRisk::ReadOnly;
        }
    }
    if has_marker(tool, DESTRUCTIVE_MARKERS) {
        return ToolRisk::Destructive;
    }
    if has_marker(tool, WRITE_MARKERS) {
        return ToolRisk::Write;
    }
    ToolRisk::Write
}

/// Apply a policy mode to one tool.
///
/// Matrix:
///
/// | Risk | Restricted | Manual | Auto |
/// |---|---|---|---|
/// | `ReadOnly` | `Allow` | `Allow` | `Allow` |
/// | `Write` | `Ask` | `Ask` | `Allow` |
/// | `Destructive` | `Deny` | `Ask` | `Ask` |
///
/// A tool that never states read-only intent (no `readOnlyHint`, no marker) is
/// unknown and returns `Ask` in every mode, including `Auto`. An explicit
/// `readOnlyHint: false` counts as a known write, not as unknown.
pub fn decide(tool: &Tool, mode: PolicyMode) -> ToolDecision {
    let risk = classify(tool);
    let known = is_explicitly_classified(tool);
    match (mode, risk) {
        (_, ToolRisk::ReadOnly) if known => ToolDecision::Allow,
        (PolicyMode::Auto, ToolRisk::Write) if known => ToolDecision::Allow,
        (PolicyMode::Restricted, ToolRisk::Destructive) if known => ToolDecision::Deny,
        _ => ToolDecision::Ask,
    }
}

fn is_explicitly_classified(tool: &Tool) -> bool {
    let annotated = tool.annotations.as_ref().is_some_and(|hints| {
        hints.read_only_hint.is_some() || hints.destructive_hint == Some(true)
    });
    annotated || has_marker(tool, DESTRUCTIVE_MARKERS) || has_marker(tool, WRITE_MARKERS)
}

fn has_marker(tool: &Tool, markers: &[&str]) -> bool {
    text_has_marker(&tool.name, markers)
        || tool
            .title
            .as_deref()
            .is_some_and(|title| text_has_marker(title, markers))
        || tool
            .description
            .as_deref()
            .is_some_and(|description| text_has_marker(description, markers))
}

fn text_has_marker(text: &str, markers: &[&str]) -> bool {
    text.split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .any(|word| {
            markers
                .iter()
                .any(|marker| word.eq_ignore_ascii_case(marker))
        })
}

// ---------------------------------------------------------------------------
// Result size caps
// ---------------------------------------------------------------------------

/// Bounds applied to one `tools/call` result before it is handed to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseLimits {
    /// Maximum serialised byte length of the `content` array.
    pub max_content_bytes: usize,
    /// Maximum serialised byte length of `structuredContent`.
    pub max_structured_bytes: usize,
    /// Maximum number of content blocks in `content`.
    pub max_items: usize,
}

impl Default for ResponseLimits {
    fn default() -> Self {
        Self {
            max_content_bytes: DEFAULT_MAX_CONTENT_BYTES,
            max_structured_bytes: DEFAULT_MAX_STRUCTURED_BYTES,
            max_items: DEFAULT_MAX_ITEMS,
        }
    }
}

impl ResponseLimits {
    /// Check that every cap is non-zero.
    pub fn validate(&self) -> Result<()> {
        if self.max_content_bytes == 0 {
            return Err(invalid("MCP content byte cap must be non-zero"));
        }
        if self.max_structured_bytes == 0 {
            return Err(invalid("MCP structured content byte cap must be non-zero"));
        }
        if self.max_items == 0 {
            return Err(invalid("MCP content item cap must be non-zero"));
        }
        Ok(())
    }

    /// Reject an oversize result without echoing its content.
    ///
    /// The content byte count is the compact JSON length of the whole
    /// `content` array (brackets and commas included), so a result cannot
    /// bypass the cap by splitting one value into many blocks. The error names
    /// the failing dimension and cap only.
    pub fn check_tool_result(&self, content: &[Value], structured: Option<&Value>) -> Result<()> {
        self.validate()?;
        if content.len() > self.max_items {
            return Err(limit("item count", content.len(), self.max_items));
        }
        let content_bytes = serde_json::to_vec(content)?.len();
        if content_bytes > self.max_content_bytes {
            return Err(limit(
                "content bytes",
                content_bytes,
                self.max_content_bytes,
            ));
        }
        if let Some(structured) = structured {
            let structured_bytes = serde_json::to_vec(structured)?.len();
            if structured_bytes > self.max_structured_bytes {
                return Err(limit(
                    "structured content bytes",
                    structured_bytes,
                    self.max_structured_bytes,
                ));
            }
        }
        Ok(())
    }

    /// Check a parsed [`ToolCallResult`] with the same caps.
    pub fn check_tool_call_result(&self, result: &ToolCallResult) -> Result<()> {
        self.check_tool_result(&result.content, result.structured_content.as_ref())
    }
}

// ---------------------------------------------------------------------------
// Timeouts
// ---------------------------------------------------------------------------

/// Request and total time budgets for one logical MCP operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutPolicy {
    /// Bound on one request.
    pub request_ms: u64,
    /// Bound on the whole operation, including retries.
    pub total_ms: u64,
}

impl Default for TimeoutPolicy {
    fn default() -> Self {
        Self {
            request_ms: DEFAULT_REQUEST_TIMEOUT_MS,
            total_ms: DEFAULT_TOTAL_TIMEOUT_MS,
        }
    }
}

impl TimeoutPolicy {
    /// Build and validate a policy.
    pub fn new(request_ms: u64, total_ms: u64) -> Result<Self> {
        let policy = Self {
            request_ms,
            total_ms,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Validate the budget.
    ///
    /// Both values must be non-zero, the request bound must not exceed the
    /// total bound, and each must stay under the crate maximum. A zero or
    /// inverted value is `zero.fnd.invalid_input`; an over-large value is
    /// `zero.fnd.limit_exceeded`.
    pub fn validate(&self) -> Result<()> {
        if self.request_ms == 0 {
            return Err(invalid("MCP request timeout must be non-zero"));
        }
        if self.total_ms == 0 {
            return Err(invalid("MCP total timeout must be non-zero"));
        }
        if self.request_ms > self.total_ms {
            return Err(invalid(
                "MCP request timeout must not exceed the total timeout",
            ));
        }
        if self.request_ms > MAX_REQUEST_TIMEOUT_MS {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "MCP request timeout {} ms exceeds limit {MAX_REQUEST_TIMEOUT_MS} ms",
                    self.request_ms
                ),
            ));
        }
        if self.total_ms > MAX_TOTAL_TIMEOUT_MS {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "MCP total timeout {} ms exceeds limit {MAX_TOTAL_TIMEOUT_MS} ms",
                    self.total_ms
                ),
            ));
        }
        Ok(())
    }

    /// Fail with `zero.fnd.timeout` once the total budget is exhausted.
    pub fn check_elapsed(&self, elapsed_ms: u64) -> Result<()> {
        if elapsed_ms >= self.total_ms {
            return Err(timed_out(format!(
                "MCP operation exceeded the total timeout of {} ms",
                self.total_ms
            )));
        }
        Ok(())
    }

    /// The per-request budget as a [`Duration`].
    pub fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_ms)
    }

    /// The total budget as a [`Duration`].
    pub fn total_timeout(&self) -> Duration {
        Duration::from_millis(self.total_ms)
    }
}

// ---------------------------------------------------------------------------
// SSRF for resource URLs
// ---------------------------------------------------------------------------

/// Hosts that are metadata services or internal aliases by convention.
const BLOCKED_HOSTS: &[&str] = &[
    "metadata",
    "metadata.google.internal",
    "metadata.azure.internal",
    "instance-data",
    "kubernetes.default",
    "kubernetes.default.svc",
];

/// Refuse an MCP resource URL that could reach the local host or a metadata
/// service.
///
/// This is a deliberate, self-contained policy so `zero-mcp` stays below
/// `zero-web` in the dependency graph. It refuses:
///
/// - every scheme except `http` and `https` (`file:`, `data:`, `javascript:`,
///   and the rest);
/// - userinfo, which can disguise the real authority;
/// - `localhost`, `*.localhost`, and the metadata/internal host aliases;
/// - loopback, private, shared, link-local, unique-local, unspecified, and
///   broadcast IPv4/IPv6 literals, including IPv4-mapped IPv6 and
///   `169.254.169.254` / `fd00:ec2::254`.
///
/// The URL is parsed but never fetched, and no error echoes it. DNS names are
/// not resolved here, so a name that resolves to a private address is a
/// deferred check for the transport.
pub fn check_resource_url(value: &str) -> Result<()> {
    let url =
        Url::parse(value).map_err(|_| invalid("MCP resource URL is not a valid absolute URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(denied("MCP resource URL must use http or https"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(denied("MCP resource URL must not contain userinfo"));
    }
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| invalid("MCP resource URL must have a host"))?;
    check_resource_host(host)
}

fn check_resource_host(host: &str) -> Result<()> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    // `Url::host_str` keeps the brackets around an IPv6 literal.
    let bare = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(&host);
    if bare == "localhost" || bare.ends_with(".localhost") {
        return Err(denied("MCP resource URL host is a loopback name"));
    }
    if BLOCKED_HOSTS.contains(&bare) {
        return Err(denied("MCP resource URL host is a local metadata service"));
    }
    if let Ok(address) = bare.parse::<IpAddr>() {
        if let Some(reason) = blocked_address_reason(address) {
            return Err(denied(format!(
                "MCP resource URL host is a {reason} address"
            )));
        }
    }
    Ok(())
}

fn blocked_address_reason(address: IpAddr) -> Option<&'static str> {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            if address.is_loopback() {
                Some("loopback")
            } else if address.is_private() {
                Some("private")
            } else if address.is_link_local() {
                Some("link-local")
            } else if address.is_unspecified() || address.is_broadcast() || octets[0] == 0 {
                Some("unspecified")
            } else if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                Some("shared")
            } else {
                None
            }
        }
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return blocked_address_reason(IpAddr::V4(mapped));
            }
            let segments = address.segments();
            if address.is_loopback() {
                Some("loopback")
            } else if address.is_unspecified() {
                Some("unspecified")
            } else if (segments[0] & 0xfe00) == 0xfc00 {
                Some("unique-local")
            } else if (segments[0] & 0xffc0) == 0xfe80 {
                Some("link-local")
            } else {
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Replay guard
// ---------------------------------------------------------------------------

/// What [`ReplayGuard::check_and_record`] found for one id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayOutcome {
    /// The id was not seen inside the window; it is now recorded.
    Fresh,
    /// The id was seen inside the window; it must not be processed again.
    Replay,
    /// The id was seen, but its record is older than the window; it is now
    /// recorded afresh.
    Expired,
}

/// A bounded, TTL-scoped set of request ids.
///
/// Callers key the guard by anything unique per request. [`Self::check_and_record`]
/// takes a single string; [`Self::check_and_record_pair`] builds a
/// `(method, id)` key so an id reused across methods is not treated as a
/// replay. Recording is first-in-first-out: once `capacity` ids are retained,
/// the oldest is evicted, so a replay after that many distinct ids is fresh
/// again rather than silently dropped.
///
/// The guard is in memory only. Persisting it across restarts and sharing it
/// between processes is deferred; callers that need that must supply their own
/// durable store.
#[derive(Debug, Clone)]
pub struct ReplayGuard {
    ttl_ms: u64,
    capacity: usize,
    seen: HashMap<String, i64>,
    order: VecDeque<(String, i64)>,
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl ReplayGuard {
    /// Build a guard with an explicit window and capacity.
    ///
    /// `ttl_ms` and `capacity` must be non-zero.
    pub fn new(ttl_ms: u64, capacity: usize) -> Result<Self> {
        if ttl_ms == 0 {
            return Err(invalid("MCP replay TTL must be non-zero"));
        }
        if capacity == 0 {
            return Err(invalid("MCP replay capacity must be non-zero"));
        }
        Ok(Self {
            ttl_ms,
            capacity,
            seen: HashMap::new(),
            order: VecDeque::new(),
        })
    }

    /// Build a guard with [`DEFAULT_REPLAY_TTL_MS`] and
    /// [`DEFAULT_REPLAY_CAPACITY`].
    pub fn with_defaults() -> Self {
        Self {
            ttl_ms: DEFAULT_REPLAY_TTL_MS,
            capacity: DEFAULT_REPLAY_CAPACITY,
            seen: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// The replay window in milliseconds.
    pub fn ttl_ms(&self) -> u64 {
        self.ttl_ms
    }

    /// The maximum number of ids retained.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The number of ids currently retained.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether no ids are retained.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Check and record one id.
    ///
    /// A repeat within `ttl_ms` (inclusive) is [`ReplayOutcome::Replay`]. An
    /// older record is pruned and returned as [`ReplayOutcome::Expired`], then
    /// re-recorded at `now_ms`. Unrelated records older than the window are
    /// pruned on every call.
    pub fn check_and_record(&mut self, id: &str, now_ms: i64) -> ReplayOutcome {
        if let Some(previous) = self.seen.get(id).copied() {
            if !self.is_expired(previous, now_ms) {
                return ReplayOutcome::Replay;
            }
            self.remove(id, previous);
            self.prune(now_ms);
            self.make_room();
            self.record(id, now_ms);
            return ReplayOutcome::Expired;
        }

        self.prune(now_ms);
        self.make_room();
        self.record(id, now_ms);
        ReplayOutcome::Fresh
    }

    /// Check and record a `(method, id)` pair.
    pub fn check_and_record_pair(&mut self, id: &str, method: &str, now_ms: i64) -> ReplayOutcome {
        self.check_and_record(&replay_key(method, id), now_ms)
    }

    fn is_expired(&self, previous: i64, now_ms: i64) -> bool {
        let age = now_ms.saturating_sub(previous);
        age > 0 && (age as u64) > self.ttl_ms
    }

    fn prune(&mut self, now_ms: i64) {
        while let Some((_, previous)) = self.order.front() {
            if !self.is_expired(*previous, now_ms) {
                break;
            }
            self.evict_oldest();
        }
    }

    fn make_room(&mut self) {
        while self.order.len() >= self.capacity {
            self.evict_oldest();
        }
    }

    fn record(&mut self, id: &str, now_ms: i64) {
        self.seen.insert(id.to_string(), now_ms);
        self.order.push_back((id.to_string(), now_ms));
    }

    fn remove(&mut self, id: &str, previous: i64) {
        if self.seen.get(id) == Some(&previous) {
            self.seen.remove(id);
        }
        self.order
            .retain(|(entry, stamp)| !(entry == id && *stamp == previous));
    }

    fn evict_oldest(&mut self) {
        if let Some((id, previous)) = self.order.pop_front() {
            if self.seen.get(&id) == Some(&previous) {
                self.seen.remove(&id);
            }
        }
    }
}

fn replay_key(method: &str, id: &str) -> String {
    format!("{method}\u{0}{id}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ResultType, ToolAnnotations};
    use serde_json::json;

    fn tool(name: &str, input_schema: Value) -> Tool {
        Tool {
            name: name.to_string(),
            title: None,
            description: None,
            input_schema,
            output_schema: None,
            annotations: None,
        }
    }

    fn annotated(name: &str, read_only_hint: Option<bool>, destructive_hint: Option<bool>) -> Tool {
        let mut tool = tool(name, json!({"type": "object"}));
        tool.annotations = Some(ToolAnnotations {
            read_only_hint,
            destructive_hint,
            ..ToolAnnotations::default()
        });
        tool
    }

    fn catalog(tools: Vec<Tool>) -> ToolCatalog {
        ToolCatalog {
            tools,
            next_cursor: None,
            ttl_ms: None,
            cache_scope: None,
            result_type: ResultType::Complete,
        }
    }

    fn schema_a() -> Value {
        json!({"type": "object", "properties": {"query": {"type": "string"}}})
    }

    fn schema_b() -> Value {
        json!({"type": "object", "properties": {"limit": {"type": "integer"}}})
    }

    #[test]
    fn first_pin_is_new_and_an_identical_catalog_is_unchanged() {
        let catalog = catalog(vec![tool("search", schema_a())]);
        let mut store = SchemaPinStore::new();

        assert_eq!(store.pin_catalog("server", &catalog), PinOutcome::New);
        assert_eq!(
            store.pinned_hash("server", "search"),
            Some(catalog.tools[0].schema_hash())
        );
        assert_eq!(store.pin_catalog("server", &catalog), PinOutcome::Unchanged);
    }

    #[test]
    fn a_description_only_change_is_unchanged() {
        let first = catalog(vec![tool("search", schema_a())]);
        let mut changed = tool("search", schema_a());
        changed.description = Some("A completely different description".to_string());
        let second = catalog(vec![changed]);

        let mut store = SchemaPinStore::new();
        store.pin_catalog("server", &first);
        assert_eq!(store.pin_catalog("server", &second), PinOutcome::Unchanged);
    }

    #[test]
    fn a_changed_schema_is_changed_and_the_decision_is_exactly_ask() {
        let first = catalog(vec![tool("search", schema_a())]);
        let second = catalog(vec![tool("search", schema_b())]);
        let mut store = SchemaPinStore::new();
        store.pin_catalog("server", &first);

        let outcome = store.pin_catalog("server", &second);
        assert!(outcome.is_changed());
        assert_eq!(outcome.decision(), ToolDecision::Ask);
        assert_eq!(outcome.changed_tools().len(), 1);
        assert_eq!(outcome.changed_tools()[0].name, "search");
        assert!(outcome.changed_tools()[0].is_redefined());
        // The old baseline is kept until approval.
        assert_eq!(
            store.pinned_hash("server", "search"),
            Some(first.tools[0].schema_hash())
        );
        assert_eq!(
            store.pin_catalog("server", &second).decision(),
            ToolDecision::Ask
        );
    }

    #[test]
    fn approval_for_the_old_hash_does_not_authorize_the_new_one() {
        let first = catalog(vec![tool("search", schema_a())]);
        let second = catalog(vec![tool("search", schema_b())]);
        let mut store = SchemaPinStore::new();
        store.pin_catalog("server", &first);

        let stale = SchemaApproval::approve_catalog("server", &first);
        let error = store
            .require_approval("server", &second, &stale)
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("search"));
        assert_eq!(
            store.pinned_hash("server", "search"),
            Some(first.tools[0].schema_hash())
        );
    }

    #[test]
    fn an_empty_approval_asks_instead_of_proceeding() {
        let first = catalog(vec![tool("search", schema_a())]);
        let second = catalog(vec![tool("search", schema_b())]);
        let mut store = SchemaPinStore::new();
        store.pin_catalog("server", &first);

        let error = store
            .require_approval("server", &second, &SchemaApproval::empty("server"))
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyAskRequired);
        assert!(error.message().contains("search"));
        assert!(store.pin_catalog("server", &second).is_changed());
    }

    #[test]
    fn approval_of_the_exact_new_hash_proceeds() {
        let first = catalog(vec![tool("search", schema_a())]);
        let second = catalog(vec![tool("search", schema_b())]);
        let mut store = SchemaPinStore::new();
        store.pin_catalog("server", &first);

        let approval = SchemaApproval::approve_catalog("server", &second);
        store
            .require_approval("server", &second, &approval)
            .unwrap();
        assert_eq!(
            store.pinned_hash("server", "search"),
            Some(second.tools[0].schema_hash())
        );
        assert_eq!(store.pin_catalog("server", &second), PinOutcome::Unchanged);
    }

    #[test]
    fn approval_built_from_the_changed_set_proceeds_and_removals_count() {
        let first = catalog(vec![
            tool("search", schema_a()),
            tool("delete_file", schema_a()),
        ]);
        let mut store = SchemaPinStore::new();
        store.pin_catalog("server", &first);

        let second = catalog(vec![tool("search", schema_b())]);
        let outcome = store.pin_catalog("server", &second);
        assert_eq!(outcome.changed_tools().len(), 2);
        assert!(outcome
            .changed_tools()
            .iter()
            .any(|tool| tool.name == "delete_file" && tool.is_removed()));

        let approval = SchemaApproval::approve_changes("server", &outcome);
        store
            .require_approval("server", &second, &approval)
            .unwrap();
        assert_eq!(store.pin_catalog("server", &second), PinOutcome::Unchanged);
        assert_eq!(store.pinned_tools("server").map(BTreeMap::len), Some(1));
    }

    #[test]
    fn a_changed_approval_for_another_server_is_denied() {
        let first = catalog(vec![tool("search", schema_a())]);
        let second = catalog(vec![tool("search", schema_b())]);
        let mut store = SchemaPinStore::new();
        store.pin_catalog("server", &first);

        let wrong_server = SchemaApproval::approve_catalog("other", &second);
        let error = store
            .require_approval("server", &second, &wrong_server)
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
    }

    #[test]
    fn the_pin_store_round_trips_through_a_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mcp-pins.json");
        let catalog = catalog(vec![tool("search", schema_a())]);

        let mut store = SchemaPinStore::open(&path).unwrap();
        assert!(store.is_empty());
        assert_eq!(store.pin_catalog("server", &catalog), PinOutcome::New);
        store.save().unwrap();

        let mut reopened = SchemaPinStore::open(&path).unwrap();
        assert_eq!(reopened.path(), Some(path.as_path()));
        assert_eq!(
            reopened.pin_catalog("server", &catalog),
            PinOutcome::Unchanged
        );
        assert_eq!(reopened.len(), 1);
    }

    #[test]
    fn annotations_drive_risk_and_markers_are_a_fallback() {
        assert_eq!(
            classify(&annotated("delete_everything", Some(true), None)),
            ToolRisk::ReadOnly
        );
        assert_eq!(
            classify(&annotated("list_files", Some(false), Some(true))),
            ToolRisk::Destructive
        );
        assert_eq!(
            classify(&annotated("list_files", Some(false), None)),
            ToolRisk::Write
        );
        assert_eq!(
            classify(&tool("delete_file", schema_a())),
            ToolRisk::Destructive
        );
        assert_eq!(classify(&tool("write_file", schema_a())), ToolRisk::Write);

        let mut upload = tool("ingest", schema_a());
        upload.description = Some("Uploads a file to the workspace".to_string());
        assert_eq!(classify(&upload), ToolRisk::Write);

        let mut shell = tool("run", schema_a());
        shell.description = Some("Executes a shell command".to_string());
        assert_eq!(classify(&shell), ToolRisk::Write);
    }

    #[test]
    fn destructive_hint_wins_when_both_hints_are_set() {
        assert_eq!(
            classify(&annotated("harmless", Some(true), Some(true))),
            ToolRisk::Destructive
        );
    }

    #[test]
    fn the_policy_matrix_allows_reads_asks_writes_and_denies_in_restricted() {
        let read = annotated("inspect", Some(true), None);
        let write = annotated("mutate", Some(false), None);
        let destructive = annotated("drop_tables", Some(false), Some(true));
        let unknown = tool("list_files", schema_a());

        for mode in [PolicyMode::Restricted, PolicyMode::Manual, PolicyMode::Auto] {
            assert_eq!(decide(&read, mode), ToolDecision::Allow);
            assert_eq!(decide(&unknown, mode), ToolDecision::Ask);
        }

        assert_eq!(decide(&write, PolicyMode::Restricted), ToolDecision::Ask);
        assert_eq!(decide(&write, PolicyMode::Manual), ToolDecision::Ask);
        assert_eq!(decide(&write, PolicyMode::Auto), ToolDecision::Allow);

        assert_eq!(
            decide(&destructive, PolicyMode::Restricted),
            ToolDecision::Deny
        );
        assert_eq!(decide(&destructive, PolicyMode::Manual), ToolDecision::Ask);
        assert_eq!(decide(&destructive, PolicyMode::Auto), ToolDecision::Ask);

        // An unannotated destructive marker follows the same destructive row.
        assert_eq!(
            decide(&tool("delete_file", schema_a()), PolicyMode::Restricted),
            ToolDecision::Deny
        );
    }

    #[test]
    fn response_limits_reject_each_dimension_without_echoing_content() {
        let limits = ResponseLimits {
            max_content_bytes: 32,
            max_structured_bytes: 32,
            max_items: 1,
        };
        assert!(limits
            .check_tool_result(&[json!({"type": "text", "text": "hi"})], None)
            .is_ok());

        let too_many = limits
            .check_tool_result(
                &[
                    json!({"type": "text", "text": "a"}),
                    json!({"type": "text", "text": "b"}),
                ],
                None,
            )
            .unwrap_err();
        assert_eq!(too_many.code(), ErrorCode::LimitExceeded);
        assert!(too_many.message().contains("item count"));
        assert!(too_many.message().contains("1"));

        let secret = "TOKEN_SECRET_0123456789";
        let too_large = limits
            .check_tool_result(&[json!({"type": "text", "text": secret.repeat(4)})], None)
            .unwrap_err();
        assert_eq!(too_large.code(), ErrorCode::LimitExceeded);
        assert!(too_large.message().contains("content bytes"));
        assert!(!too_large.message().contains(secret));

        let structured = limits
            .check_tool_result(&[], Some(&json!({"payload": secret.repeat(4)})))
            .unwrap_err();
        assert_eq!(structured.code(), ErrorCode::LimitExceeded);
        assert!(structured.message().contains("structured content bytes"));
        assert!(!structured.message().contains(secret));
    }

    #[test]
    fn response_limits_validate_non_zero_caps() {
        let limits = ResponseLimits {
            max_content_bytes: 0,
            max_structured_bytes: 1,
            max_items: 1,
        };
        assert_eq!(
            limits.validate().unwrap_err().code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn timeout_policy_validates_and_reports_total_budget_exhaustion() {
        let policy = TimeoutPolicy::default();
        assert!(policy.validate().is_ok());
        assert_eq!(
            policy.request_timeout(),
            Duration::from_millis(DEFAULT_REQUEST_TIMEOUT_MS)
        );
        assert!(policy.check_elapsed(policy.total_ms - 1).is_ok());
        let error = policy.check_elapsed(policy.total_ms).unwrap_err();
        assert_eq!(error.code(), ErrorCode::Timeout);
        assert!(error.message().contains(&policy.total_ms.to_string()));

        assert_eq!(
            TimeoutPolicy {
                request_ms: 0,
                total_ms: 1_000
            }
            .validate()
            .unwrap_err()
            .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            TimeoutPolicy {
                request_ms: 2_000,
                total_ms: 1_000
            }
            .validate()
            .unwrap_err()
            .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            TimeoutPolicy {
                request_ms: MAX_REQUEST_TIMEOUT_MS + 1,
                total_ms: MAX_TOTAL_TIMEOUT_MS,
            }
            .validate()
            .unwrap_err()
            .code(),
            ErrorCode::LimitExceeded
        );
        assert!(TimeoutPolicy::new(1_000, 5_000).is_ok());
    }

    #[test]
    fn resource_urls_allow_public_http_and_https() {
        for url in [
            "https://example.com/resource",
            "http://example.com:8080/resource",
            "https://example.com/a?b=c",
            "https://198.51.100.10/resource",
        ] {
            assert!(check_resource_url(url).is_ok(), "{url}");
        }
    }

    #[test]
    fn resource_urls_refuse_loopback_private_link_local_metadata_and_schemes() {
        for url in [
            "http://localhost/",
            "http://localhost./",
            "http://foo.localhost/",
            "http://127.0.0.1/",
            "http://127.9.9.9/",
            "http://2130706433/",
            "http://0x7f000001/",
            "http://0177.0.0.1/",
            "http://[::1]/",
            "http://10.1.2.3/",
            "http://172.16.0.1/",
            "http://192.168.0.1/",
            "http://100.64.0.1/",
            "http://169.254.169.254/latest/meta-data",
            "http://[fd00:ec2::254]/",
            "http://[fe80::1]/",
            "http://0.0.0.0/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:10.0.0.1]/",
            "http://metadata.google.internal/",
            "file:///etc/passwd",
            "data:text/plain,hello",
            "javascript:alert(1)",
            "https://user:pass@example.com/resource",
            "https://user@example.com/resource",
        ] {
            let result = check_resource_url(url);
            assert!(result.is_err(), "{url} was accepted");
            assert_eq!(result.unwrap_err().code(), ErrorCode::PolicyDenied, "{url}");
        }
    }

    #[test]
    fn resource_url_errors_do_not_echo_the_url_or_its_secrets() {
        let error = check_resource_url(
            "https://user:pass@example.com/resource?token=TOKEN_SECRET_0123456789",
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(!error.message().contains("TOKEN_SECRET"));
        assert!(!error.message().contains("example.com"));
        assert!(!error.message().contains("pass"));

        for url in ["not a url", "http://", "https://"] {
            let error = check_resource_url(url).unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidInput);
        }
    }

    #[test]
    fn replay_repeats_inside_the_window_and_expires_after_it() {
        let mut guard = ReplayGuard::new(100, 8).unwrap();
        assert_eq!(
            guard.check_and_record("request-1", 1_000),
            ReplayOutcome::Fresh
        );
        assert_eq!(
            guard.check_and_record("request-1", 1_050),
            ReplayOutcome::Replay
        );
        assert_eq!(
            guard.check_and_record("request-1", 1_101),
            ReplayOutcome::Expired
        );
        assert_eq!(
            guard.check_and_record("request-1", 1_102),
            ReplayOutcome::Replay
        );
    }

    #[test]
    fn replay_evicts_the_oldest_id_at_capacity() {
        let mut guard = ReplayGuard::new(1_000, 2).unwrap();
        assert_eq!(guard.check_and_record("a", 1), ReplayOutcome::Fresh);
        assert_eq!(guard.check_and_record("b", 2), ReplayOutcome::Fresh);
        assert_eq!(guard.check_and_record("c", 3), ReplayOutcome::Fresh);
        assert_eq!(guard.len(), 2);
        // `a` was evicted, so it is no longer a replay.
        assert_eq!(guard.check_and_record("a", 4), ReplayOutcome::Fresh);
    }

    #[test]
    fn replay_prunes_expired_entries_on_every_check() {
        let mut guard = ReplayGuard::new(10, 8).unwrap();
        assert_eq!(guard.check_and_record("a", 0), ReplayOutcome::Fresh);
        assert_eq!(guard.check_and_record("b", 0), ReplayOutcome::Fresh);
        assert_eq!(guard.check_and_record("c", 100), ReplayOutcome::Fresh);
        assert_eq!(guard.len(), 1);
        assert_eq!(guard.check_and_record("a", 100), ReplayOutcome::Fresh);
    }

    #[test]
    fn replay_pairs_do_not_collide_across_methods() {
        let mut guard = ReplayGuard::new(1_000, 8).unwrap();
        assert_eq!(
            guard.check_and_record_pair("1", "tools/call", 10),
            ReplayOutcome::Fresh
        );
        assert_eq!(
            guard.check_and_record_pair("1", "tools/list", 11),
            ReplayOutcome::Fresh
        );
        assert_eq!(
            guard.check_and_record_pair("1", "tools/call", 12),
            ReplayOutcome::Replay
        );
    }

    #[test]
    fn replay_rejects_a_zero_window_or_capacity() {
        assert_eq!(
            ReplayGuard::new(0, 1).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            ReplayGuard::new(1, 0).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
        let defaults = ReplayGuard::default();
        assert_eq!(defaults.ttl_ms(), DEFAULT_REPLAY_TTL_MS);
        assert_eq!(defaults.capacity(), DEFAULT_REPLAY_CAPACITY);
        assert!(defaults.is_empty());
    }

    #[test]
    fn approval_errors_name_tools_but_never_descriptions() {
        let mut first_tool = tool("search", schema_a());
        first_tool.description = Some("SECRET_PROMPT_0123456789".to_string());
        let first = catalog(vec![first_tool]);
        let second = catalog(vec![tool("search", schema_b())]);

        let mut store = SchemaPinStore::new();
        store.pin_catalog("server", &first);
        let error = store
            .require_approval("server", &second, &SchemaApproval::empty("server"))
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyAskRequired);
        assert!(error.message().contains("search"));
        assert!(!error.message().contains("SECRET_PROMPT_0123456789"));
    }
}
