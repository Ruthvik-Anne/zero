//! Declarative monitors (MON-07, MON-08, MON-09, MON-10; T-MON-03).
//!
//! A plugin (or a project manifest) declares monitors as data: a name, the
//! executable to run, a description, and a trigger. [`load_manifest`] validates
//! the document and produces a [`MonitorRegistry`]; [`start_for`] starts the
//! definitions that match a trigger through the existing [`MonitorEngine`].
//!
//! # Safety
//!
//! Declarative monitors are untrusted input. [`MonitorPolicy`] is deny-by-
//! default: an empty command allowlist, no shell, no network, no local targets,
//! and no allowed roots. [`check`] runs before any spawn, so a refused
//! definition never becomes a child process. [`start_for`] reports a refusal as
//! a typed [`MonitorRefusal`] and keeps starting the remaining definitions; one
//! bad plugin monitor does not abort the whole trigger.
//!
//! The engine is still the only spawn path. This module never wraps a command in
//! a shell. `requires_shell` is a declaration that the named command is itself a
//! shell (or needs one); it is admitted only when the policy sets
//! `allow_shell`.
//!
//! # Sources
//!
//! [`MonitorSource`] declares what the child observes. The command is the
//! implementation for every source, so a plugin can bring its own watcher. For
//! log tails, directory watches, CI polls, and WebSocket feeds the validated
//! target is handed to the child as `ZERO_MONITOR_SOURCE_TARGET` (with
//! `ZERO_MONITOR_SOURCE_KIND`); a `Script` source gets no extra variables. The
//! engine does not embed `tail`, a directory watcher, or a WebSocket client
//! itself (no new dependency), and it does not poll the network on its own.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::monitor::{MonitorEngine, MonitorHandle, MonitorSpec, MonitorStatus, DEFAULT_LINE_CAP_BYTES};

/// Schema version understood by [`load_manifest`].
pub const MONITOR_MANIFEST_SCHEMA_VERSION: u32 = 1;
/// Default bound on a manifest document.
pub const DEFAULT_MANIFEST_MAX_BYTES: usize = 256 * 1024;
/// Default bound on the number of monitors in one manifest.
pub const DEFAULT_MANIFEST_MAX_MONITORS: usize = 64;

/// Environment variable naming the declared source kind for a monitor child.
pub const SOURCE_KIND_ENV: &str = "ZERO_MONITOR_SOURCE_KIND";
/// Environment variable carrying the validated source target for a child.
pub const SOURCE_TARGET_ENV: &str = "ZERO_MONITOR_SOURCE_TARGET";

const SUPPORTED_POLL_SCHEMES: &[&str] = &["http", "https"];
const SUPPORTED_WEBSOCKET_SCHEMES: &[&str] = &["wss"];

// ---------------------------------------------------------------------------
// Definitions
// ---------------------------------------------------------------------------

/// What starts a declarative monitor (MON-08).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonitorWhen {
    /// Started explicitly by a user or caller.
    Manual,
    /// Started when a session opens.
    SessionStart,
    /// Started when a skill with this name is invoked. Matching ignores ASCII
    /// case.
    SkillInvoke(String),
}

impl MonitorWhen {
    /// A borrowed key for [`MonitorRegistry::for_trigger`].
    pub fn key(&self) -> MonitorWhenKey<'_> {
        match self {
            Self::Manual => MonitorWhenKey::Manual,
            Self::SessionStart => MonitorWhenKey::SessionStart,
            Self::SkillInvoke(skill) => MonitorWhenKey::SkillInvoke(skill),
        }
    }
}

impl Serialize for MonitorWhen {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let text = match self {
            Self::Manual => "manual".to_string(),
            Self::SessionStart => "session_start".to_string(),
            Self::SkillInvoke(skill) => format!("skill:{skill}"),
        };
        serializer.serialize_str(&text)
    }
}

impl<'de> Deserialize<'de> for MonitorWhen {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        let text = raw.trim();
        if text.eq_ignore_ascii_case("manual") {
            return Ok(Self::Manual);
        }
        if text.eq_ignore_ascii_case("session_start") || text.eq_ignore_ascii_case("session-start") {
            return Ok(Self::SessionStart);
        }
        if let Some(skill) = text.strip_prefix("skill:") {
            let skill = skill.trim();
            if skill.is_empty() {
                return Err(serde::de::Error::custom(
                    "`when` of the form `skill:<name>` needs a non-empty skill name",
                ));
            }
            return Ok(Self::SkillInvoke(skill.to_string()));
        }
        Err(serde::de::Error::custom(
            "`when` must be `manual`, `session_start`, or `skill:<name>`",
        ))
    }
}

/// A borrowed trigger for registry lookup and [`start_for`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorWhenKey<'a> {
    Manual,
    SessionStart,
    SkillInvoke(&'a str),
}

impl MonitorWhenKey<'_> {
    /// True when `when` matches this trigger. Skill names compare ignoring
    /// ASCII case; different trigger kinds never match each other.
    pub fn matches(self, when: &MonitorWhen) -> bool {
        match (self, when) {
            (Self::Manual, MonitorWhen::Manual) | (Self::SessionStart, MonitorWhen::SessionStart) => {
                true
            }
            (Self::SkillInvoke(left), MonitorWhen::SkillInvoke(right)) => {
                left.eq_ignore_ascii_case(right)
            }
            _ => false,
        }
    }
}

/// What a declarative monitor observes (MON-07).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MonitorSource {
    /// A long-running or self-terminating script; the default.
    #[default]
    Script,
    /// A file that the command tails.
    #[serde(alias = "log")]
    LogTail { path: PathBuf },
    /// A directory that the command watches.
    #[serde(alias = "directory")]
    DirectoryWatch { path: PathBuf },
    /// A CI or pull-request endpoint that the command polls.
    #[serde(alias = "ci")]
    CiPoll { url: String },
    /// A WebSocket feed; only `wss` is accepted.
    #[serde(rename = "websocket", alias = "web_socket", alias = "ws")]
    WebSocket { url: String },
}

impl MonitorSource {
    /// Declared kind, as handed to the child.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Script => "script",
            Self::LogTail { .. } => "log_tail",
            Self::DirectoryWatch { .. } => "directory_watch",
            Self::CiPoll { .. } => "ci_poll",
            Self::WebSocket { .. } => "websocket",
        }
    }

    /// The path or URL the source targets, when it has one.
    pub fn target(&self) -> Option<String> {
        match self {
            Self::Script => None,
            Self::LogTail { path } | Self::DirectoryWatch { path } => {
                Some(path.to_string_lossy().into_owned())
            }
            Self::CiPoll { url } | Self::WebSocket { url } => Some(url.clone()),
        }
    }
}

/// One declarative monitor (MON-09 shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorDefinition {
    /// Unique (case-insensitive) monitor name; also the engine id.
    #[serde(default)]
    pub name: String,
    /// Executable, never a shell string.
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub description: String,
    pub when: MonitorWhen,
    #[serde(default)]
    pub source: MonitorSource,
    #[serde(default)]
    pub requires_shell: bool,
    /// Optional per-line output cap. It may not exceed
    /// [`MonitorPolicy::max_output_bytes`]; [`check`] refuses the definition
    /// instead of silently truncating a larger declaration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_bytes: Option<usize>,
}

impl MonitorDefinition {
    /// True when `name` matches, ignoring ASCII case.
    pub fn has_name(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }

    /// The engine spec this definition expands to under `policy`.
    ///
    /// `check` must have accepted the definition first. The effective output
    /// cap is the smaller of the definition's declaration and the policy's cap;
    /// since `check` refuses a larger declaration, this is the definition's
    /// value or the policy's.
    pub fn to_spec(&self, policy: &MonitorPolicy) -> MonitorSpec {
        let cap = self.max_output_bytes.unwrap_or(policy.max_output_bytes);
        let mut spec = MonitorSpec::new(self.name.clone(), self.name.clone(), self.command.clone())
            .args(self.args.clone())
            .description(self.description.clone());
        spec.max_output_bytes = Some(cap);
        if let Some(target) = self.source.target() {
            spec = spec
                .env(SOURCE_KIND_ENV, self.source.kind())
                .env(SOURCE_TARGET_ENV, target);
        }
        spec
    }
}

/// A parsed manifest document. Unknown JSON fields are ignored so a newer
/// producer can add fields without breaking an older reader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorManifest {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub monitors: Vec<MonitorDefinition>,
}

fn default_schema_version() -> u32 {
    MONITOR_MANIFEST_SCHEMA_VERSION
}

/// Bounds applied before a manifest is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitorManifestLimits {
    pub max_bytes: usize,
    pub max_monitors: usize,
}

impl MonitorManifestLimits {
    pub fn new(max_bytes: usize, max_monitors: usize) -> Self {
        Self { max_bytes, max_monitors }
    }
}

impl Default for MonitorManifestLimits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MANIFEST_MAX_BYTES,
            max_monitors: DEFAULT_MANIFEST_MAX_MONITORS,
        }
    }
}

/// The validated definitions from one manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MonitorRegistry {
    definitions: Vec<MonitorDefinition>,
}

impl MonitorRegistry {
    pub fn new(definitions: Vec<MonitorDefinition>) -> Self {
        Self { definitions }
    }

    pub fn definitions(&self) -> &[MonitorDefinition] {
        &self.definitions
    }

    pub fn len(&self) -> usize {
        self.definitions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.definitions.is_empty()
    }

    /// Definitions whose `when` matches `trigger`, in manifest order.
    pub fn for_trigger(&self, trigger: MonitorWhenKey<'_>) -> Vec<&MonitorDefinition> {
        self.definitions.iter().filter(|definition| trigger.matches(&definition.when)).collect()
    }

    /// Load and validate a manifest file with the default bounds.
    pub fn load_file(path: impl AsRef<Path>) -> Result<Self> {
        Self::load_file_with_limits(path, MonitorManifestLimits::default())
    }

    /// Load and validate a manifest file, checking the file size before read.
    pub fn load_file_with_limits(
        path: impl AsRef<Path>,
        limits: MonitorManifestLimits,
    ) -> Result<Self> {
        let path = path.as_ref();
        let metadata = std::fs::metadata(path)?;
        if !metadata.is_file() {
            return Err(config_invalid(format!(
                "monitor manifest `{}` is not a regular file",
                path.display()
            )));
        }
        if metadata.len() > u64::try_from(limits.max_bytes).unwrap_or(u64::MAX) {
            return Err(limit_exceeded(format!(
                "monitor manifest `{}` is {} bytes; the limit is {}",
                path.display(),
                metadata.len(),
                limits.max_bytes
            )));
        }
        let text = std::fs::read_to_string(path)?;
        load_manifest(&text, limits)
    }
}

/// Parse, validate, and bound a manifest document.
///
/// Errors are typed: `Serialization` for malformed JSON, `SchemaVersion` for an
/// unsupported version, `LimitExceeded` for the byte or count bound,
/// `AlreadyExists` for a duplicate name, and `ConfigInvalid` for a definition
/// that fails semantic validation (empty command/description, bad `when`,
/// relative or UNC local target, malformed or insecure URL scheme, zero output
/// cap).
pub fn load_manifest(text: &str, limits: MonitorManifestLimits) -> Result<MonitorRegistry> {
    if text.len() > limits.max_bytes {
        return Err(limit_exceeded(format!(
            "monitor manifest is {} bytes; the limit is {}",
            text.len(),
            limits.max_bytes
        )));
    }
    let mut manifest: MonitorManifest = serde_json::from_str(text)?;
    if manifest.schema_version != MONITOR_MANIFEST_SCHEMA_VERSION {
        return Err(ZeroError::new(
            ErrorCode::SchemaVersion,
            format!(
                "monitor manifest schema version {} is not supported; expected {}",
                manifest.schema_version, MONITOR_MANIFEST_SCHEMA_VERSION
            ),
        ));
    }
    if manifest.monitors.len() > limits.max_monitors {
        return Err(limit_exceeded(format!(
            "monitor manifest declares {} monitors; the limit is {}",
            manifest.monitors.len(),
            limits.max_monitors
        )));
    }

    let mut names = BTreeSet::new();
    for definition in &mut manifest.monitors {
        definition.name = definition.name.trim().to_string();
        definition.command = definition.command.trim().to_string();
        definition.description = definition.description.trim().to_string();
        validate_definition(definition)?;
        if !names.insert(definition.name.to_ascii_lowercase()) {
            return Err(ZeroError::new(
                ErrorCode::AlreadyExists,
                format!("monitor name `{}` is declared more than once (names ignore case)", definition.name),
            ));
        }
    }
    Ok(MonitorRegistry { definitions: manifest.monitors })
}

fn validate_definition(definition: &MonitorDefinition) -> Result<()> {
    if definition.name.is_empty() {
        return Err(config_invalid("monitor manifest contains a definition with an empty name"));
    }
    if definition.command.is_empty() {
        return Err(config_invalid(format!("monitor `{}` has an empty command", definition.name)));
    }
    if definition.description.is_empty() {
        return Err(config_invalid(format!(
            "monitor `{}` has an empty description",
            definition.name
        )));
    }
    if definition.command.contains('\0') || definition.args.iter().any(|arg| arg.contains('\0')) {
        return Err(config_invalid(format!("monitor `{}` contains a NUL byte", definition.name)));
    }
    if let MonitorWhen::SkillInvoke(skill) = &definition.when {
        if skill.trim().is_empty() {
            return Err(config_invalid(format!(
                "monitor `{}` declares an empty skill trigger",
                definition.name
            )));
        }
    }
    if definition.max_output_bytes == Some(0) {
        return Err(config_invalid(format!(
            "monitor `{}` declares a zero output cap",
            definition.name
        )));
    }
    match &definition.source {
        MonitorSource::Script => {}
        MonitorSource::LogTail { path } => validate_local_path(definition, path, "log tail")?,
        MonitorSource::DirectoryWatch { path } => {
            validate_local_path(definition, path, "directory watch")?;
        }
        MonitorSource::CiPoll { url } => {
            validate_source_url(definition, url, "CI poll", SUPPORTED_POLL_SCHEMES)?;
        }
        MonitorSource::WebSocket { url } => {
            validate_source_url(definition, url, "WebSocket", SUPPORTED_WEBSOCKET_SCHEMES)?;
        }
    }
    Ok(())
}

fn validate_local_path(definition: &MonitorDefinition, path: &Path, kind: &str) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(config_invalid(format!(
            "monitor `{}` has an empty {kind} path",
            definition.name
        )));
    }
    if !path.is_absolute() {
        return Err(config_invalid(format!(
            "monitor `{}` {kind} path `{}` must be absolute",
            definition.name,
            path.display()
        )));
    }
    if is_network_path(path) {
        return Err(config_invalid(format!(
            "monitor `{}` {kind} path `{}` is a network path, not a local target",
            definition.name,
            path.display()
        )));
    }
    Ok(())
}

fn validate_source_url(
    definition: &MonitorDefinition,
    url: &str,
    kind: &str,
    schemes: &[&str],
) -> Result<()> {
    let parts = parse_http_url(url).ok_or_else(|| {
        config_invalid(format!(
            "monitor `{}` has a malformed {kind} URL `{url}`",
            definition.name
        ))
    })?;
    if !schemes.contains(&parts.scheme.as_str()) {
        return Err(config_invalid(format!(
            "monitor `{}` {kind} URL scheme `{}` is not allowed; use {}",
            definition.name,
            parts.scheme,
            schemes.join(" or ")
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Safety policy (MON-10)
// ---------------------------------------------------------------------------

/// Deny-by-default policy for declarative monitors (MON-10).
///
/// The default refuses every command (empty allowlist), every shell, every
/// network source, every local target, and accepts no roots. A caller must opt
/// in field by field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorPolicy {
    /// Command basenames that may run. An empty list denies every command.
    pub allowed_commands: Vec<String>,
    /// Admit definitions with `requires_shell: true`.
    pub allow_shell: bool,
    /// Admit `CiPoll` and `WebSocket` sources.
    pub allow_network: bool,
    /// Per-line output cap handed to the engine spec. Zero is an invalid policy.
    pub max_output_bytes: usize,
    /// Admit `LogTail` and `DirectoryWatch` sources.
    pub allow_local_targets: bool,
    /// Roots that contain every local target. A target outside every root is
    /// refused.
    pub allowed_roots: Vec<PathBuf>,
}

impl Default for MonitorPolicy {
    fn default() -> Self {
        Self {
            allowed_commands: Vec::new(),
            allow_shell: false,
            allow_network: false,
            max_output_bytes: DEFAULT_LINE_CAP_BYTES,
            allow_local_targets: false,
            allowed_roots: Vec::new(),
        }
    }
}

/// Check one definition against one policy. Never spawns anything.
///
/// Refusals use `PermissionDenied`; malformed input and an invalid policy use
/// `InvalidInput`; a declared output cap above the policy's cap uses
/// `LimitExceeded`.
pub fn check(definition: &MonitorDefinition, policy: &MonitorPolicy) -> Result<()> {
    if definition.name.trim().is_empty() {
        return Err(invalid_input("monitor name is empty"));
    }
    if policy.max_output_bytes == 0 {
        return Err(invalid_input(
            "monitor policy max_output_bytes must be greater than zero",
        ));
    }
    check_command(definition, policy)?;
    check_output_cap(definition, policy)?;
    match &definition.source {
        MonitorSource::Script => Ok(()),
        MonitorSource::LogTail { path } => check_local_target(path, "log tail", policy),
        MonitorSource::DirectoryWatch { path } => {
            check_local_target(path, "directory watch", policy)
        }
        MonitorSource::CiPoll { url } => {
            check_remote_url(url, "CI poll", SUPPORTED_POLL_SCHEMES, policy)
        }
        MonitorSource::WebSocket { url } => {
            check_remote_url(url, "WebSocket", SUPPORTED_WEBSOCKET_SCHEMES, policy)
        }
    }
}

fn check_command(definition: &MonitorDefinition, policy: &MonitorPolicy) -> Result<()> {
    let command = definition.command.trim();
    if command.is_empty() {
        return Err(invalid_input("monitor command is empty"));
    }
    let Some(basename) = Path::new(command).file_name().and_then(|name| name.to_str()) else {
        return Err(denied(format!("command `{command}` has no usable file name")));
    };
    if policy.allowed_commands.is_empty() {
        return Err(denied(format!(
            "no commands are allowlisted; `{basename}` is refused"
        )));
    }
    if !policy.allowed_commands.iter().any(|allowed| allowed == basename) {
        return Err(denied(format!(
            "command `{basename}` is not in the monitor allowlist"
        )));
    }
    if definition.requires_shell && !policy.allow_shell {
        return Err(denied(format!(
            "command `{basename}` requires a shell; shell monitors are disabled"
        )));
    }
    Ok(())
}

fn check_output_cap(definition: &MonitorDefinition, policy: &MonitorPolicy) -> Result<()> {
    let Some(declared) = definition.max_output_bytes else {
        return Ok(());
    };
    if declared == 0 {
        return Err(invalid_input(format!(
            "monitor `{}` declares a zero output cap",
            definition.name
        )));
    }
    if declared > policy.max_output_bytes {
        return Err(ZeroError::new(
            ErrorCode::LimitExceeded,
            format!(
                "monitor `{}` declares a {declared}-byte output cap; the policy allows {}; \
                 the definition is refused instead of silently truncated",
                definition.name, policy.max_output_bytes
            ),
        ));
    }
    Ok(())
}

fn check_remote_url(
    url: &str,
    kind: &str,
    schemes: &[&str],
    policy: &MonitorPolicy,
) -> Result<()> {
    if !policy.allow_network {
        return Err(denied(format!("{kind} sources need network access; network is disabled")));
    }
    let parts = parse_http_url(url)
        .ok_or_else(|| invalid_input(format!("{kind} URL `{url}` is malformed")))?;
    if !schemes.contains(&parts.scheme.as_str()) {
        return Err(denied(format!(
            "{kind} URL scheme `{}` is not allowed; use {}",
            parts.scheme,
            schemes.join(" or ")
        )));
    }
    if parts.has_userinfo {
        return Err(denied(format!("{kind} URL must not embed credentials")));
    }
    if let Some(reason) = denied_host_reason(&parts.host) {
        return Err(denied(format!(
            "{kind} URL host `{}` is refused: {reason} addresses are not allowed",
            parts.host
        )));
    }
    Ok(())
}

fn check_local_target(path: &Path, kind: &str, policy: &MonitorPolicy) -> Result<()> {
    if !policy.allow_local_targets {
        return Err(denied(format!("{kind} sources need local targets; local targets are disabled")));
    }
    if !path.is_absolute() {
        return Err(denied(format!("{kind} path `{}` must be absolute", path.display())));
    }
    if is_network_path(path) {
        return Err(denied(format!(
            "{kind} path `{}` is a network path, not a local target",
            path.display()
        )));
    }
    if policy.allowed_roots.is_empty() {
        return Err(denied(format!(
            "{kind} path `{}` has no allowed root; add one to the policy",
            path.display()
        )));
    }
    let Some(target) = lexical_normalize(path) else {
        return Err(denied(format!(
            "{kind} path `{}` is not a normalized absolute path",
            path.display()
        )));
    };
    let mut inside = false;
    for root in &policy.allowed_roots {
        let Some(root) = lexical_normalize(root) else {
            continue;
        };
        if !path_starts_with(&target, &root) {
            continue;
        }
        // When both paths exist, the filesystem view must agree with the
        // lexical one. This catches a symlink that points out of an allowed
        // root without trusting a stale or missing path.
        if let (Ok(canonical_target), Ok(canonical_root)) =
            (std::fs::canonicalize(path), std::fs::canonicalize(root.as_path()))
        {
            if !path_starts_with(&canonical_target, &canonical_root) {
                continue;
            }
        }
        inside = true;
        break;
    }
    if !inside {
        return Err(denied(format!(
            "{kind} path `{}` is outside the allowed roots",
            path.display()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// True for a Windows UNC path or a `//`-rooted path. Both describe a remote or
/// ambiguous location, never a local sandbox root.
fn is_network_path(path: &Path) -> bool {
    let text = path.to_string_lossy();
    text.starts_with("\\\\") || text.starts_with("//")
}

/// Lexically resolve `.` and `..` without touching the filesystem. `None` for a
/// relative path or one that climbs above its root.
fn lexical_normalize(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => out.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::Normal(part) => out.push(part),
        }
    }
    Some(out)
}

/// Component-wise prefix test. Windows compares components ignoring ASCII case.
fn path_starts_with(path: &Path, root: &Path) -> bool {
    let mut path = path.components();
    let mut root = root.components();
    loop {
        match (root.next(), path.next()) {
            (None, _) => return true,
            (Some(_), None) => return false,
            (Some(left), Some(right)) => {
                let equal = if cfg!(windows) {
                    left.as_os_str().to_string_lossy().eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
                } else {
                    left == right
                };
                if !equal {
                    return false;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

struct ParsedUrl {
    scheme: String,
    host: String,
    has_userinfo: bool,
}

/// Minimal absolute-URL parser: scheme, authority, host, and userinfo. No
/// percent-decoding and no DNS, so the policy can stay offline.
fn parse_http_url(input: &str) -> Option<ParsedUrl> {
    let url = input.trim();
    if url.is_empty() || url.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
        return None;
    }
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty() || !scheme.chars().next()?.is_ascii_alphabetic() {
        return None;
    }
    if !scheme
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'))
    {
        return None;
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return None;
    }
    let (has_userinfo, hostport) = match authority.rsplit_once('@') {
        Some((_, hostport)) => (true, hostport),
        None => (false, authority),
    };
    if hostport.is_empty() {
        return None;
    }
    let host = if let Some(stripped) = hostport.strip_prefix('[') {
        let (inside, after) = stripped.split_once(']')?;
        if !after.is_empty() {
            let port = after.strip_prefix(':')?;
            if port.is_empty() || !port.chars().all(|ch| ch.is_ascii_digit()) {
                return None;
            }
            port.parse::<u16>().ok()?;
        }
        inside
    } else {
        let (candidate, port) = match hostport.rsplit_once(':') {
            Some((host, port)) if !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) => {
                (host, Some(port))
            }
            _ => (hostport, None),
        };
        if let Some(port) = port {
            port.parse::<u16>().ok()?;
        }
        if candidate.contains(':') {
            return None;
        }
        candidate
    };
    if host.is_empty() || host.chars().any(|ch| matches!(ch, '/' | '?' | '#' | '@')) {
        return None;
    }
    Some(ParsedUrl {
        scheme: scheme.to_ascii_lowercase(),
        host: host.to_ascii_lowercase(),
        has_userinfo,
    })
}

/// Why a URL host is not a public destination. Names that merely resolve to a
/// private address through DNS are not detected: the policy never performs
/// network lookups.
fn denied_host_reason(host: &str) -> Option<&'static str> {
    if host.contains('%') {
        return Some("link-local (IPv6 zone)");
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Some("empty");
    }
    if host == "localhost" || host.ends_with(".localhost") {
        return Some("loopback");
    }
    if host == "local" || host.ends_with(".local") {
        return Some("link-local");
    }
    if host == "metadata"
        || host == "metadata.google.internal"
        || host.ends_with(".metadata.google.internal")
        || host == "instance-data"
        || host == "instance-data.ec2.internal"
        || host.ends_with(".instance-data.ec2.internal")
    {
        return Some("cloud metadata");
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return denied_ip_reason(ip);
    }
    // Some resolvers accept bare decimal or hexadecimal IPv4 literals.
    if host.chars().all(|ch| ch.is_ascii_digit()) {
        if let Ok(value) = host.parse::<u32>() {
            return denied_ip_reason(IpAddr::V4(Ipv4Addr::from(value)));
        }
    }
    if let Some(hex) = host.strip_prefix("0x") {
        if let Ok(value) = u32::from_str_radix(hex, 16) {
            return denied_ip_reason(IpAddr::V4(Ipv4Addr::from(value)));
        }
    }
    None
}

fn denied_ip_reason(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(address) => {
            if address.is_loopback() {
                Some("loopback")
            } else if address.is_private() {
                Some("private")
            } else if address.is_link_local() {
                Some("link-local")
            } else if address.is_unspecified() || address.is_broadcast() {
                Some("unspecified")
            } else if is_shared_address(address) {
                Some("shared")
            } else if address.octets()[0] == 0 {
                Some("this-network")
            } else {
                None
            }
        }
        IpAddr::V6(address) => {
            if address.is_loopback() {
                return Some("loopback");
            }
            if address.is_unspecified() {
                return Some("unspecified");
            }
            if let Some(mapped) = address.to_ipv4() {
                return denied_ip_reason(IpAddr::V4(mapped));
            }
            let first = address.segments()[0];
            if first & 0xffc0 == 0xfe80 {
                Some("link-local")
            } else if first & 0xfe00 == 0xfc00 {
                Some("unique-local")
            } else {
                None
            }
        }
    }
}

fn is_shared_address(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

// ---------------------------------------------------------------------------
// Triggered start and session stop (MON-08)
// ---------------------------------------------------------------------------

/// One definition refused at start time, with its typed reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorRefusal {
    pub name: String,
    pub code: ErrorCode,
    pub message: String,
}

impl MonitorRefusal {
    pub fn from_error(name: &str, error: &ZeroError) -> Self {
        Self {
            name: name.to_string(),
            code: error.code(),
            message: error.message().to_string(),
        }
    }
}

/// What one trigger started and what it skipped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MonitorTriggerReport {
    pub started: Vec<MonitorHandle>,
    pub skipped: Vec<MonitorRefusal>,
}

impl MonitorTriggerReport {
    pub fn is_empty(&self) -> bool {
        self.started.is_empty() && self.skipped.is_empty()
    }
}

/// Start every definition matching `trigger` and return the spawned handles.
///
/// This is [`start_for_report`] with the skip details projected away.
pub fn start_for(
    trigger: MonitorWhenKey<'_>,
    registry: &MonitorRegistry,
    policy: &MonitorPolicy,
    engine: &mut MonitorEngine,
    now_ms: i64,
) -> Result<Vec<MonitorHandle>> {
    Ok(start_for_report(trigger, registry, policy, engine, now_ms)?.started)
}

/// Start every definition matching `trigger`.
///
/// A definition refused by [`check`], already running under the same name, or
/// failing to spawn is recorded in [`MonitorTriggerReport::skipped`] and does
/// not abort the trigger. Start is idempotent while a monitor with that name is
/// running; a name retained by the engine in `Stopped`/`Failed` is skipped too
/// because restart after exit needs explicit confirmation (T-MON-04).
pub fn start_for_report(
    trigger: MonitorWhenKey<'_>,
    registry: &MonitorRegistry,
    policy: &MonitorPolicy,
    engine: &mut MonitorEngine,
    now_ms: i64,
) -> Result<MonitorTriggerReport> {
    let mut report = MonitorTriggerReport::default();
    for definition in registry.for_trigger(trigger) {
        if let Err(error) = check(definition, policy) {
            report.skipped.push(MonitorRefusal::from_error(&definition.name, &error));
            continue;
        }
        if let Some(status) = engine.status(&definition.name) {
            let message = match status {
                MonitorStatus::Running | MonitorStatus::Starting => format!(
                    "monitor `{}` is already running; start is idempotent",
                    definition.name
                ),
                MonitorStatus::Stopped | MonitorStatus::Failed => format!(
                    "monitor `{}` is already registered as {status:?}; restart needs confirmation",
                    definition.name
                ),
            };
            report.skipped.push(MonitorRefusal {
                name: definition.name.clone(),
                code: ErrorCode::AlreadyExists,
                message,
            });
            continue;
        }
        match engine.start(definition.to_spec(policy), now_ms) {
            Ok(handle) => report.started.push(handle),
            Err(error) => report.skipped.push(MonitorRefusal::from_error(&definition.name, &error)),
        }
    }
    Ok(report)
}

/// Stop every monitor in the engine (MON-08 session stop). Idempotent.
pub fn stop_all(engine: &mut MonitorEngine) -> Result<()> {
    let ids: Vec<String> = engine.ids().into_iter().map(str::to_owned).collect();
    let mut first_error = None;
    for id in ids {
        if let Err(error) = engine.stop(&id, 0) {
            if error.code() != ErrorCode::NotFound && first_error.is_none() {
                first_error = Some(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Error constructors
// ---------------------------------------------------------------------------

fn denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PermissionDenied, message)
}

fn invalid_input(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn config_invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::ConfigInvalid, message)
}

fn limit_exceeded(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::monitor::{BurstWindow, MemoryLogSink, MonitorEvent, TRUNCATION_MARKER};

    const HELPER_LINE: &str = "DEFS-DEPLOY ok";
    const HELPER_LONG_LINE: &str = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

    // ----- child side -----------------------------------------------------

    /// Child side of the declarative-start tests. The parent spawns this test
    /// binary with `--exact` pointing at this test, so a normal `cargo test`
    /// run (which does not pass `--exact`) is a no-op.
    #[test]
    fn monitor_defs_helper_process() {
        if !std::env::args().any(|arg| arg == "--exact") {
            return;
        }
        use std::io::Write;
        let mut stdout = std::io::stdout();
        // Terminate libtest's `test ... ` prefix so payload lines stay whole.
        let _ = writeln!(stdout);
        let _ = writeln!(stdout, "{HELPER_LINE}");
        let _ = writeln!(stdout, "{HELPER_LONG_LINE}");
        let _ = stdout.flush();
        std::thread::sleep(Duration::from_millis(500));
    }

    // ----- helpers --------------------------------------------------------

    fn definition(name: &str, when: MonitorWhen) -> MonitorDefinition {
        MonitorDefinition {
            name: name.to_string(),
            command: "zero-tool".to_string(),
            args: Vec::new(),
            description: format!("{name} monitor"),
            when,
            source: MonitorSource::Script,
            requires_shell: false,
            max_output_bytes: None,
        }
    }

    fn policy_for(command: &str) -> MonitorPolicy {
        MonitorPolicy {
            allowed_commands: vec![command.to_string()],
            ..MonitorPolicy::default()
        }
    }

    fn definition_json(name: &str, when: &str) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "command": "zero-tool",
            "description": format!("{name} monitor"),
            "when": when,
        })
    }

    fn manifest_text(monitors: Vec<serde_json::Value>) -> String {
        serde_json::json!({
            "schema_version": MONITOR_MANIFEST_SCHEMA_VERSION,
            "monitors": monitors,
        })
        .to_string()
    }

    fn helper_args() -> Vec<String> {
        vec![
            "--exact".to_string(),
            "monitor_defs::tests::monitor_defs_helper_process".to_string(),
            "--nocapture".to_string(),
            "--test-threads=1".to_string(),
        ]
    }

    fn helper_basename() -> String {
        std::env::current_exe()
            .expect("current test executable")
            .file_name()
            .expect("test executable name")
            .to_string_lossy()
            .into_owned()
    }

    fn helper_definition(name: &str, when: MonitorWhen) -> MonitorDefinition {
        let exe = std::env::current_exe().expect("current test executable");
        MonitorDefinition {
            name: name.to_string(),
            command: exe.to_string_lossy().into_owned(),
            args: helper_args(),
            description: format!("{name} helper monitor"),
            when,
            source: MonitorSource::Script,
            requires_shell: false,
            max_output_bytes: None,
        }
    }

    fn drain_until_line(
        engine: &mut MonitorEngine,
        id: &str,
        wanted: &str,
        timeout: Duration,
    ) -> Vec<MonitorEvent> {
        let start = Instant::now();
        let mut now = 0i64;
        let mut events = Vec::new();
        loop {
            now += 5;
            let batch = engine.drain(now);
            let found = batch
                .iter()
                .flat_map(|event| event.lines.iter())
                .any(|line| line.contains(wanted));
            events.extend(batch);
            if found {
                return events;
            }
            assert!(start.elapsed() < timeout, "monitor `{id}` never printed `{wanted}`");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    // ----- manifest parsing ----------------------------------------------

    #[test]
    fn manifest_parses_and_ignores_unknown_fields() {
        let log_path = std::env::temp_dir().join("zero-deploy.log");
        let text = serde_json::json!({
            "schema_version": 1,
            "future_field": {"anything": true},
            "monitors": [
                {
                    "name": "deploy-watch",
                    "command": "zwatch",
                    "args": ["--follow"],
                    "description": "watch deploys",
                    "when": "skill:deploy",
                    "source": {"kind": "log_tail", "path": log_path.clone()},
                    "future_definition_field": 7,
                },
                {
                    "name": "idle-ping",
                    "command": "zping",
                    "description": "heartbeat",
                    "when": "manual",
                },
            ],
        })
        .to_string();
        let registry = load_manifest(&text, MonitorManifestLimits::default()).expect("valid manifest");
        assert_eq!(registry.len(), 2);
        assert!(!registry.is_empty());

        let deploy = &registry.definitions()[0];
        assert_eq!(deploy.name, "deploy-watch");
        assert_eq!(deploy.args, vec!["--follow".to_string()]);
        assert_eq!(deploy.when, MonitorWhen::SkillInvoke("deploy".to_string()));
        assert_eq!(deploy.source, MonitorSource::LogTail { path: log_path });
        assert!(!deploy.requires_shell);

        let idle = &registry.definitions()[1];
        assert_eq!(idle.when, MonitorWhen::Manual);
        assert_eq!(idle.source, MonitorSource::Script, "an omitted source defaults to a script");
    }

    #[test]
    fn manifest_rejects_duplicate_names_ignoring_case() {
        let text = manifest_text(vec![
            definition_json("Deploy", "manual"),
            definition_json("deploy", "manual"),
        ]);
        let error = load_manifest(&text, MonitorManifestLimits::default()).expect_err("duplicate");
        assert_eq!(error.code(), ErrorCode::AlreadyExists);
        assert!(error.message().contains("deploy"), "{}", error.message());
    }

    #[test]
    fn manifest_reports_malformed_json_with_a_typed_error() {
        let error = load_manifest("{ not json", MonitorManifestLimits::default()).expect_err("bad");
        assert_eq!(error.code(), ErrorCode::Serialization);

        let text = serde_json::json!({
            "schema_version": 2,
            "monitors": [],
        })
        .to_string();
        let error = load_manifest(&text, MonitorManifestLimits::default()).expect_err("version");
        assert_eq!(error.code(), ErrorCode::SchemaVersion);
    }

    #[test]
    fn manifest_rejects_empty_command_description_and_when() {
        let missing_command = serde_json::json!({
            "name": "broken",
            "description": "x",
            "when": "manual",
        });
        let error = load_manifest(&manifest_text(vec![missing_command]), MonitorManifestLimits::default())
            .expect_err("empty command");
        assert_eq!(error.code(), ErrorCode::ConfigInvalid);

        let missing_description = serde_json::json!({
            "name": "broken",
            "command": "zero-tool",
            "when": "manual",
        });
        let error =
            load_manifest(&manifest_text(vec![missing_description]), MonitorManifestLimits::default())
                .expect_err("empty description");
        assert_eq!(error.code(), ErrorCode::ConfigInvalid);

        let bad_when = serde_json::json!({
            "name": "broken",
            "command": "zero-tool",
            "description": "x",
            "when": "sometimes",
        });
        let error = load_manifest(&manifest_text(vec![bad_when]), MonitorManifestLimits::default())
            .expect_err("bad when");
        assert_eq!(error.code(), ErrorCode::Serialization);
    }

    #[test]
    fn manifest_bounds_size_and_monitor_count() {
        let text = manifest_text(vec![definition_json("a", "manual"), definition_json("b", "manual")]);
        let error = load_manifest(&text, MonitorManifestLimits::new(text.len() - 1, 8))
            .expect_err("oversized");
        assert_eq!(error.code(), ErrorCode::LimitExceeded);

        let error = load_manifest(&text, MonitorManifestLimits::new(64 * 1024, 1))
            .expect_err("too many monitors");
        assert_eq!(error.code(), ErrorCode::LimitExceeded);
    }

    #[test]
    fn manifest_validates_local_paths_and_urls() {
        let relative = serde_json::json!({
            "name": "relative",
            "command": "zero-tool",
            "description": "x",
            "when": "manual",
            "source": {"kind": "log_tail", "path": "logs/deploy.log"},
        });
        let error = load_manifest(&manifest_text(vec![relative]), MonitorManifestLimits::default())
            .expect_err("relative path");
        assert_eq!(error.code(), ErrorCode::ConfigInvalid);

        let unc = serde_json::json!({
            "name": "unc",
            "command": "zero-tool",
            "description": "x",
            "when": "manual",
            "source": {"kind": "directory_watch", "path": PathBuf::from(r"\\server\share")},
        });
        let error = load_manifest(&manifest_text(vec![unc]), MonitorManifestLimits::default())
            .expect_err("network path");
        assert_eq!(error.code(), ErrorCode::ConfigInvalid);

        let plaintext = serde_json::json!({
            "name": "plaintext",
            "command": "zero-tool",
            "description": "x",
            "when": "manual",
            "source": {"kind": "websocket", "url": "ws://example.com/feed"},
        });
        let error = load_manifest(&manifest_text(vec![plaintext]), MonitorManifestLimits::default())
            .expect_err("plaintext websocket");
        assert_eq!(error.code(), ErrorCode::ConfigInvalid, "{}", error.message());

        let absolute = {
            let dir = tempfile::tempdir().expect("temp dir");
            let path = dir.path().join("deploy.log");
            serde_json::json!({
                "name": "tail",
                "command": "zero-tool",
                "description": "x",
                "when": "manual",
                "source": {"kind": "log_tail", "path": path},
            })
        };
        load_manifest(&manifest_text(vec![absolute]), MonitorManifestLimits::default())
            .expect("absolute local path loads");
    }

    #[test]
    fn load_file_reads_a_bounded_manifest() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("monitors.json");
        std::fs::write(&path, manifest_text(vec![definition_json("disk", "manual")])).expect("write");
        let registry = MonitorRegistry::load_file(&path).expect("load file");
        assert_eq!(registry.len(), 1);

        let error = MonitorRegistry::load_file_with_limits(&path, MonitorManifestLimits::new(8, 8))
            .expect_err("size bound");
        assert_eq!(error.code(), ErrorCode::LimitExceeded);

        let error = MonitorRegistry::load_file(dir.path().join("missing.json")).expect_err("missing");
        assert_eq!(error.code(), ErrorCode::NotFound);
    }

    // ----- triggers -------------------------------------------------------

    #[test]
    fn for_trigger_matches_manual_session_and_skill_ignoring_case() {
        let registry = MonitorRegistry::new(vec![
            definition("manual-one", MonitorWhen::Manual),
            definition("session-one", MonitorWhen::SessionStart),
            definition("deploy-one", MonitorWhen::SkillInvoke("Deploy".to_string())),
            definition("review-one", MonitorWhen::SkillInvoke("review".to_string())),
        ]);

        let names = |trigger: MonitorWhenKey<'_>| {
            registry
                .for_trigger(trigger)
                .into_iter()
                .map(|definition| definition.name.clone())
                .collect::<Vec<_>>()
        };

        assert_eq!(names(MonitorWhenKey::Manual), vec!["manual-one"]);
        assert_eq!(names(MonitorWhenKey::SessionStart), vec!["session-one"]);
        assert_eq!(names(MonitorWhenKey::SkillInvoke("deploy")), vec!["deploy-one"]);
        assert_eq!(names(MonitorWhenKey::SkillInvoke("DEPLOY")), vec!["deploy-one"]);
        assert!(names(MonitorWhenKey::SkillInvoke("nope")).is_empty());
        assert_eq!(MonitorWhen::SessionStart.key(), MonitorWhenKey::SessionStart);
    }

    // ----- the Done criterion: a skill-invoked plugin monitor ------------

    #[test]
    fn skill_invoked_plugin_monitor_starts_only_for_that_skill() {
        let exe = std::env::current_exe().expect("current test executable");
        let manifest = serde_json::json!({
            "schema_version": 1,
            "monitors": [{
                "name": "deploy-observer",
                "command": exe,
                "args": helper_args(),
                "description": "observe deploy output",
                "when": "skill:deploy",
            }],
        })
        .to_string();
        let registry = load_manifest(&manifest, MonitorManifestLimits::default()).expect("manifest");
        let policy = policy_for(&helper_basename());
        let sink = Arc::new(MemoryLogSink::default());
        let mut engine = MonitorEngine::with_sink(sink).with_window(BurstWindow::new(64, 1 << 20, 20));

        let other = start_for_report(
            MonitorWhenKey::SkillInvoke("review"),
            &registry,
            &policy,
            &mut engine,
            0,
        )
        .expect("trigger review");
        assert!(other.started.is_empty(), "another skill must not start the monitor");
        assert!(engine.ids().is_empty());

        let report = start_for_report(
            MonitorWhenKey::SkillInvoke("DEPLOY"),
            &registry,
            &policy,
            &mut engine,
            10,
        )
        .expect("trigger deploy");
        assert_eq!(report.started.len(), 1, "the deploy skill starts its monitor: {report:?}");
        assert!(report.skipped.is_empty(), "{report:?}");
        assert_eq!(report.started[0].id, "deploy-observer");
        assert_eq!(engine.status("deploy-observer"), Some(MonitorStatus::Running));

        let events = drain_until_line(
            &mut engine,
            "deploy-observer",
            HELPER_LINE,
            Duration::from_secs(10),
        );
        assert!(events.iter().any(|event| event.monitor_id == "deploy-observer"));

        let again = start_for(
            MonitorWhenKey::SkillInvoke("deploy"),
            &registry,
            &policy,
            &mut engine,
            20,
        )
        .expect("idempotent trigger");
        assert!(again.is_empty(), "a running monitor is not started twice");
        assert_eq!(engine.ids(), vec!["deploy-observer"]);

        stop_all(&mut engine).expect("session stop");
        assert_eq!(engine.status("deploy-observer"), Some(MonitorStatus::Stopped));
        assert_eq!(engine.stats("deploy-observer").expect("stats").pending_lines, 0);
    }

    #[test]
    fn declarative_output_cap_reaches_the_engine() {
        let exe = std::env::current_exe().expect("current test executable");
        let manifest = serde_json::json!({
            "schema_version": 1,
            "monitors": [{
                "name": "capped",
                "command": exe,
                "args": helper_args(),
                "description": "capped helper",
                "when": "manual",
                "max_output_bytes": 24,
            }],
        })
        .to_string();
        let registry = load_manifest(&manifest, MonitorManifestLimits::default()).expect("manifest");
        let policy = MonitorPolicy {
            max_output_bytes: 24,
            ..policy_for(&helper_basename())
        };
        let mut engine = MonitorEngine::new().with_window(BurstWindow::new(64, 1 << 20, 20));

        start_for(MonitorWhenKey::Manual, &registry, &policy, &mut engine, 0).expect("start");

        let events = drain_until_line(&mut engine, "capped", "xxxx", Duration::from_secs(10));
        let long = events
            .iter()
            .flat_map(|event| event.lines.iter())
            .find(|line| line.starts_with("xxxx"))
            .expect("the long line");
        assert!(
            long.ends_with(TRUNCATION_MARKER),
            "a declared cap is enforced by the engine: {long:?}"
        );
        assert!(long.len() <= 24 + TRUNCATION_MARKER.len(), "cap is 24 bytes, got {}", long.len());
        assert!(engine.stats("capped").expect("stats").truncated_lines >= 1);
        stop_all(&mut engine).expect("stop");
    }

    // ----- policy ---------------------------------------------------------

    #[test]
    fn policy_deny_defaults_refuse_commands_and_shells() {
        let manual = definition("zero-tool", MonitorWhen::Manual);

        let error = check(&manual, &MonitorPolicy::default()).expect_err("empty allowlist denies");
        assert_eq!(error.code(), ErrorCode::PermissionDenied);

        let other = policy_for("other");
        let error = check(&manual, &other).expect_err("unlisted command");
        assert_eq!(error.code(), ErrorCode::PermissionDenied);

        check(&manual, &policy_for("zero-tool")).expect("listed command");

        let mut shell = manual.clone();
        shell.requires_shell = true;
        let error = check(&shell, &policy_for("zero-tool")).expect_err("shell denied");
        assert_eq!(error.code(), ErrorCode::PermissionDenied);

        let shell_policy = MonitorPolicy {
            allow_shell: true,
            ..policy_for("zero-tool")
        };
        check(&shell, &shell_policy).expect("allowlisted shell when allowed");

        let mut full_path = manual.clone();
        full_path.command =
            Path::new("C:/tools/zero-tool.exe").to_string_lossy().into_owned();
        let exe_policy = policy_for("zero-tool.exe");
        check(&full_path, &exe_policy).expect("the allowlist matches the basename");
    }

    #[test]
    fn policy_refuses_private_metadata_and_insecure_urls() {
        let mut network = policy_for("zero-tool");
        network.allow_network = true;

        let poll = |url: &str, policy: &MonitorPolicy| {
            let mut definition = definition("poll", MonitorWhen::Manual);
            definition.source = MonitorSource::CiPoll { url: url.to_string() };
            check(&definition, policy)
        };
        let websocket = |url: &str, policy: &MonitorPolicy| {
            let mut definition = definition("feed", MonitorWhen::Manual);
            definition.source = MonitorSource::WebSocket { url: url.to_string() };
            check(&definition, policy)
        };

        for url in [
            "http://localhost:8080/build",
            "http://127.0.0.1/build",
            "http://[::1]/build",
            "http://10.1.2.3/build",
            "http://172.16.0.9/build",
            "http://192.168.1.2/build",
            "http://169.254.169.254/latest/meta-data",
            "http://metadata.google.internal/computeMetadata/v1",
            "http://0x7f000001/build",
            "http://2130706433/build",
            "http://user:token@example.com/build",
        ] {
            let error = poll(url, &network).expect_err(url);
            assert_eq!(error.code(), ErrorCode::PermissionDenied, "{url}: {}", error.message());
        }

        let error = websocket("ws://example.com/feed", &network).expect_err("plaintext websocket");
        assert_eq!(error.code(), ErrorCode::PermissionDenied);
        let error = poll("wss://example.com/feed", &network).expect_err("poll needs http(s)");
        assert_eq!(error.code(), ErrorCode::PermissionDenied);

        poll("https://ci.example.com/build", &network).expect("public https poll");
        websocket("wss://events.example.com/feed", &network).expect("public wss feed");

        let offline = MonitorPolicy { allow_network: false, ..network.clone() };
        let error = poll("https://ci.example.com/build", &offline).expect_err("network disabled");
        assert_eq!(error.code(), ErrorCode::PermissionDenied);
    }

    #[test]
    fn policy_refuses_local_targets_outside_allowed_roots() {
        let root = tempfile::tempdir().expect("root");
        let outside = tempfile::tempdir().expect("outside");
        let inside_path = root.path().join("watch");
        let outside_path = outside.path().join("watch");
        std::fs::create_dir_all(&inside_path).expect("inside dir");

        let mut policy = policy_for("zero-tool");
        policy.allowed_roots = vec![root.path().to_path_buf()];

        let mut definition = definition("watch", MonitorWhen::Manual);
        definition.source = MonitorSource::DirectoryWatch { path: inside_path.clone() };

        let error = check(&definition, &policy).expect_err("local targets disabled by default");
        assert_eq!(error.code(), ErrorCode::PermissionDenied);

        policy.allow_local_targets = true;
        check(&definition, &policy).expect("inside an allowed root");

        definition.source = MonitorSource::LogTail { path: outside_path };
        let error = check(&definition, &policy).expect_err("outside the root");
        assert_eq!(error.code(), ErrorCode::PermissionDenied);

        definition.source = MonitorSource::LogTail { path: PathBuf::from("relative.log") };
        let error = check(&definition, &policy).expect_err("relative path");
        assert_eq!(error.code(), ErrorCode::PermissionDenied);

        policy.allowed_roots.clear();
        definition.source = MonitorSource::LogTail { path: inside_path };
        let error = check(&definition, &policy).expect_err("no allowed roots");
        assert_eq!(error.code(), ErrorCode::PermissionDenied);
    }

    #[test]
    fn policy_refuses_a_definition_above_the_output_cap() {
        let policy = MonitorPolicy {
            max_output_bytes: 1024,
            ..policy_for("zero-tool")
        };

        let mut definition = definition("capped", MonitorWhen::Manual);
        definition.max_output_bytes = Some(2048);
        let error = check(&definition, &policy).expect_err("cap above policy");
        assert_eq!(error.code(), ErrorCode::LimitExceeded);

        definition.max_output_bytes = Some(1024);
        check(&definition, &policy).expect("cap equal to the policy");

        definition.max_output_bytes = Some(0);
        let error = check(&definition, &policy).expect_err("zero cap");
        assert_eq!(error.code(), ErrorCode::InvalidInput);

        let policy = MonitorPolicy {
            max_output_bytes: 0,
            ..policy_for("zero-tool")
        };
        let error = check(&definition, &policy).expect_err("zero policy cap");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
    }

    // ----- start reporting and session stop ------------------------------

    #[test]
    fn a_refused_definition_is_reported_and_others_still_start() {
        let registry = MonitorRegistry::new(vec![
            helper_definition("good", MonitorWhen::Manual),
            definition("refused", MonitorWhen::Manual),
        ]);
        let policy = policy_for(&helper_basename());
        let mut engine = MonitorEngine::new().with_window(BurstWindow::new(64, 1 << 20, 20));

        let report =
            start_for_report(MonitorWhenKey::Manual, &registry, &policy, &mut engine, 0)
                .expect("trigger");
        assert_eq!(report.started.len(), 1, "{report:?}");
        assert_eq!(report.started[0].id, "good");
        assert_eq!(report.skipped.len(), 1, "{report:?}");
        assert_eq!(report.skipped[0].name, "refused");
        assert_eq!(report.skipped[0].code, ErrorCode::PermissionDenied);
        assert_eq!(engine.ids(), vec!["good"]);

        stop_all(&mut engine).expect("stop all");
    }

    #[test]
    fn stop_all_stops_every_monitor_and_is_idempotent() {
        let registry = MonitorRegistry::new(vec![
            helper_definition("first", MonitorWhen::Manual),
            helper_definition("second", MonitorWhen::Manual),
        ]);
        let policy = policy_for(&helper_basename());
        let mut engine = MonitorEngine::new().with_window(BurstWindow::new(64, 1 << 20, 20));

        start_for(MonitorWhenKey::Manual, &registry, &policy, &mut engine, 0).expect("start");
        assert_eq!(engine.ids().len(), 2);

        stop_all(&mut engine).expect("first stop");
        for id in ["first", "second"] {
            assert_eq!(engine.status(id), Some(MonitorStatus::Stopped), "{id}");
            assert_eq!(engine.stats(id).expect("stats").pending_lines, 0, "{id}");
        }
        stop_all(&mut engine).expect("second stop is idempotent");

        // The engine retains stopped names, so a re-trigger is reported, not
        // silently spawned again (restart needs confirmation, T-MON-04).
        let report =
            start_for_report(MonitorWhenKey::Manual, &registry, &policy, &mut engine, 30)
                .expect("re-trigger");
        assert!(report.started.is_empty());
        assert_eq!(report.skipped.len(), 2);
        assert!(report.skipped.iter().all(|skip| skip.code == ErrorCode::AlreadyExists));
    }
}
