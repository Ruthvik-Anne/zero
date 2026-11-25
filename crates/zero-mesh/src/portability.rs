//! Portability for cross-OS teleport (T-TEL-06, TEL-01, TEL-12, TEL-13,
//! TEL-14).
//!
//! A teleport between two hosts is not only a byte copy. Absolute paths embedded
//! in a transcript or a config must be remapped to the target directory, kernel
//! state that cannot be loaded on another OS must be rebuilt, and the target's
//! available tools must be checked before anything is claimed as complete.
//! This module is the value half of that boundary:
//!
//! - [`PathMap`] and [`remap_path`] translate an absolute path from one source
//!   root to one target root. Windows drive and UNC paths become POSIX paths and
//!   back, separators are normalised, a case-only difference is accepted on a
//!   case-insensitive source, and a path outside the source root or with a `..`
//!   component is refused.
//! - [`remap_text`] rewrites only absolute path tokens that belong to a map. It
//!   never rewrites surrounding prose, and it reports how many tokens were
//!   substituted and skipped per map. [`working_directory_notice`] returns the
//!   context line that tells the model the directory changed (TEL-12).
//! - [`remap_snapshot`] remaps the text-bearing components (session transcript,
//!   kernel checkpoint/config, and workspace manifest metadata) and passes
//!   binary artifacts through untouched. Because every component hash and the
//!   source signature are bound to the old bytes, the result is **re-signed**
//!   with the target device key. The source signature is invalidated
//!   intentionally; verify the source snapshot before calling this function.
//! - [`plan_kernel_rebuild`] produces a target-appropriate kernel plan: a bare
//!   `python3` on Unix, `python` on Windows, a documented package set, and no
//!   Windows path in the plan.
//! - [`preflight`] probes the target for the tools a session needs and returns
//!   per-tool install guidance. [`can_run`] refuses missing tools and refuses a
//!   plan that requires `git` in a directory with no repository.
//!
//! Everything here is a pure value operation: no process is spawned, no tool is
//! actually installed, and no socket is opened. Live processes, PTYs, and open
//! sockets do not move (TEL-14); this module reports what must be rebuilt rather
//! than pretending it moved.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, ZeroError};

use crate::identity::KeyPair;
use crate::snapshot::{self, Component, ComponentBlob, Snapshot};

/// Longest accepted source, target, or remapped path: 8 KiB.
pub const MAX_REMAP_PATH_BYTES: usize = 8 * 1024;

/// Longest transcript or config text [`remap_text`] will scan: 1 MiB.
pub const MAX_REMAP_TEXT_BYTES: usize = 1024 * 1024;

/// Largest rewritten text [`remap_text`] will return: 2 MiB.
pub const MAX_REMAP_OUTPUT_BYTES: usize = 2 * 1024 * 1024;

/// Most path-like tokens [`remap_text`] will inspect in one call.
pub const MAX_REMAP_TOKENS: usize = 65_536;

/// Most maps one call may apply. The first map that claims a token wins.
pub const MAX_PATH_MAPS: usize = 32;

/// Longest accepted interpreter command in a [`KernelRebuildPlan`].
pub const MAX_PYTHON_BYTES: usize = 64;

/// Most packages a [`KernelRebuildPlan`] may list.
pub const MAX_KERNEL_PACKAGES: usize = 64;

/// Longest package name in a [`KernelRebuildPlan`].
pub const MAX_PACKAGE_NAME_BYTES: usize = 128;

/// The documented kernel package set, sorted.
///
/// `ipykernel` is the IPython kernel transport (KRN-10); `jupyter_client` is the
/// client side of the same protocol; `cloudpickle` is the checkpoint format used
/// for pure-Python kernel state (TEL-12). The list is deliberately small and
/// fixed so a rebuild plan is deterministic and reviewable.
pub const KERNEL_PACKAGES: [&str; 3] = ["cloudpickle", "ipykernel", "jupyter_client"];

/// Components whose bytes may contain absolute paths and are remapped.
///
/// The session carries the transcript, the kernel checkpoint carries config and
/// cwd values, and the workspace manifest carries path metadata. `Artifacts` is
/// a binary/index artifact, and `Goals`, `Schedules`, and `Ledger` are not path
/// metadata in this slice; all four pass through byte-identically.
pub const REMAPPABLE_COMPONENTS: [Component; 3] =
    [Component::Session, Component::Kernel, Component::Manifest];

/// One source-root to target-root mapping.
///
/// Both roots must be absolute in their own style: a Windows drive path
/// (`C:\work\proj`), a UNC path (`\\server\share\proj`), or a POSIX path
/// (`/home/alice/proj`). `case_insensitive_source` controls component comparison
/// on the source side; a drive letter is always compared case-insensitively
/// because `c:` and `C:` are the same drive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathMap {
    /// The absolute source root a path must be under.
    pub from_root: String,
    /// The absolute target root the remainder is joined onto.
    pub to_root: String,
    /// True when source path components compare case-insensitively (Windows).
    pub case_insensitive_source: bool,
}

impl PathMap {
    /// Build and validate a map.
    pub fn new(
        from_root: impl Into<String>,
        to_root: impl Into<String>,
        case_insensitive_source: bool,
    ) -> Result<Self> {
        let map = Self {
            from_root: from_root.into(),
            to_root: to_root.into(),
            case_insensitive_source,
        };
        map.validate()?;
        Ok(map)
    }

    /// Validate that both roots are absolute and carry no `..` component.
    pub fn validate(&self) -> Result<()> {
        parse_absolute(&self.from_root, false)?;
        parse_absolute(&self.to_root, false)?;
        Ok(())
    }

    /// True when `path` is syntactically under `from_root`.
    ///
    /// Traversal is tolerated here only so [`remap_text`] can count such a token
    /// as skipped instead of silently treating it as unrelated text.
    fn claims_path(&self, path: &str) -> bool {
        let Ok(source) = parse_absolute(path, true) else {
            return false;
        };
        let Ok(root) = parse_absolute(&self.from_root, false) else {
            return false;
        };
        strip_root(&source, &root, self.case_insensitive_source).is_some()
    }
}

/// How many tokens one map substituted and how many it had to skip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemapReport {
    /// The map these counts belong to.
    pub map: PathMap,
    /// Tokens under `from_root` that were rewritten.
    pub substituted: usize,
    /// Tokens under `from_root` that were left unchanged (for example `..`).
    pub skipped: usize,
}

/// The result of rewriting a transcript or config fragment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextRemap {
    /// Rewritten text.
    pub text: String,
    /// One report per map, in the same order as the maps passed in.
    pub reports: Vec<RemapReport>,
}

impl TextRemap {
    /// Total substitutions across every map.
    pub fn substituted(&self) -> usize {
        self.reports.iter().map(|report| report.substituted).sum()
    }

    /// Total skipped tokens across every map.
    pub fn skipped(&self) -> usize {
        self.reports.iter().map(|report| report.skipped).sum()
    }
}

/// The result of remapping a snapshot and re-signing it for the target device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotRemap {
    /// The rebuilt snapshot, signed by the target device key.
    pub snapshot: Snapshot,
    /// Per-map substitution and skip counts.
    pub reports: Vec<RemapReport>,
    /// Components whose bytes actually changed, in [`Component::ALL`] order.
    pub remapped: Vec<Component>,
}

/// Remap one absolute path from a source root to a target root.
///
/// Rules:
///
/// - both the path and [`PathMap::from_root`] must be absolute; a relative path
///   is `zero.fnd.invalid_input`;
/// - `\` and `/` are both accepted as separators, repeated separators are
///   collapsed, and `.` components are removed;
/// - a drive letter and UNC server/share must match the source root; every
///   other component compares case-insensitively only when
///   [`PathMap::case_insensitive_source`] is true;
/// - a path outside the source root is `zero.fnd.invalid_input`, as is any
///   `..` component;
/// - the remainder keeps its original case and bytes (spaces and non-ASCII are
///   preserved) and is joined onto the target root with the target style's
///   separator (`\` for a drive or UNC target, `/` for POSIX);
/// - a path above [`MAX_REMAP_PATH_BYTES`] is `zero.fnd.limit_exceeded`.
pub fn remap_path(path: &str, map: &PathMap) -> Result<String> {
    let source = parse_absolute(path, false)?;
    let from = parse_absolute(&map.from_root, false)?;
    let target = parse_absolute(&map.to_root, false)?;
    let remainder = strip_root(&source, &from, map.case_insensitive_source).ok_or_else(|| {
        invalid(format!(
            "`{path}` is outside the source root `{}`",
            map.from_root
        ))
    })?;
    Ok(join_absolute(&target, &remainder))
}

/// A transcript-safe notice that the working directory moved.
///
/// TEL-12 requires the model to be told the directory changed. This module does
/// not know the session format, so it returns one plain-text context line for
/// the caller to insert; it does not mutate a transcript itself.
pub fn working_directory_notice(map: &PathMap) -> Result<String> {
    map.validate()?;
    Ok(format!(
        "The workspace moved during teleport: `{}` is now `{}`. Use the new path for commands and \
         file references.",
        map.from_root, map.to_root
    ))
}

/// Rewrite absolute path tokens in a transcript or config fragment.
///
/// Only a token that (a) parses as an absolute Windows or POSIX path and (b) is
/// under one map's `from_root` is touched. Everything else is copied verbatim,
/// so prose, `C++`, `/etc/hosts`, version numbers, and relative paths are left
/// alone. A quoted or backtick-delimited value whose whole content is a path is
/// remapped as one token, which is how a path with spaces survives. A quoted
/// command such as `"cd /home/alice/proj"` is still handled word by word.
///
/// The first map that claims a token wins; a later map is never tried for that
/// token. A token that claims a map but cannot be remapped safely (for example a
/// `..` component or a case-sensitive mismatch) is left byte-identically intact
/// and counted in [`RemapReport::skipped`]. Tokens outside every root are not
/// counted as skipped because they are unrelated text.
///
/// The input is bounded by [`MAX_REMAP_TEXT_BYTES`], the output by
/// [`MAX_REMAP_OUTPUT_BYTES`], and the token count by [`MAX_REMAP_TOKENS`].
pub fn remap_text(text: &str, maps: &[PathMap]) -> Result<TextRemap> {
    if text.len() > MAX_REMAP_TEXT_BYTES {
        return Err(limit(format!(
            "text is {} bytes; the remap limit is {MAX_REMAP_TEXT_BYTES}",
            text.len()
        )));
    }
    if maps.len() > MAX_PATH_MAPS {
        return Err(limit(format!(
            "{} path maps were supplied; the limit is {MAX_PATH_MAPS}",
            maps.len()
        )));
    }
    for map in maps {
        map.validate()?;
    }

    let mut reports: Vec<RemapReport> = maps
        .iter()
        .map(|map| RemapReport {
            map: map.clone(),
            substituted: 0,
            skipped: 0,
        })
        .collect();
    let mut output = String::with_capacity(text.len());
    let mut tokens = 0usize;
    let mut index = 0usize;

    while index < text.len() {
        let ch = text[index..]
            .chars()
            .next()
            .expect("the index is always on a character boundary");

        if is_quote(ch) && is_opening_quote(text, index) {
            let inner_start = index + ch.len_utf8();
            if let Some(relative_end) = text[inner_start..].find(ch) {
                let inner_end = inner_start + relative_end;
                let inner = &text[inner_start..inner_end];
                let candidate = inner.trim();
                if !candidate.is_empty() && is_absolute_candidate(candidate) {
                    tokens += 1;
                    if tokens > MAX_REMAP_TOKENS {
                        return Err(limit(format!(
                            "text has more than {MAX_REMAP_TOKENS} path tokens"
                        )));
                    }
                    let replacement = apply_token(candidate, maps, &mut reports);
                    output.push(ch);
                    output.push_str(&replacement);
                    output.push(ch);
                    if output.len() > MAX_REMAP_OUTPUT_BYTES {
                        return Err(limit(format!(
                            "remapped text exceeds {MAX_REMAP_OUTPUT_BYTES} bytes"
                        )));
                    }
                    index = inner_end + ch.len_utf8();
                    continue;
                }
            }
            output.push(ch);
            index = inner_start;
            continue;
        }

        if is_token_char(ch) {
            let start = index;
            let mut end = index + ch.len_utf8();
            while end < text.len() {
                let next = text[end..]
                    .chars()
                    .next()
                    .expect("the index is always on a character boundary");
                if !is_token_char(next) {
                    break;
                }
                end += next.len_utf8();
            }

            let raw = &text[start..end];
            let (candidate, trailing) = trim_token_end(raw);
            if !candidate.is_empty() && is_absolute_candidate(candidate) {
                tokens += 1;
                if tokens > MAX_REMAP_TOKENS {
                    return Err(limit(format!(
                        "text has more than {MAX_REMAP_TOKENS} path tokens"
                    )));
                }
                output.push_str(&apply_token(candidate, maps, &mut reports));
                output.push_str(trailing);
            } else {
                output.push_str(raw);
            }
            index = end;
        } else {
            output.push(ch);
            index += ch.len_utf8();
        }

        if output.len() > MAX_REMAP_OUTPUT_BYTES {
            return Err(limit(format!(
                "remapped text exceeds {MAX_REMAP_OUTPUT_BYTES} bytes"
            )));
        }
    }

    Ok(TextRemap {
        text: output,
        reports,
    })
}

/// Remap a snapshot and re-sign it with the target device key.
///
/// The source snapshot's blob hashes and signature describe the **old** bytes.
/// Remapping changes at least one blob's size or hash and the content-derived
/// snapshot id, so the source signature is invalid by construction. This
/// function rebuilds the manifest and signs it with `target_key`; the old
/// signature is intentionally discarded. Call
/// [`verify_snapshot`](crate::snapshot::verify) with the source device key
/// before calling this function, because a re-sign is a trusted-device action,
/// not a verification.
///
/// Only [`REMAPPABLE_COMPONENTS`] are scanned, and only valid UTF-8 is treated
/// as text. Binary artifacts and non-UTF-8 blobs pass through byte-identically.
/// The returned [`SnapshotRemap`] records which components changed.
pub fn remap_snapshot(
    snapshot: &Snapshot,
    maps: &[PathMap],
    target_key: &KeyPair,
) -> Result<Snapshot> {
    Ok(remap_snapshot_report(snapshot, maps, target_key)?.snapshot)
}

/// The reporting form of [`remap_snapshot`].
pub fn remap_snapshot_report(
    snapshot: &Snapshot,
    maps: &[PathMap],
    target_key: &KeyPair,
) -> Result<SnapshotRemap> {
    check_blob_consistency(snapshot)?;
    if maps.len() > MAX_PATH_MAPS {
        return Err(limit(format!(
            "{} path maps were supplied; the limit is {MAX_PATH_MAPS}",
            maps.len()
        )));
    }
    for map in maps {
        map.validate()?;
    }

    let mut reports: Vec<RemapReport> = maps
        .iter()
        .map(|map| RemapReport {
            map: map.clone(),
            substituted: 0,
            skipped: 0,
        })
        .collect();
    let mut blobs = snapshot.blobs.clone();
    let mut remapped = Vec::new();

    for component in REMAPPABLE_COMPONENTS {
        let Some(bytes) = blobs.get(&component) else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(bytes) else {
            continue;
        };
        let result = remap_text(text, maps)?;
        for (target, source) in reports.iter_mut().zip(result.reports.iter()) {
            target.substituted += source.substituted;
            target.skipped += source.skipped;
        }
        if result.text != text {
            blobs.insert(component, result.text.into_bytes());
            remapped.push(component);
        }
    }

    let rebuilt = snapshot::create_excluding(
        &snapshot.manifest.project_id,
        blobs
            .into_iter()
            .map(|(component, bytes)| ComponentBlob::new(component, bytes)),
        snapshot.manifest.excluded.clone(),
        snapshot.manifest.created_ms,
        target_key,
    )?;

    Ok(SnapshotRemap {
        snapshot: rebuilt,
        reports,
        remapped,
    })
}

/// A target-side kernel rebuild plan.
///
/// `python` is a bare command, never an absolute path. `packages` is the
/// documented [`KERNEL_PACKAGES`] set. `offline_cache` is true only for a
/// same-OS move, where the local wheel cache can be reused; a cross-OS move
/// needs target-platform wheels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelRebuildPlan {
    /// Target-appropriate interpreter command: `python3` on Unix, `python` on
    /// Windows.
    pub python: String,
    /// Packages to install on the target, sorted.
    pub packages: Vec<String>,
    /// Reuse the local wheel cache (same-OS moves only).
    pub offline_cache: bool,
}

impl KernelRebuildPlan {
    /// Validate the interpreter command, package names, and package count.
    pub fn validate(&self) -> Result<()> {
        validate_python(&self.python)?;
        if self.packages.len() > MAX_KERNEL_PACKAGES {
            return Err(limit(format!(
                "kernel plan has {} packages; the limit is {MAX_KERNEL_PACKAGES}",
                self.packages.len()
            )));
        }
        let mut seen = BTreeSet::new();
        for package in &self.packages {
            validate_package(package)?;
            if !seen.insert(package.as_str()) {
                return Err(invalid(format!(
                    "kernel package `{package}` appears more than once"
                )));
            }
        }
        Ok(())
    }
}

/// Build a target-appropriate kernel rebuild plan.
///
/// `source_os` and `target_os` accept `windows`/`win`, `linux`, and
/// `macos`/`darwin`/`osx`. `available_python` is what the target actually has;
/// a Windows absolute path is refused when the target is not Windows and a POSIX
/// absolute path is refused when the target is Windows. The plan itself carries
/// only a bare command, so no `C:\...` path can leak into a POSIX target plan.
///
/// The same-OS case still produces a plan (a rebuild is idempotent) and sets
/// `offline_cache = true`; a cross-OS move sets it false because compiled wheels
/// and virtual environments do not move between operating systems.
pub fn plan_kernel_rebuild(
    source_os: &str,
    target_os: &str,
    available_python: &str,
) -> Result<KernelRebuildPlan> {
    let source = OsFamily::parse(source_os)?;
    let target = OsFamily::parse(target_os)?;
    let python = target_python(target, available_python)?;
    let plan = KernelRebuildPlan {
        python,
        packages: KERNEL_PACKAGES
            .iter()
            .map(|package| (*package).to_string())
            .collect(),
        offline_cache: source == target,
    };
    plan.validate()?;
    Ok(plan)
}

/// Probes whether one tool is available on the target.
pub trait ToolProbe {
    /// True when `tool` is installed and callable on the target.
    fn has_tool(&self, tool: &str) -> bool;
}

/// A fixed set of available tools, useful for tests and config snapshots.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolSet {
    tools: BTreeSet<String>,
}

impl ToolSet {
    /// Build a probe from tool names. Names are trimmed, ASCII-lowercased, and
    /// a trailing `.exe` is ignored.
    pub fn new<I, S>(tools: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            tools: tools
                .into_iter()
                .map(|tool| normalize_tool(tool.as_ref()))
                .filter(|tool| !tool.is_empty())
                .collect(),
        }
    }
}

impl ToolProbe for ToolSet {
    fn has_tool(&self, tool: &str) -> bool {
        self.tools.contains(&normalize_tool(tool))
    }
}

/// Declared required and available tools.
///
/// This is the value form of a preflight input and also implements
/// [`ToolProbe`], so `preflight(&spec.required, &spec)` works without a
/// separate probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPreflight {
    /// Tools the session needs on the target.
    pub required: Vec<String>,
    /// Tools the target is known to have.
    pub available: Vec<String>,
}

impl ToolPreflight {
    /// Normalise, sort, and deduplicate both lists.
    pub fn new<I, S, J, T>(required: I, available: J) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        J: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        Self {
            required: normalize_tools(required),
            available: normalize_tools(available),
        }
    }
}

impl ToolProbe for ToolPreflight {
    fn has_tool(&self, tool: &str) -> bool {
        let wanted = normalize_tool(tool);
        self.available
            .iter()
            .any(|available| normalize_tool(available) == wanted)
    }
}

/// The result of probing the target for required tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightReport {
    /// True when every required tool is available.
    pub ok: bool,
    /// Normalised required tools, sorted.
    pub required: Vec<String>,
    /// Required tools the probe reported as available, sorted.
    pub available: Vec<String>,
    /// Required tools the probe reported as missing, sorted.
    pub missing: Vec<String>,
    /// Per-tool install guidance for every missing tool.
    pub guidance: BTreeMap<String, String>,
}

/// Probe `required` and report missing tools with install guidance.
///
/// Tool names are trimmed, ASCII-lowercased, and deduplicated. A missing
/// required tool is listed in [`PreflightReport::missing`] with an entry in
/// [`PreflightReport::guidance`]. This function never spawns a process; the
/// caller supplies the probe.
pub fn preflight(required: &[String], probe: &dyn ToolProbe) -> PreflightReport {
    let required = normalize_tools(required.iter().cloned());
    let mut available = Vec::new();
    let mut missing = Vec::new();
    let mut guidance = BTreeMap::new();

    for tool in &required {
        if probe.has_tool(tool) {
            available.push(tool.clone());
        } else {
            missing.push(tool.clone());
            guidance.insert(tool.clone(), install_guidance(tool));
        }
    }

    PreflightReport {
        ok: missing.is_empty(),
        required,
        available,
        missing,
        guidance,
    }
}

/// Install guidance for one tool.
///
/// The table is deliberately short; an unknown tool still gets a usable
/// `install it and put it on PATH` line rather than an empty report.
pub fn install_guidance(tool: &str) -> String {
    let tool = normalize_tool(tool);
    match tool.as_str() {
        "git" => "Install Git from https://git-scm.com/downloads, or restore without repository \
                  history; a no-git directory must not require git."
            .to_string(),
        "python" | "python3" => "Install Python 3.11 or newer and put `python3` (or `python` on \
                                 Windows) on PATH."
            .to_string(),
        "pip" | "pip3" => {
            "Install pip with `python3 -m ensurepip --upgrade`, or use `uv` and the offline wheel \
             cache."
                .to_string()
        }
        "uv" => "Install uv from https://docs.astral.sh/uv/ and run `uv sync` before teleport."
            .to_string(),
        "node" => {
            "Install the Node.js LTS release from https://nodejs.org/ and put `node` on PATH."
                .to_string()
        }
        "npm" => {
            "Install npm with Node.js from https://nodejs.org/ and put `npm` on PATH.".to_string()
        }
        "cargo" | "rustc" => {
            "Install the Rust toolchain from https://rustup.rs/ and put `cargo` and `rustc` on \
             PATH."
                .to_string()
        }
        "bash" | "sh" => {
            "Install a POSIX shell (`bash` or `sh`) from the target OS package manager.".to_string()
        }
        "powershell" => {
            "Install PowerShell from https://github.com/PowerShell/PowerShell and put `pwsh` on \
             PATH."
                .to_string()
        }
        "tar" => "Install `tar` from the target OS package manager.".to_string(),
        "unzip" => "Install `unzip` from the target OS package manager.".to_string(),
        "curl" => "Install `curl` from the target OS package manager.".to_string(),
        "rg" => {
            "Install ripgrep from https://github.com/BurntSushi/ripgrep#installation.".to_string()
        }
        "make" => {
            "Install `make` (build-essential on Debian/Ubuntu) from the target OS.".to_string()
        }
        "gcc" | "cc" => "Install a C compiler (`gcc` or `clang`) from the target OS.".to_string(),
        "ssh" => "Install the OpenSSH client from the target OS package manager.".to_string(),
        _ => format!("Install `{tool}` and put it on PATH."),
    }
}

/// Refuse a rebuild plan that the target cannot run.
///
/// Checked in this order:
///
/// 1. the plan itself is valid (bare target interpreter, no duplicate packages);
/// 2. `no_git_dir` is true and the plan requires `git` — a directory with no
///    repository must not need git, even when git happens to be installed;
/// 3. a required tool is missing from the report's available list;
/// 4. `plan.python` was not checked by the preflight, or is missing.
///
/// Every refusal names the tool and its install guidance.
pub fn can_run(
    plan: &KernelRebuildPlan,
    preflight: &PreflightReport,
    no_git_dir: bool,
) -> Result<()> {
    plan.validate()?;

    let required = normalize_tools(preflight.required.iter().cloned());
    let available = normalize_tools(preflight.available.iter().cloned());

    if no_git_dir && required.iter().any(|tool| tool == "git") {
        let guidance = preflight
            .guidance
            .get("git")
            .cloned()
            .unwrap_or_else(|| install_guidance("git"));
        return Err(denied(format!(
            "this directory has no git repository; teleport must not require git. {guidance}"
        )));
    }

    let missing: Vec<&String> = required
        .iter()
        .filter(|tool| !available.contains(tool))
        .collect();
    if !missing.is_empty() {
        let mut message = format!(
            "the target is missing required tools: {}",
            missing
                .iter()
                .map(|tool| tool.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        for tool in &missing {
            let guidance = preflight
                .guidance
                .get(*tool)
                .cloned()
                .unwrap_or_else(|| install_guidance(tool));
            message.push_str("\n- ");
            message.push_str(tool);
            message.push_str(": ");
            message.push_str(&guidance);
        }
        return Err(denied(message));
    }

    let python = normalize_tool(&plan.python);
    if !required.contains(&python) {
        return Err(invalid(format!(
            "preflight did not check the kernel interpreter `{}`; add it to the required tools",
            plan.python
        )));
    }
    if !available.contains(&python) {
        return Err(denied(format!(
            "kernel interpreter `{}` is not available on the target. {}",
            plan.python,
            install_guidance(&plan.python)
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Path parsing and remapping
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathKind {
    Posix,
    Drive,
    Unc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AbsolutePath {
    kind: PathKind,
    drive: Option<char>,
    server: Option<String>,
    share: Option<String>,
    components: Vec<String>,
}

/// Parse an absolute drive, UNC, or POSIX path.
///
/// `allow_parent` is true only for the lenient check [`PathMap::claims_path`]
/// uses; the strict remap path always refuses a `..` component.
fn parse_absolute(value: &str, allow_parent: bool) -> Result<AbsolutePath> {
    if value.is_empty() {
        return Err(invalid("a path must not be empty"));
    }
    if value.len() > MAX_REMAP_PATH_BYTES {
        return Err(limit(format!(
            "path is {} bytes; the limit is {MAX_REMAP_PATH_BYTES}",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid("a path must not contain control characters"));
    }
    if value.trim() != value {
        return Err(invalid("a path must not start or end with whitespace"));
    }
    if value.starts_with("\\\\?\\")
        || value.starts_with("\\\\.\\")
        || value.starts_with("//?/")
        || value.starts_with("//./")
    {
        return Err(invalid(
            "Windows device paths (`\\\\?\\`, `\\\\.\\`) are not portable",
        ));
    }

    let windows_unc =
        value.starts_with("\\\\") || (value.starts_with("//") && !value.starts_with("///"));
    let slashed: String = value
        .chars()
        .map(|ch| if ch == '\\' { '/' } else { ch })
        .collect();

    if windows_unc {
        let rest = slashed.trim_start_matches('/');
        let mut parts = rest.split('/');
        let server = parts.next().unwrap_or("");
        let share = parts.next().unwrap_or("");
        if server.is_empty() || share.is_empty() {
            return Err(invalid(format!(
                "UNC path `{value}` needs a server and a share"
            )));
        }
        if server == "." || server == ".." || share == "." || share == ".." {
            return Err(invalid(format!(
                "UNC path `{value}` has a traversal server or share"
            )));
        }
        let remainder = parts.collect::<Vec<_>>().join("/");
        return Ok(AbsolutePath {
            kind: PathKind::Unc,
            drive: None,
            server: Some(server.to_string()),
            share: Some(share.to_string()),
            components: split_components(&remainder, allow_parent)?,
        });
    }

    let bytes = slashed.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        let drive = (bytes[0] as char).to_ascii_uppercase();
        let rest = &slashed[2..];
        if rest.is_empty() || !rest.starts_with('/') {
            return Err(invalid(format!(
                "drive path `{value}` must be absolute, for example `C:\\work`"
            )));
        }
        return Ok(AbsolutePath {
            kind: PathKind::Drive,
            drive: Some(drive),
            server: None,
            share: None,
            components: split_components(rest.trim_start_matches('/'), allow_parent)?,
        });
    }

    if slashed.starts_with('/') {
        return Ok(AbsolutePath {
            kind: PathKind::Posix,
            drive: None,
            server: None,
            share: None,
            components: split_components(slashed.trim_start_matches('/'), allow_parent)?,
        });
    }

    Err(invalid(format!(
        "`{value}` is not an absolute path; a remap needs a root"
    )))
}

fn split_components(rest: &str, allow_parent: bool) -> Result<Vec<String>> {
    let mut components = Vec::new();
    for part in rest.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            if allow_parent {
                components.push(part.to_string());
            } else {
                return Err(invalid("a remap path must not contain a `..` component"));
            }
        } else {
            components.push(part.to_string());
        }
    }
    Ok(components)
}

fn strip_root(
    path: &AbsolutePath,
    root: &AbsolutePath,
    case_insensitive: bool,
) -> Option<Vec<String>> {
    if path.kind != root.kind {
        return None;
    }
    match path.kind {
        PathKind::Drive => {
            if path.drive != root.drive {
                return None;
            }
        }
        PathKind::Unc => {
            if !component_eq(
                path.server.as_deref()?,
                root.server.as_deref()?,
                case_insensitive,
            ) {
                return None;
            }
            if !component_eq(
                path.share.as_deref()?,
                root.share.as_deref()?,
                case_insensitive,
            ) {
                return None;
            }
        }
        PathKind::Posix => {}
    }

    if path.components.len() < root.components.len() {
        return None;
    }
    for (path_part, root_part) in path.components.iter().zip(root.components.iter()) {
        if !component_eq(path_part, root_part, case_insensitive) {
            return None;
        }
    }
    Some(path.components[root.components.len()..].to_vec())
}

fn component_eq(left: &str, right: &str, case_insensitive: bool) -> bool {
    if case_insensitive {
        left.to_lowercase() == right.to_lowercase()
    } else {
        left == right
    }
}

fn join_absolute(target: &AbsolutePath, remainder: &[String]) -> String {
    let components: Vec<&str> = target
        .components
        .iter()
        .map(String::as_str)
        .chain(remainder.iter().map(String::as_str))
        .collect();

    match target.kind {
        PathKind::Posix => {
            if components.is_empty() {
                "/".to_string()
            } else {
                let mut out = String::from("/");
                out.push_str(&components.join("/"));
                out
            }
        }
        PathKind::Drive => {
            let mut out = String::new();
            out.push(target.drive.unwrap_or('C'));
            out.push(':');
            if components.is_empty() {
                out.push('\\');
            } else {
                for component in components {
                    out.push('\\');
                    out.push_str(component);
                }
            }
            out
        }
        PathKind::Unc => {
            let mut out = String::from("\\\\");
            out.push_str(target.server.as_deref().unwrap_or(""));
            out.push('\\');
            out.push_str(target.share.as_deref().unwrap_or(""));
            for component in components {
                out.push('\\');
                out.push_str(component);
            }
            out
        }
    }
}

fn is_absolute_candidate(value: &str) -> bool {
    parse_absolute(value, true).is_ok()
}

fn is_quote(ch: char) -> bool {
    matches!(ch, '"' | '\'' | '`')
}

/// A closing quote is not an opening quote. Without this check a pair such as
/// `"hello" C:\work "world"` would let the closing quote consume the path and
/// its surrounding quotes, changing unrelated punctuation.
fn is_opening_quote(text: &str, index: usize) -> bool {
    if index == 0 {
        return true;
    }
    let before = text[..index]
        .chars()
        .next_back()
        .expect("index is a character boundary");
    before.is_whitespace()
        || is_quote(before)
        || matches!(before, '=' | ':' | '[' | '{' | '(' | ',' | ';' | '|')
}

fn is_token_char(ch: char) -> bool {
    const DELIMITERS: [char; 15] = [
        '"', '\'', '`', '(', ')', '[', ']', '{', '}', '<', '>', ',', ';', '=', '|',
    ];
    !ch.is_whitespace() && !DELIMITERS.contains(&ch)
}

/// Split trailing sentence punctuation from a token, but keep a drive root
/// (`C:`), a `.` component, and a `..` traversal marker attached.
fn trim_token_end(raw: &str) -> (&str, &str) {
    let mut end = raw.len();
    while end > 0 {
        let ch = raw[..end]
            .chars()
            .next_back()
            .expect("end is a character boundary");
        let is_drive_colon = end == 2
            && raw.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && raw.as_bytes().get(1) == Some(&b':');
        let is_dot_component = ch == '.'
            && raw[..end - ch.len_utf8()]
                .chars()
                .next_back()
                .is_some_and(|before| before == '.' || before == '/' || before == '\\');
        if matches!(ch, '.' | ',' | ';' | ':' | '!' | '?') && !is_drive_colon && !is_dot_component {
            end -= ch.len_utf8();
        } else {
            break;
        }
    }
    (&raw[..end], &raw[end..])
}

fn apply_token(token: &str, maps: &[PathMap], reports: &mut [RemapReport]) -> String {
    for (index, map) in maps.iter().enumerate() {
        if !map.claims_path(token) {
            continue;
        }
        return match remap_path(token, map) {
            Ok(remapped) => {
                reports[index].substituted += 1;
                remapped
            }
            Err(_) => {
                reports[index].skipped += 1;
                token.to_string()
            }
        };
    }
    token.to_string()
}

// ---------------------------------------------------------------------------
// Snapshot consistency
// ---------------------------------------------------------------------------

/// Confirm that the blobs match the supplied manifest before re-signing.
///
/// This is deliberately **not** signature verification: the source public key
/// is not part of the signature, and re-signing is the caller's trusted action.
/// It only ensures a tampered, partial, or internally inconsistent snapshot is
/// not silently blessed with the target key.
fn check_blob_consistency(snapshot: &Snapshot) -> Result<()> {
    snapshot.manifest.canonical_bytes()?;

    if snapshot.blobs.len() != snapshot.manifest.components.len() {
        return Err(tamper(format!(
            "snapshot carries {} blobs but the manifest names {}",
            snapshot.blobs.len(),
            snapshot.manifest.components.len()
        )));
    }
    for (component, meta) in &snapshot.manifest.components {
        let bytes = snapshot.blobs.get(component).ok_or_else(|| {
            tamper(format!(
                "component `{}` is missing from the snapshot",
                component.as_str()
            ))
        })?;
        if bytes.len() != meta.bytes {
            return Err(tamper(format!(
                "component `{}` is {} bytes but the manifest declares {}",
                component.as_str(),
                bytes.len(),
                meta.bytes
            )));
        }
        if blake3::hash(bytes).to_hex().to_string() != meta.blake3 {
            return Err(tamper(format!(
                "component `{}` does not match its manifest hash",
                component.as_str()
            )));
        }
    }
    for component in snapshot.blobs.keys() {
        if !snapshot.manifest.components.contains_key(component) {
            return Err(tamper(format!(
                "component `{}` is present but absent from the manifest",
                component.as_str()
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Kernel plan validation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OsFamily {
    Windows,
    Linux,
    MacOs,
}

impl OsFamily {
    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "windows" | "win" | "win32" => Ok(OsFamily::Windows),
            "linux" => Ok(OsFamily::Linux),
            "macos" | "mac" | "osx" | "darwin" => Ok(OsFamily::MacOs),
            _ => Err(invalid(format!(
                "`{value}` is not a supported OS; use windows, linux, or macos"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathStyle {
    Bare,
    Windows,
    Posix,
}

fn path_style(value: &str) -> PathStyle {
    let bytes = value.as_bytes();
    let drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if drive || value.starts_with("\\\\") || value.starts_with("//") {
        PathStyle::Windows
    } else if value.starts_with('/') || value.contains('/') {
        PathStyle::Posix
    } else if value.contains('\\') {
        PathStyle::Windows
    } else {
        PathStyle::Bare
    }
}

fn target_python(target: OsFamily, available_python: &str) -> Result<String> {
    if available_python.is_empty() {
        return Err(invalid("available python must not be empty"));
    }
    if available_python.len() > MAX_PYTHON_BYTES {
        return Err(limit(format!(
            "available python is {} bytes; the limit is {MAX_PYTHON_BYTES}",
            available_python.len()
        )));
    }
    if available_python.trim() != available_python {
        return Err(invalid(
            "available python must not be padded with whitespace",
        ));
    }
    if available_python.chars().any(char::is_control) {
        return Err(invalid(
            "available python must not contain control characters",
        ));
    }

    match (target, path_style(available_python)) {
        (OsFamily::Windows, PathStyle::Posix) => {
            return Err(invalid(format!(
                "available python `{available_python}` is a POSIX path but the target is Windows"
            )))
        }
        (OsFamily::Linux | OsFamily::MacOs, PathStyle::Windows) => {
            return Err(invalid(format!(
                "available python `{available_python}` is a Windows path but the target is not \
                 Windows"
            )))
        }
        _ => {}
    }

    let base = available_python
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(available_python)
        .to_ascii_lowercase();
    let base = base.strip_suffix(".exe").unwrap_or(&base);
    let python3 = base == "python3"
        || base
            .strip_prefix("python3.")
            .is_some_and(|minor| !minor.is_empty() && minor.chars().all(|ch| ch.is_ascii_digit()));

    match target {
        OsFamily::Windows => {
            if base == "python" || python3 {
                Ok("python".to_string())
            } else {
                Err(invalid(format!(
                    "`{available_python}` is not a Python 3 interpreter for the Windows target"
                )))
            }
        }
        OsFamily::Linux | OsFamily::MacOs => {
            if python3 {
                Ok("python3".to_string())
            } else {
                Err(invalid(format!(
                    "`{available_python}` is not an unambiguous Python 3 interpreter; use \
                     `python3` on a Unix target"
                )))
            }
        }
    }
}

fn validate_python(python: &str) -> Result<()> {
    if python.is_empty() {
        return Err(invalid("kernel python must not be empty"));
    }
    if python.len() > MAX_PYTHON_BYTES {
        return Err(limit(format!(
            "kernel python is {} bytes; the limit is {MAX_PYTHON_BYTES}",
            python.len()
        )));
    }
    if python.trim() != python {
        return Err(invalid("kernel python must not be padded with whitespace"));
    }
    if python.chars().any(char::is_control) {
        return Err(invalid("kernel python must not contain control characters"));
    }
    if python.contains('/') || python.contains('\\') || python.contains(':') {
        return Err(invalid(format!(
            "kernel python `{python}` is a path; the plan carries a bare command so it stays \
             portable"
        )));
    }
    if !python
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(invalid(format!(
            "kernel python `{python}` contains characters that are not valid in a command name"
        )));
    }
    Ok(())
}

fn validate_package(package: &str) -> Result<()> {
    if package.is_empty() {
        return Err(invalid("a kernel package name must not be empty"));
    }
    if package.len() > MAX_PACKAGE_NAME_BYTES {
        return Err(limit(format!(
            "kernel package name is {} bytes; the limit is {MAX_PACKAGE_NAME_BYTES}",
            package.len()
        )));
    }
    if package.trim() != package {
        return Err(invalid(
            "a kernel package name must not start or end with whitespace",
        ));
    }
    if !package
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(invalid(format!(
            "kernel package `{package}` contains characters that are not valid in a \
             distribution name"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tool names
// ---------------------------------------------------------------------------

fn normalize_tool(tool: &str) -> String {
    let normalized = tool.trim().to_ascii_lowercase();
    normalized
        .strip_suffix(".exe")
        .unwrap_or(&normalized)
        .to_string()
}

fn normalize_tools<I, S>(tools: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut tools: Vec<String> = tools
        .into_iter()
        .map(|tool| normalize_tool(tool.as_ref()))
        .filter(|tool| !tool.is_empty())
        .collect();
    tools.sort_unstable();
    tools.dedup();
    tools
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

fn denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyDenied, message)
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn limit(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

fn tamper(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::TamperDetected, message)
}

type Result<T, E = ZeroError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{create, verify as verify_snapshot};

    const NOW: i64 = 1_700_000_000_000;

    fn key() -> KeyPair {
        KeyPair::generate().expect("device key")
    }

    fn windows_map() -> PathMap {
        PathMap::new(r"C:\Users\Alice\Proj", "/home/alice/proj", true).expect("map")
    }

    #[test]
    fn windows_drive_and_unc_paths_remap_to_posix() {
        let map = windows_map();
        assert_eq!(
            remap_path(r"C:\Users\Alice\Proj\src\main.rs", &map).expect("remap"),
            "/home/alice/proj/src/main.rs"
        );
        assert_eq!(
            remap_path(r"C:\Users\Alice\Proj", &map).expect("root"),
            "/home/alice/proj"
        );
        assert_eq!(
            remap_path("c:/users/alice/proj/SRC/Main.rs", &map).expect("case"),
            "/home/alice/proj/SRC/Main.rs"
        );
        assert_eq!(
            remap_path(r"C:\Users\Alice\Proj\With Space\naïve\文件.rs", &map)
                .expect("spaces and non-ascii"),
            "/home/alice/proj/With Space/naïve/文件.rs"
        );
        assert_eq!(
            remap_path("C:/Users\\Alice/Proj\\src", &map).expect("mixed separators"),
            "/home/alice/proj/src"
        );

        let unc = PathMap::new(r"\\Server\Share\Proj", "/mnt/share/proj", true).expect("unc map");
        assert_eq!(
            remap_path(r"\\server\SHARE\proj\src\lib.rs", &unc).expect("unc remap"),
            "/mnt/share/proj/src/lib.rs"
        );
    }

    #[test]
    fn posix_paths_remap_to_windows_drive_and_unc() {
        let drive = PathMap::new("/home/alice/proj", r"C:\Users\Alice\Proj", false).expect("map");
        assert_eq!(
            remap_path("/home/alice/proj/src/main.rs", &drive).expect("drive"),
            r"C:\Users\Alice\Proj\src\main.rs"
        );
        assert_eq!(
            remap_path("/home/alice/proj/With Space/naïve.rs", &drive).expect("spaces"),
            r"C:\Users\Alice\Proj\With Space\naïve.rs"
        );

        let unc = PathMap::new("/mnt/share/proj", r"\\Server\Share\Proj", false).expect("unc map");
        assert_eq!(
            remap_path("/mnt/share/proj/src/lib.rs", &unc).expect("unc"),
            r"\\Server\Share\Proj\src\lib.rs"
        );
    }

    #[test]
    fn outside_root_and_traversal_are_refused() {
        let map = windows_map();
        for path in [
            r"C:\Users\Alice\ProjOther\src\main.rs",
            r"C:\Users\Alice\Proj\..\secret",
            r"C:\Users\Alice\Proj\src\..\..\Windows",
            r"D:\Users\Alice\Proj\src\main.rs",
            r"Users\Alice\Proj\src\main.rs",
            "/home/alice/proj/src/main.rs",
        ] {
            assert_eq!(
                remap_path(path, &map).expect_err("must refuse").code(),
                ErrorCode::InvalidInput,
                "{path}"
            );
        }

        let posix = PathMap::new("/home/alice/proj", "/srv/zero", false).expect("posix map");
        assert_eq!(
            remap_path("/home/alice/project/src", &posix)
                .expect_err("prefix must be a component boundary")
                .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            remap_path("/home/alice/proj/../x", &posix)
                .expect_err("traversal")
                .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn case_sensitive_sources_refuse_a_case_only_difference() {
        let strict = PathMap::new(r"C:\Users\Alice\Proj", "/home/alice/proj", false).expect("map");
        assert_eq!(
            remap_path(r"c:\users\alice\proj\src\main.rs", &strict)
                .expect_err("case differs")
                .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            remap_path(r"C:\Users\Alice\Proj\src\main.rs", &strict).expect("exact case"),
            "/home/alice/proj/src/main.rs"
        );
    }

    #[test]
    fn maps_and_paths_are_bounded() {
        let long = format!("/{}", "a".repeat(MAX_REMAP_PATH_BYTES));
        let map = PathMap::new("/home/alice/proj", "/srv/zero", false).expect("map");
        assert_eq!(
            remap_path(&long, &map).expect_err("path cap").code(),
            ErrorCode::LimitExceeded
        );

        for bad in [
            String::new(),
            "relative/path".to_string(),
            r"C:\Users\..\Alice".to_string(),
            "/home/../alice".to_string(),
            r"C:".to_string(),
            r"\\server".to_string(),
        ] {
            assert_eq!(
                PathMap::new(bad.clone(), "/srv/zero", false)
                    .expect_err("bad root")
                    .code(),
                ErrorCode::InvalidInput,
                "{bad}"
            );
        }
    }

    #[test]
    fn a_working_directory_notice_names_both_roots() {
        let notice = working_directory_notice(&windows_map()).expect("notice");
        assert!(notice.contains(r"C:\Users\Alice\Proj"));
        assert!(notice.contains("/home/alice/proj"));
        assert!(notice.contains("Use the new path"));
    }

    #[test]
    fn remap_text_rewrites_only_path_tokens() {
        let maps = vec![windows_map()];
        let text = r#"cwd=C:\Users\Alice\Proj\src
note: C++ and /etc/hosts are unrelated
open "C:\Users\Alice\Proj\README.md" now.
path=/home/alice/other
see C:\Users\Alice\Proj\src\main.rs."#;
        let result = remap_text(text, &maps).expect("remap text");

        assert!(result.text.contains("/home/alice/proj/src"));
        assert!(result.text.contains("/home/alice/proj/README.md"));
        assert!(result.text.contains("C++"));
        assert!(result.text.contains("/etc/hosts"));
        assert!(result.text.contains("/home/alice/other"));
        assert!(result.text.contains("/home/alice/proj/src/main.rs."));
        assert!(!result.text.contains(r"C:\Users\Alice\Proj"));
        assert_eq!(result.reports.len(), 1);
        assert_eq!(result.reports[0].substituted, 3);
        assert_eq!(result.reports[0].skipped, 0);
        assert_eq!(result.substituted(), 3);
    }

    #[test]
    fn remap_text_handles_json_escaped_paths_and_quoted_spaces() {
        let maps = vec![windows_map()];
        let text = r#"{"cwd":"C:\\Users\\Alice\\Proj\\src","note":"kept"}"#;
        let result = remap_text(text, &maps).expect("json remap");
        assert_eq!(
            result.text,
            r#"{"cwd":"/home/alice/proj/src","note":"kept"}"#
        );
        assert_eq!(result.reports[0].substituted, 1);

        let quoted = r#"open "C:\Users\Alice\Proj\With Space\file name.txt" now"#;
        let result = remap_text(quoted, &maps).expect("quoted space remap");
        assert_eq!(
            result.text,
            r#"open "/home/alice/proj/With Space/file name.txt" now"#
        );

        let two_quotes = r#""hello" C:\Users\Alice\Proj\src "world""#;
        let result = remap_text(two_quotes, &maps).expect("two quoted words");
        assert_eq!(result.text, r#""hello" /home/alice/proj/src "world""#);
        assert_eq!(result.text.matches('"').count(), 4);
    }

    #[test]
    fn remap_text_reports_skipped_tokens_and_is_bounded() {
        let maps = vec![windows_map()];
        let text = r"leave C:\Users\Alice\Proj\..\secret alone";
        let result = remap_text(text, &maps).expect("skip traversal");
        assert_eq!(result.text, text);
        assert_eq!(result.reports[0].substituted, 0);
        assert_eq!(result.reports[0].skipped, 1);

        let too_long = "x".repeat(MAX_REMAP_TEXT_BYTES + 1);
        assert_eq!(
            remap_text(&too_long, &maps).expect_err("text cap").code(),
            ErrorCode::LimitExceeded
        );

        let too_many_maps = vec![windows_map(); MAX_PATH_MAPS + 1];
        assert_eq!(
            remap_text("plain", &too_many_maps)
                .expect_err("map cap")
                .code(),
            ErrorCode::LimitExceeded
        );

        let tokens = " /a".repeat(MAX_REMAP_TOKENS + 1);
        assert_eq!(
            remap_text(&tokens, &[]).expect_err("token cap").code(),
            ErrorCode::LimitExceeded
        );
    }

    #[test]
    fn remap_text_is_deterministic_and_the_first_map_wins() {
        let first = PathMap::new("/home/alice/proj", "/srv/first", false).expect("first");
        let second = PathMap::new("/home/alice", "/srv/second", false).expect("second");
        let maps = vec![first, second];

        let text = "cwd=/home/alice/proj/src and cache=/home/alice/.cache";
        let once = remap_text(text, &maps).expect("first remap");
        let twice = remap_text(text, &maps).expect("second remap");
        assert_eq!(once, twice);
        assert_eq!(once.text, "cwd=/srv/first/src and cache=/srv/second/.cache");
        assert_eq!(once.reports[0].substituted, 1);
        assert_eq!(once.reports[1].substituted, 1);
    }

    fn snapshot_with(path: &str) -> (KeyPair, Snapshot) {
        let device = key();
        let blobs = vec![
            ComponentBlob::new(Component::Session, format!("cwd={path}\n").into_bytes()),
            ComponentBlob::new(
                Component::Kernel,
                format!("{{\"cwd\":\"{path}\"}}").into_bytes(),
            ),
            ComponentBlob::new(
                Component::Artifacts,
                format!("artifact cwd={path}").into_bytes(),
            ),
            ComponentBlob::new(
                Component::Manifest,
                format!("manifest `{path}`").into_bytes(),
            ),
        ];
        let snapshot = create("project-1", blobs, NOW, &device).expect("snapshot");
        (device, snapshot)
    }

    #[test]
    fn remap_snapshot_re_signs_and_leaves_artifacts_alone() {
        let source = r"C:\Users\Alice\Proj";
        let (source_key, snapshot) = snapshot_with(source);
        let target_key = key();
        let map = PathMap::new(source, "/home/alice/proj", true).expect("map");

        let remapped = remap_snapshot_report(&snapshot, &[map], &target_key).expect("remap");

        verify_snapshot(&remapped.snapshot, &target_key.public_key_b64())
            .expect("target key verifies");
        assert_eq!(
            verify_snapshot(&remapped.snapshot, &source_key.public_key_b64())
                .expect_err("source key is invalid after the re-sign")
                .code(),
            ErrorCode::PolicyDenied
        );
        assert_eq!(
            remapped.remapped,
            vec![Component::Session, Component::Kernel, Component::Manifest]
        );
        assert_eq!(remapped.reports[0].substituted, 3);

        let session = std::str::from_utf8(&remapped.snapshot.blobs[&Component::Session])
            .expect("session text");
        assert!(session.contains("/home/alice/proj"));
        let kernel =
            std::str::from_utf8(&remapped.snapshot.blobs[&Component::Kernel]).expect("kernel text");
        assert!(kernel.contains("/home/alice/proj"));
        let manifest = std::str::from_utf8(&remapped.snapshot.blobs[&Component::Manifest])
            .expect("manifest text");
        assert!(manifest.contains("/home/alice/proj"));

        assert_eq!(
            remapped.snapshot.blobs[&Component::Artifacts],
            snapshot.blobs[&Component::Artifacts],
            "binary artifacts are not remapped"
        );
        assert_ne!(
            remapped.snapshot.manifest.snapshot_id,
            snapshot.manifest.snapshot_id
        );
    }

    #[test]
    fn remap_snapshot_is_deterministic_and_passes_through_non_utf8() {
        let target_key = key();
        let map = PathMap::new("/home/alice/proj", r"C:\Users\Alice\Proj", false).expect("map");

        let (_, snapshot) = snapshot_with("/home/alice/proj/src");
        let first =
            remap_snapshot(&snapshot, std::slice::from_ref(&map), &target_key).expect("first");
        let second = remap_snapshot(&snapshot, &[map], &target_key).expect("second");
        assert_eq!(first, second);

        let device = key();
        let blobs = vec![
            ComponentBlob::new(Component::Session, b"\xffnot utf-8".to_vec()),
            ComponentBlob::new(Component::Kernel, b"kernel".to_vec()),
            ComponentBlob::new(Component::Manifest, b"manifest".to_vec()),
        ];
        let binary = create("project-1", blobs, NOW, &device).expect("binary snapshot");
        let target_key = key();
        let remapped = remap_snapshot_report(&binary, &[], &target_key).expect("re-sign");
        assert!(remapped.remapped.is_empty());
        assert_eq!(
            remapped.snapshot.blobs[&Component::Session],
            binary.blobs[&Component::Session]
        );
        verify_snapshot(&remapped.snapshot, &target_key.public_key_b64())
            .expect("re-signed binary snapshot verifies");
    }

    #[test]
    fn remap_snapshot_refuses_an_inconsistent_snapshot() {
        let (_, mut snapshot) = snapshot_with("/home/alice/proj");
        snapshot
            .blobs
            .get_mut(&Component::Session)
            .expect("session")
            .push(b'!');
        let target_key = key();
        assert_eq!(
            remap_snapshot(&snapshot, &[], &target_key)
                .expect_err("tampered input must not be re-signed")
                .code(),
            ErrorCode::TamperDetected
        );
    }

    #[test]
    fn kernel_plans_are_target_appropriate_and_deterministic() {
        let linux = plan_kernel_rebuild("windows", "linux", "/usr/bin/python3.11")
            .expect("windows to linux");
        assert_eq!(linux.python, "python3");
        assert_eq!(
            linux.packages,
            KERNEL_PACKAGES
                .iter()
                .map(|package| (*package).to_string())
                .collect::<Vec<_>>()
        );
        assert!(!linux.offline_cache);
        assert!(!linux.python.contains('\\'));
        assert!(!linux.python.contains(':'));

        let repeated = plan_kernel_rebuild("windows", "linux", "python3").expect("repeat");
        assert_eq!(linux, repeated);

        let windows = plan_kernel_rebuild("linux", "windows", r"C:\Python312\python.exe")
            .expect("to windows");
        assert_eq!(windows.python, "python");
        assert!(!windows.offline_cache);

        let same = plan_kernel_rebuild("linux", "linux", "/usr/bin/python3").expect("same os");
        assert!(same.offline_cache);

        let mac = plan_kernel_rebuild("macos", "linux", "python3").expect("mac to linux");
        assert_eq!(mac.python, "python3");
        assert!(!mac.offline_cache);
    }

    #[test]
    fn kernel_plans_refuse_foreign_or_ambiguous_python() {
        for (target, available) in [
            ("linux", r"C:\Python312\python.exe"),
            ("windows", "/usr/bin/python3"),
            ("linux", "python"),
            ("linux", "python2"),
            ("windows", "python2"),
            ("linux", ""),
        ] {
            assert_eq!(
                plan_kernel_rebuild("linux", target, available)
                    .expect_err("must refuse")
                    .code(),
                ErrorCode::InvalidInput,
                "{target} {available}"
            );
        }
        assert_eq!(
            plan_kernel_rebuild("plan9", "linux", "python3")
                .expect_err("unknown os")
                .code(),
            ErrorCode::InvalidInput
        );

        let plan = KernelRebuildPlan {
            python: r"C:\Python\python.exe".to_string(),
            packages: vec!["ipykernel".to_string()],
            offline_cache: false,
        };
        assert_eq!(
            plan.validate().expect_err("path in plan").code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn preflight_reports_missing_tools_with_per_tool_guidance() {
        let required = vec![
            "git".to_string(),
            "node".to_string(),
            "python3".to_string(),
            "git".to_string(),
        ];
        let probes = ToolSet::new(["node"]);
        let report = preflight(&required, &probes);

        assert!(!report.ok);
        assert_eq!(report.required, vec!["git", "node", "python3"]);
        assert_eq!(report.available, vec!["node"]);
        assert_eq!(report.missing, vec!["git", "python3"]);
        assert!(report.guidance["git"].contains("no-git"));
        assert!(report.guidance["python3"].contains("Python 3.11"));
        assert!(!report.guidance.contains_key("node"));

        let spec = ToolPreflight::new(
            vec!["python3".to_string(), "pip".to_string()],
            vec![
                "python3".to_string(),
                "pip".to_string(),
                "pip.exe".to_string(),
            ],
        );
        let report = preflight(&spec.required, &spec);
        assert!(report.ok);
        assert_eq!(report.required, vec!["pip", "python3"]);
        assert_eq!(report.available, vec!["pip", "python3"]);
        assert!(report.missing.is_empty());
        assert!(report.guidance.is_empty());

        let unknown = preflight(
            &["frobnicator".to_string()],
            &ToolSet::new(Vec::<String>::new()),
        );
        assert!(!unknown.ok);
        assert!(unknown.guidance["frobnicator"].contains("PATH"));
    }

    #[test]
    fn a_no_git_directory_passes_without_git() {
        let plan = plan_kernel_rebuild("linux", "linux", "python3").expect("plan");
        let spec = ToolPreflight::new(
            vec!["python3".to_string(), "pip".to_string()],
            vec!["python3".to_string(), "pip".to_string()],
        );
        let report = preflight(&spec.required, &spec);
        can_run(&plan, &report, true).expect("a no-git directory does not need git");
        can_run(&plan, &report, false).expect("the same plan works with git available");
    }

    #[test]
    fn a_no_git_directory_refuses_a_git_requirement() {
        let plan = plan_kernel_rebuild("linux", "linux", "python3").expect("plan");
        let spec = ToolPreflight::new(
            vec!["git".to_string(), "python3".to_string()],
            vec!["git".to_string(), "python3".to_string()],
        );
        let report = preflight(&spec.required, &spec);
        assert!(report.ok);

        let error = can_run(&plan, &report, true).expect_err("git is refused in a no-git dir");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.to_string().contains("no git repository"));
        assert!(error.to_string().contains("must not require git"));
        can_run(&plan, &report, false).expect("git is accepted when a repository may exist");
    }

    #[test]
    fn can_run_refuses_missing_tools_and_unchecked_python() {
        let plan = plan_kernel_rebuild("linux", "linux", "python3").expect("plan");

        let spec = ToolPreflight::new(vec!["python3".to_string()], Vec::<String>::new());
        let report = preflight(&spec.required, &spec);
        let error = can_run(&plan, &report, false).expect_err("missing python3");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.to_string().contains("python3"));
        assert!(error.to_string().contains("Install Python"));

        let spec = ToolPreflight::new(vec!["pip".to_string()], vec!["pip".to_string()]);
        let report = preflight(&spec.required, &spec);
        let error = can_run(&plan, &report, false).expect_err("python was not checked");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.to_string().contains("python3"));
    }
}
