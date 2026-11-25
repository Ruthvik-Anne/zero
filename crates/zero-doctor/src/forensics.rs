//! Incident timeline and redacted offline support bundle (DOC-07, OBS-07).
//!
//! Forensics has to work after the fact: the daemon, kernel, and mesh may all
//! be dead, so this module reads only caller-supplied artifacts and local files
//! and has no network code at all. Two pieces are exposed:
//!
//! - [`Timeline::from_artifacts`] folds JSONL or tab-separated log artifacts
//!   into one deterministic [`TimelineEvent`] list: sorted by `(at_ms, source,
//!   kind, detail)` with `actor` as the final tie-break, exact repeats removed,
//!   and the list bounded by [`MAX_TIMELINE_EVENTS`]. A malformed line is
//!   counted, never fatal, and the line's contents are never echoed.
//! - [`build_bundle`] writes a self-contained directory bundle (`manifest.json`,
//!   `timeline.jsonl`, and redacted copies of whitelisted files) that can be read
//!   without the daemon. Path exclusions, a redaction pass, and per-file/total
//!   size caps are applied before anything is written.
//!
//! Errors carry paths and reasons only. File contents, secret values, and raw
//! malformed lines never reach an error or a report.
//!
//! File hashes use a documented non-cryptographic FNV-1a 64 (the same algorithm
//! family `zero-mcp` uses) because this crate's manifest does not depend on a
//! hashing crate. The hash exists to prove two bundles came from the same bytes,
//! not to resist an attacker who already has the bundle.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

use crate::VERSION;

/// Hard cap on retained timeline events. Newest events are dropped first and
/// the drop is reported.
pub const MAX_TIMELINE_EVENTS: usize = 10_000;

/// Longest `detail` kept per timeline event, in characters.
pub const MAX_DETAIL_CHARS: usize = 512;
/// Longest `kind` kept per timeline event, in characters.
pub const MAX_KIND_CHARS: usize = 80;
/// Longest `source`, `actor`, or path label kept, in characters.
pub const MAX_LABEL_CHARS: usize = 120;

/// The marker that replaces a redacted value.
pub const REDACTED: &str = "[redacted]";

/// Caller-provided values shorter than this are not redacted: replacing a very
/// short string corrupts unrelated text without hiding a usable secret.
pub const MIN_REDACTION_CHARS: usize = 4;

/// Default cap for one file inside a bundle.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 1024 * 1024;
/// Default cap for all copied content inside a bundle.
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;

/// Bundle manifest schema version.
pub const BUNDLE_SCHEMA_VERSION: u32 = 1;

/// Manifest file name inside the bundle directory.
pub const MANIFEST_FILE: &str = "manifest.json";
/// Timeline file name inside the bundle directory.
pub const TIMELINE_FILE: &str = "timeline.jsonl";
/// Subdirectory that holds copies of whitelisted files.
pub const FILES_DIR: &str = "files";

/// The stable "no network was used" value reported by the bundle.
pub const NETWORK_NONE: &str = "none";

/// The stable hash algorithm name used in manifests and file entries.
pub const HASH_ALGORITHM: &str = "fnv1a64";

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Strong credential prefixes. A marker must begin a token; the whole token is
/// replaced, never just the prefix.
const STRONG_MARKERS: [&str; 4] = ["sk-", "ghp_", "oc_sk_", "AKIA"];

// ---------------------------------------------------------------------------
// Timeline
// ---------------------------------------------------------------------------

/// One incident-timeline record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEvent {
    /// Milliseconds since the Unix epoch.
    pub at_ms: i64,
    /// The artifact the line came from (for example a journal name).
    pub source: String,
    /// The event kind (`turn`, `mesh`, `repair`, ...).
    pub kind: String,
    /// Who or what produced it, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Redaction-safe detail. Control characters are stripped and the length is
    /// bounded by [`MAX_DETAIL_CHARS`].
    pub detail: String,
}

/// One caller-supplied log artifact. Lines are in memory; nothing is opened by
/// this module for timelines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    /// Stable name used as the event `source`.
    pub name: String,
    /// Raw lines: JSONL objects or `timestamp<TAB>kind<TAB>detail`.
    pub lines: Vec<String>,
}

/// A folded, ordered, de-duplicated, bounded timeline.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Timeline {
    pub events: Vec<TimelineEvent>,
    /// Lines that could not be parsed. Their contents are never retained.
    pub malformed: usize,
    /// Exact repeats removed by de-duplication.
    pub duplicates: usize,
    /// Events dropped because the timeline exceeded [`MAX_TIMELINE_EVENTS`].
    pub dropped: usize,
    /// Whether any event was dropped.
    pub truncated: bool,
}

impl Timeline {
    /// Fold artifacts into one timeline.
    ///
    /// Artifacts are processed in `name` order and each line is parsed as JSONL
    /// when it starts with `{`, otherwise as `timestamp<TAB>kind<TAB>detail`.
    /// Blank lines are ignored; unparseable lines increment `malformed`.
    pub fn from_artifacts(artifacts: &[Artifact]) -> Self {
        let mut ordered: Vec<&Artifact> = artifacts.iter().collect();
        ordered.sort_by(|a, b| a.name.cmp(&b.name));

        let mut events = Vec::new();
        let mut malformed = 0usize;
        for artifact in ordered {
            let source = one_line(&artifact.name, MAX_LABEL_CHARS);
            for line in &artifact.lines {
                let line = line.trim_end_matches('\r');
                if line.trim().is_empty() {
                    continue;
                }
                match event_from_line(&source, line) {
                    Some(event) => events.push(event),
                    None => malformed += 1,
                }
            }
        }

        let mut timeline = Self {
            events,
            malformed,
            duplicates: 0,
            dropped: 0,
            truncated: false,
        };
        timeline.normalize();
        timeline
    }

    /// Redact caller values and strong credential markers in every event field.
    ///
    /// Returns the number of replacements. The timeline is re-sorted and
    /// re-deduplicated afterwards, because redaction can change a sort key.
    pub fn redact(&mut self, redactions: &[String]) -> usize {
        let mut count = 0usize;
        for event in &mut self.events {
            let (source, hits) = redact_text(&event.source, redactions);
            event.source = source;
            count += hits;

            let (kind, hits) = redact_text(&event.kind, redactions);
            event.kind = kind;
            count += hits;

            if let Some(actor) = event.actor.as_mut() {
                let (redacted, hits) = redact_text(actor, redactions);
                *actor = redacted;
                count += hits;
            }

            let (detail, hits) = redact_text(&event.detail, redactions);
            event.detail = detail;
            count += hits;
        }
        self.normalize();
        count
    }

    /// Number of retained events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the timeline has no events.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Sort, remove exact repeats, and enforce the event bound.
    fn normalize(&mut self) {
        self.events.sort_by(event_order);
        let before = self.events.len();
        self.events.dedup();
        self.duplicates += before - self.events.len();
        if self.events.len() > MAX_TIMELINE_EVENTS {
            let excess = self.events.len() - MAX_TIMELINE_EVENTS;
            self.events.truncate(MAX_TIMELINE_EVENTS);
            self.dropped += excess;
            self.truncated = true;
        }
    }
}

fn event_order(a: &TimelineEvent, b: &TimelineEvent) -> std::cmp::Ordering {
    a.at_ms
        .cmp(&b.at_ms)
        .then_with(|| a.source.cmp(&b.source))
        .then_with(|| a.kind.cmp(&b.kind))
        .then_with(|| a.detail.cmp(&b.detail))
        .then_with(|| a.actor.cmp(&b.actor))
}

fn event_from_line(source: &str, line: &str) -> Option<TimelineEvent> {
    if line.trim_start().starts_with('{') {
        event_from_json(source, line)
    } else {
        event_from_tsv(source, line)
    }
}

fn event_from_json(source: &str, line: &str) -> Option<TimelineEvent> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let object = value.as_object()?;
    let at = ["at_ms", "ts_ms", "timestamp_ms", "at", "ts", "timestamp"]
        .iter()
        .find_map(|key| object.get(*key))?;
    let at_ms = timestamp_value(at)?;
    let kind =
        string_field(object, &["kind", "event", "type"]).unwrap_or_else(|| "event".to_string());
    let actor = string_field(object, &["actor", "by", "user"]);
    let detail = string_field(object, &["detail", "message", "msg"]).unwrap_or_default();
    Some(build_event(at_ms, source, &kind, actor, &detail))
}

fn string_field(
    object: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(serde_json::Value::as_str))
        .map(str::to_string)
}

fn timestamp_value(value: &serde_json::Value) -> Option<i64> {
    if let Some(number) = value.as_i64() {
        return Some(number);
    }
    if let Some(number) = value.as_f64() {
        return number
            .is_finite()
            .then(|| number.round())
            .filter(|number| *number >= i64::MIN as f64 && *number <= i64::MAX as f64)
            .map(|number| number as i64);
    }
    value.as_str().and_then(parse_timestamp)
}

fn event_from_tsv(source: &str, line: &str) -> Option<TimelineEvent> {
    let mut parts = line.splitn(3, '\t');
    let at = parts.next()?;
    let kind = parts.next()?;
    let detail = parts.next().unwrap_or("");
    let kind = kind.trim();
    if kind.is_empty() {
        return None;
    }
    let at_ms = parse_timestamp(at)?;
    Some(build_event(at_ms, source, kind, None, detail))
}

fn build_event(
    at_ms: i64,
    source: &str,
    kind: &str,
    actor: Option<String>,
    detail: &str,
) -> TimelineEvent {
    TimelineEvent {
        at_ms,
        source: one_line(source, MAX_LABEL_CHARS),
        kind: one_line(kind, MAX_KIND_CHARS),
        actor: actor
            .map(|actor| one_line(&actor, MAX_LABEL_CHARS))
            .filter(|actor| !actor.is_empty()),
        detail: one_line(detail, MAX_DETAIL_CHARS),
    }
}

/// Parse `timestamp` as integer milliseconds, or as RFC 3339 UTC.
fn parse_timestamp(text: &str) -> Option<i64> {
    let text = text.trim().trim_matches('"').trim();
    if text.is_empty() {
        return None;
    }
    if let Ok(ms) = text.parse::<i64>() {
        return Some(ms);
    }
    parse_rfc3339_ms(text)
}

/// Minimal RFC 3339 parser: `YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)`.
///
/// No calendar crate is in this crate's dependency set, so this parses exactly
/// the shapes logs emit and rejects anything else as malformed.
fn parse_rfc3339_ms(text: &str) -> Option<i64> {
    let separator = text.find(['T', 't', ' '])?;
    let date = &text[..separator];
    let rest = &text[separator + 1..];

    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;
    if date_parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    let (clock, offset_minutes) = split_offset(rest)?;
    let mut clock_parts = clock.split(':');
    let hour: u32 = clock_parts.next()?.parse().ok()?;
    let minute: u32 = clock_parts.next()?.parse().ok()?;
    let seconds_text = clock_parts.next()?;
    if clock_parts.next().is_some() || hour > 23 || minute > 59 {
        return None;
    }

    let (second_text, fraction) = match seconds_text.split_once('.') {
        Some((seconds, fraction)) => (seconds, Some(fraction)),
        None => (seconds_text, None),
    };
    let second: u32 = second_text.parse().ok()?;
    if second > 60 {
        return None;
    }

    let millis = match fraction {
        None => 0u32,
        Some(fraction) => {
            if fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            let digits: String = fraction
                .chars()
                .chain(std::iter::repeat('0'))
                .take(3)
                .collect();
            digits.parse().ok()?
        }
    };

    let days = days_from_civil(year, month, day);
    let seconds =
        days * 86_400 + i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second);
    Some(seconds * 1_000 + i64::from(millis) - i64::from(offset_minutes) * 60_000)
}

/// Split the clock portion from its `Z` or `±HH:MM` offset.
fn split_offset(rest: &str) -> Option<(&str, i32)> {
    if let Some(clock) = rest.strip_suffix('Z').or_else(|| rest.strip_suffix('z')) {
        return Some((clock, 0));
    }
    let index = rest.rfind(['+', '-'])?;
    let (clock, offset) = rest.split_at(index);
    let sign = if offset.starts_with('-') { -1 } else { 1 };
    let (hours, minutes) = offset[1..].split_once(':')?;
    let hours: i32 = hours.parse().ok()?;
    let minutes: i32 = minutes.parse().ok()?;
    if hours > 23 || minutes > 59 {
        return None;
    }
    Some((clock, sign * (hours * 60 + minutes)))
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = i64::from((month + 9) % 12);
    let day_of_year = (153 * month_prime + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Strip control characters, keep one line, and bound the length.
fn one_line(text: &str, max: usize) -> String {
    let mut out = String::new();
    for (index, ch) in text.chars().enumerate() {
        if index >= max {
            out.push('…');
            break;
        }
        out.push(if ch.is_control() { '?' } else { ch });
    }
    out
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

/// Redact caller-provided values and strong credential markers in `text`.
///
/// Order matters: PEM blocks first, then strong markers (whole token), then
/// literal caller values. Running the token pass first keeps a caller value that
/// sits inside a token from splitting the token and leaving its tail behind.
/// Returns the redacted text and the number of replacements.
pub fn redact_text(text: &str, redactions: &[String]) -> (String, usize) {
    let (out, mut count) = redact_pem_blocks(text);
    let (out, hits) = redact_strong_tokens(&out);
    count += hits;

    let mut values: Vec<&str> = redactions
        .iter()
        .map(String::as_str)
        .filter(|value| value.chars().count() >= MIN_REDACTION_CHARS)
        .collect();
    values.sort_by(|a, b| {
        b.chars()
            .count()
            .cmp(&a.chars().count())
            .then_with(|| a.cmp(b))
    });
    values.dedup();

    let mut text = out;
    for value in values {
        if !text.contains(value) {
            continue;
        }
        count += text.matches(value).count();
        text = text.replace(value, REDACTED);
    }
    (text, count)
}

/// Replace whole PEM blocks, from a `-----BEGIN` line through its `-----END`
/// line. An unterminated block redacts to the end of the text (fail safe).
fn redact_pem_blocks(text: &str) -> (String, usize) {
    let mut out = String::with_capacity(text.len());
    let mut lines = text.split('\n').peekable();
    let mut in_block = false;
    let mut count = 0usize;

    while let Some(line) = lines.next() {
        if in_block {
            if line.to_ascii_uppercase().contains("-----END") {
                in_block = false;
                count += 1;
            }
            out.push_str(REDACTED);
        } else if line.to_ascii_uppercase().contains("-----BEGIN") {
            out.push_str(REDACTED);
            in_block = !line.to_ascii_uppercase().contains("-----END");
            if !in_block {
                count += 1;
            }
        } else {
            out.push_str(line);
        }
        if lines.peek().is_some() {
            out.push('\n');
        }
    }
    (out, count)
}

fn is_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '+' | '/')
}

/// Replace every strong marker token, including its whole tail.
fn redact_strong_tokens(text: &str) -> (String, usize) {
    let mut out = String::with_capacity(text.len());
    let mut count = 0usize;
    let mut cursor = 0usize;

    while let Some((start, marker_len)) = find_marker_at_boundary(&text[cursor..], &STRONG_MARKERS)
    {
        let start = cursor + start;
        let mut end = start + marker_len;
        while end < text.len() {
            let Some(ch) = text[end..].chars().next() else {
                break;
            };
            if !is_token_char(ch) {
                break;
            }
            end += ch.len_utf8();
        }
        out.push_str(&text[cursor..start]);
        out.push_str(REDACTED);
        count += 1;
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    (out, count)
}

/// Leftmost marker whose match begins a token (start of text or after a
/// non-token character). Ties prefer the longer marker.
fn find_marker_at_boundary(haystack: &str, markers: &[&str]) -> Option<(usize, usize)> {
    let mut best: Option<(usize, usize)> = None;
    for marker in markers {
        let mut from = 0usize;
        while let Some(found) = haystack[from..].find(marker) {
            let index = from + found;
            let at_boundary = index == 0
                || !haystack[..index]
                    .chars()
                    .next_back()
                    .is_some_and(is_token_char);
            if at_boundary {
                let replace = match best {
                    None => true,
                    Some((best_index, best_len)) => {
                        index < best_index || (index == best_index && marker.len() > best_len)
                    }
                };
                if replace {
                    best = Some((index, marker.len()));
                }
                break;
            }
            from = index + marker.len();
        }
    }
    best
}

// ---------------------------------------------------------------------------
// Bundle
// ---------------------------------------------------------------------------

/// Everything the bundle may include. `extra_files` are absolute paths or paths
/// relative to `root`; each is whitelisted individually, never walked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleInputs {
    pub root: PathBuf,
    pub timelines: Vec<Artifact>,
    pub extra_files: Vec<PathBuf>,
    /// Caller-known secret values (length >= 4) plus path fragments to exclude.
    pub redactions: Vec<String>,
}

/// Caps and the injected clock.
///
/// `created_at_ms` is an input so the same inputs produce byte-identical
/// bundles in tests and repeat runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleLimits {
    /// Largest single file (after redaction) that may be copied.
    pub max_file_bytes: u64,
    /// Largest total bytes of copied content (timeline plus extra files).
    pub max_total_bytes: u64,
    /// Bundle creation time, milliseconds since the Unix epoch.
    pub created_at_ms: i64,
}

impl Default for BundleLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            created_at_ms: now_ms(),
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

/// One file that made it into the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleFile {
    /// Bundle-relative path with `/` separators.
    pub path: String,
    /// Bytes written, after redaction.
    pub bytes: u64,
    /// `fnv1a64:<16 hex digits>` over the written bytes.
    pub hash: String,
}

/// Why a candidate file was left out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// A hard exclusion: vault, keys, credentials, `.env`, PEM/key stores, a
    /// `secret`/`token`/`credential` path segment, or a caller redaction value.
    ExcludedPath,
    /// Resolves outside `root` (directly or through a symlinked ancestor).
    OutsideRoot,
    /// The entry itself is a symlink.
    Symlink,
    /// Not a regular file (directory, device, socket, ...).
    NotFile,
    /// Already inside the bundle output directory.
    InBundle,
    /// Larger than the per-file cap.
    Oversize,
    /// Would exceed the total bundle cap.
    TotalLimit,
    /// Could not be read.
    Unreadable,
    /// Not UTF-8 text or contains NUL, so it is dropped instead of copied.
    Binary,
    /// Listed more than once.
    Duplicate,
}

impl SkipReason {
    /// Stable snake_case name, used for sorting and for human output.
    pub fn as_str(self) -> &'static str {
        match self {
            SkipReason::ExcludedPath => "excluded_path",
            SkipReason::OutsideRoot => "outside_root",
            SkipReason::Symlink => "symlink",
            SkipReason::NotFile => "not_file",
            SkipReason::InBundle => "in_bundle",
            SkipReason::Oversize => "oversize",
            SkipReason::TotalLimit => "total_limit",
            SkipReason::Unreadable => "unreadable",
            SkipReason::Binary => "binary",
            SkipReason::Duplicate => "duplicate",
        }
    }
}

/// A candidate that was left out, with the reason and its size when known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedFile {
    /// Root-relative path when inside `root`, otherwise the caller's path.
    pub path: String,
    pub reason: SkipReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
}

/// Truncation and cap flags, always present in the manifest.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruncationFlags {
    pub timeline_truncated: bool,
    pub timeline_events_dropped: usize,
    pub files_skipped: usize,
    pub total_capped: bool,
}

/// Timeline statistics recorded in the manifest.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineStats {
    pub events: usize,
    pub malformed: usize,
    pub duplicates: usize,
    pub dropped: usize,
    pub truncated: bool,
}

/// `manifest.json` contents. It lists every bundle file except itself: a file
/// cannot carry its own hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    pub schema_version: u32,
    pub zero_doctor_version: String,
    pub created_at_ms: i64,
    pub network: String,
    pub offline: bool,
    pub hash_algorithm: String,
    pub total_bytes: u64,
    pub redaction_count: usize,
    pub truncation: TruncationFlags,
    pub timeline: TimelineStats,
    pub files: Vec<BundleFile>,
    pub skipped: Vec<SkippedFile>,
}

/// The result of [`build_bundle`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleReport {
    pub out_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub network: String,
    pub offline: bool,
    pub total_bytes: u64,
    pub redactions: usize,
    pub files: Vec<BundleFile>,
    pub skipped: Vec<SkippedFile>,
    pub timeline: TimelineStats,
    pub truncation: TruncationFlags,
}

/// Typed bundle failure. Paths and reasons only; never file contents.
#[derive(Debug, Error)]
pub enum ForensicsError {
    /// `BundleInputs::root` is not a readable directory.
    #[error("bundle root is not a readable directory: {path}")]
    Root { path: PathBuf },
    /// The output directory could not be created or resolved.
    #[error("bundle output directory is not usable: {path}: {source}")]
    Output {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// A bundle file could not be written.
    #[error("bundle file could not be written: {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The manifest or the timeline could not be serialized.
    #[error("bundle serialization failed: {reason}")]
    Serialize { reason: String },
}

struct Candidate {
    label: String,
    source: PathBuf,
    bundle_path: PathBuf,
}

/// Write a self-contained, redacted bundle directory.
///
/// Layout: `manifest.json`, `timeline.jsonl`, and `files/<root-relative path>`
/// for each whitelisted extra file. Nothing is fetched and no service is
/// contacted; the report says `network: "none"` and `offline: true`.
///
/// The order is fixed: timeline, then extras sorted by bundle path, then the
/// manifest. A candidate file that cannot be included is skipped and reported,
/// never truncated silently.
pub fn build_bundle(
    inputs: &BundleInputs,
    out_dir: impl AsRef<Path>,
    limits: &BundleLimits,
) -> Result<BundleReport, ForensicsError> {
    let out_dir = out_dir.as_ref().to_path_buf();
    std::fs::create_dir_all(&out_dir).map_err(|source| ForensicsError::Output {
        path: out_dir.clone(),
        source,
    })?;
    let out_canonical =
        std::fs::canonicalize(&out_dir).map_err(|source| ForensicsError::Output {
            path: out_dir.clone(),
            source,
        })?;
    let root = std::fs::canonicalize(&inputs.root).map_err(|_| ForensicsError::Root {
        path: inputs.root.clone(),
    })?;
    if !root.is_dir() {
        return Err(ForensicsError::Root {
            path: inputs.root.clone(),
        });
    }

    let mut timeline = Timeline::from_artifacts(&inputs.timelines);
    let mut redactions = timeline.redact(&inputs.redactions);
    let mut skipped: Vec<SkippedFile> = Vec::new();
    let mut total_capped = false;

    // Classify every extra file before writing anything, so the manifest order
    // does not depend on directory iteration or caller ordering.
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    for raw in &inputs.extra_files {
        let source = if raw.is_absolute() {
            raw.clone()
        } else {
            root.join(raw)
        };
        let label = display_path(&root, &source);

        match std::fs::symlink_metadata(&source) {
            Err(_) => {
                push_skip(&mut skipped, label, SkipReason::Unreadable, None);
                continue;
            }
            Ok(metadata) if metadata.file_type().is_symlink() => {
                push_skip(&mut skipped, label, SkipReason::Symlink, None);
                continue;
            }
            Ok(metadata) if !metadata.is_file() => {
                push_skip(
                    &mut skipped,
                    label,
                    SkipReason::NotFile,
                    Some(metadata.len()),
                );
                continue;
            }
            Ok(_) => {}
        }

        let Ok(canonical) = std::fs::canonicalize(&source) else {
            push_skip(&mut skipped, label, SkipReason::Unreadable, None);
            continue;
        };
        if !canonical.starts_with(&root) {
            push_skip(&mut skipped, label, SkipReason::OutsideRoot, None);
            continue;
        }
        if canonical.starts_with(&out_canonical) {
            push_skip(&mut skipped, label, SkipReason::InBundle, None);
            continue;
        }
        let Ok(relative) = canonical.strip_prefix(&root) else {
            push_skip(&mut skipped, label, SkipReason::OutsideRoot, None);
            continue;
        };
        if relative.as_os_str().is_empty()
            || !relative
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
        {
            push_skip(&mut skipped, label, SkipReason::OutsideRoot, None);
            continue;
        }
        if is_excluded(relative, &inputs.redactions) {
            push_skip(&mut skipped, label, SkipReason::ExcludedPath, None);
            continue;
        }
        if !seen.insert(relative.to_path_buf()) {
            push_skip(&mut skipped, label, SkipReason::Duplicate, None);
            continue;
        }
        let bundle_path = Path::new(FILES_DIR).join(relative);
        candidates.push(Candidate {
            label,
            bundle_path,
            source: canonical,
        });
    }
    candidates.sort_by(|a, b| a.bundle_path.cmp(&b.bundle_path));

    // Timeline first, bounded by both the per-file cap and the total cap.
    let mut lines: Vec<String> = Vec::with_capacity(timeline.events.len());
    for event in &timeline.events {
        let line = serde_json::to_string(event).map_err(|error| ForensicsError::Serialize {
            reason: error.to_string(),
        })?;
        lines.push(line);
    }
    let available = limits.max_file_bytes.min(limits.max_total_bytes);
    let mut timeline_bytes: u64 = lines.iter().map(|line| line.len() as u64 + 1).sum();
    let mut dropped_by_cap = 0usize;
    while timeline_bytes > available {
        let Some(line) = lines.pop() else { break };
        timeline_bytes -= line.len() as u64 + 1;
        dropped_by_cap += 1;
    }
    let timeline_text = if lines.is_empty() {
        String::new()
    } else {
        let mut text = lines.join("\n");
        text.push('\n');
        text
    };
    let written_timeline = timeline_text.len() as u64;
    write_file(&out_dir.join(TIMELINE_FILE), timeline_text.as_bytes())?;

    let mut files = vec![BundleFile {
        path: TIMELINE_FILE.to_string(),
        bytes: written_timeline,
        hash: hash_hex(timeline_text.as_bytes()),
    }];
    let mut total_bytes = written_timeline;

    for candidate in &candidates {
        let metadata = match std::fs::symlink_metadata(&candidate.source) {
            Ok(metadata) => metadata,
            Err(_) => {
                push_skip(
                    &mut skipped,
                    candidate.label.clone(),
                    SkipReason::Unreadable,
                    None,
                );
                continue;
            }
        };
        if metadata.len() > limits.max_file_bytes {
            push_skip(
                &mut skipped,
                candidate.label.clone(),
                SkipReason::Oversize,
                Some(metadata.len()),
            );
            continue;
        }
        let raw = match std::fs::read(&candidate.source) {
            Ok(raw) => raw,
            Err(_) => {
                push_skip(
                    &mut skipped,
                    candidate.label.clone(),
                    SkipReason::Unreadable,
                    None,
                );
                continue;
            }
        };
        if raw.contains(&0) {
            push_skip(
                &mut skipped,
                candidate.label.clone(),
                SkipReason::Binary,
                Some(raw.len() as u64),
            );
            continue;
        }
        let Ok(text) = std::str::from_utf8(&raw) else {
            push_skip(
                &mut skipped,
                candidate.label.clone(),
                SkipReason::Binary,
                Some(raw.len() as u64),
            );
            continue;
        };
        let (redacted, hits) = redact_text(text, &inputs.redactions);
        redactions += hits;
        let redacted = redacted.into_bytes();
        if redacted.len() as u64 > limits.max_file_bytes {
            push_skip(
                &mut skipped,
                candidate.label.clone(),
                SkipReason::Oversize,
                Some(redacted.len() as u64),
            );
            continue;
        }
        if total_bytes + redacted.len() as u64 > limits.max_total_bytes {
            total_capped = true;
            push_skip(
                &mut skipped,
                candidate.label.clone(),
                SkipReason::TotalLimit,
                Some(redacted.len() as u64),
            );
            continue;
        }
        let path = out_dir.join(&candidate.bundle_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| ForensicsError::Output {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        write_file(&path, &redacted)?;
        total_bytes += redacted.len() as u64;
        files.push(BundleFile {
            path: bundle_path_string(&candidate.bundle_path),
            bytes: redacted.len() as u64,
            hash: hash_hex(&redacted),
        });
    }

    // Skipped paths are the one place a caller-declared value can survive: a
    // file is excluded *because* its path carries the value. Redact the label so
    // the manifest does not echo the value either.
    for skip in &mut skipped {
        let (path, hits) = redact_text(&skip.path, &inputs.redactions);
        skip.path = path;
        redactions += hits;
    }

    files.sort_by(|a, b| a.path.cmp(&b.path));
    skipped.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.reason.as_str().cmp(b.reason.as_str()))
    });

    let timeline_stats = TimelineStats {
        events: lines.len(),
        malformed: timeline.malformed,
        duplicates: timeline.duplicates,
        dropped: timeline.dropped + dropped_by_cap,
        truncated: timeline.truncated || dropped_by_cap > 0,
    };
    let truncation = TruncationFlags {
        timeline_truncated: timeline_stats.truncated,
        timeline_events_dropped: timeline_stats.dropped,
        files_skipped: skipped.len(),
        total_capped,
    };
    let manifest = BundleManifest {
        schema_version: BUNDLE_SCHEMA_VERSION,
        zero_doctor_version: VERSION.to_string(),
        created_at_ms: limits.created_at_ms,
        network: NETWORK_NONE.to_string(),
        offline: true,
        hash_algorithm: HASH_ALGORITHM.to_string(),
        total_bytes,
        redaction_count: redactions,
        truncation,
        timeline: timeline_stats,
        files: files.clone(),
        skipped: skipped.clone(),
    };
    let mut manifest_bytes =
        serde_json::to_vec_pretty(&manifest).map_err(|error| ForensicsError::Serialize {
            reason: error.to_string(),
        })?;
    manifest_bytes.push(b'\n');
    let manifest_path = out_dir.join(MANIFEST_FILE);
    write_file(&manifest_path, &manifest_bytes)?;

    Ok(BundleReport {
        out_dir,
        manifest_path,
        network: NETWORK_NONE.to_string(),
        offline: true,
        total_bytes,
        redactions,
        files,
        skipped,
        timeline: timeline_stats,
        truncation,
    })
}

fn push_skip(skipped: &mut Vec<SkippedFile>, path: String, reason: SkipReason, bytes: Option<u64>) {
    skipped.push(SkippedFile {
        path,
        reason,
        bytes,
    });
}

/// Hard path exclusions. Case-insensitive and component-aware so a directory
/// named `keys` is excluded but `monkeys.txt` is not.
fn is_excluded(relative: &Path, redactions: &[String]) -> bool {
    let lower = relative
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let segments: Vec<&str> = lower
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments
        .windows(2)
        .any(|pair| pair[0] == ".zero" && (pair[1] == "vault" || pair[1] == "keys"))
    {
        return true;
    }
    for segment in &segments {
        if segment.contains("secret") || segment.contains("token") || segment.contains("credential")
        {
            return true;
        }
        if matches!(*segment, ".env" | "key" | "key.prev") || segment.starts_with("credentials") {
            return true;
        }
    }
    let name = segments.last().copied().unwrap_or_default();
    if name.starts_with(".env")
        || name.ends_with(".enc")
        || name.ends_with(".pem")
        || name.ends_with(".key")
    {
        return true;
    }
    let path = relative.to_string_lossy().replace('\\', "/");
    redactions
        .iter()
        .any(|value| value.chars().count() >= MIN_REDACTION_CHARS && path.contains(value.as_str()))
}

/// Root-relative display path with `/` separators; absolute when outside root.
fn display_path(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let text = relative.to_string_lossy().replace('\\', "/");
    if text.is_empty() {
        ".".to_string()
    } else {
        text
    }
}

fn bundle_path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), ForensicsError> {
    std::fs::write(path, bytes).map_err(|source| ForensicsError::Write {
        path: path.to_path_buf(),
        source,
    })
}

/// Documented non-cryptographic FNV-1a 64. Not collision-resistant; used only
/// to show that two bundle files hold the same bytes.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn hash_hex(bytes: &[u8]) -> String {
    format!("{HASH_ALGORITHM}:{:016x}", fnv1a64(bytes))
}

/// Convenience: a `BTreeMap` of bundle-relative path to bytes, used by tests and
/// by callers that want to inspect a finished bundle without a daemon.
pub fn read_bundle(out_dir: impl AsRef<Path>) -> io::Result<BTreeMap<String, Vec<u8>>> {
    let mut out = BTreeMap::new();
    read_dir_recursive(out_dir.as_ref(), out_dir.as_ref(), &mut out)?;
    Ok(out)
}

fn read_dir_recursive(
    root: &Path,
    dir: &Path,
    out: &mut BTreeMap<String, Vec<u8>>,
) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            read_dir_recursive(root, &path, out)?;
        } else {
            out.insert(
                bundle_path_string(path.strip_prefix(root).unwrap_or(&path)),
                std::fs::read(&path)?,
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn artifact(name: &str, lines: &[&str]) -> Artifact {
        Artifact {
            name: name.to_string(),
            lines: lines.iter().map(|line| (*line).to_string()).collect(),
        }
    }

    fn limits() -> BundleLimits {
        BundleLimits {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            created_at_ms: 1_700_000_000_000,
        }
    }

    fn inputs(root: &Path) -> BundleInputs {
        BundleInputs {
            root: root.to_path_buf(),
            timelines: Vec::new(),
            extra_files: Vec::new(),
            redactions: Vec::new(),
        }
    }

    // -- timeline ---------------------------------------------------------

    #[test]
    fn timeline_orders_dedups_and_counts_malformed_lines() {
        let artifacts = vec![
            artifact(
                "beta",
                &[
                    "200\tworker\tsecond",
                    "200\tworker\tsecond",
                    "not-a-timestamp\tworker\tbroken",
                    "{\"at_ms\":100,\"kind\":\"turn\",\"detail\":\"first\"}",
                    "{\"at_ms\":\"2026-11-25T10:00:00Z\",\"kind\":\"mesh\",\"detail\":\"rfc\"}",
                    "",
                ],
            ),
            artifact("alpha", &["100\tkernel\tthird"]),
        ];

        let timeline = Timeline::from_artifacts(&artifacts);

        assert_eq!(timeline.malformed, 1);
        assert_eq!(timeline.duplicates, 1);
        assert!(!timeline.truncated);
        let keys: Vec<(i64, &str, &str)> = timeline
            .events
            .iter()
            .map(|event| (event.at_ms, event.source.as_str(), event.kind.as_str()))
            .collect();
        assert_eq!(
            keys,
            vec![
                (100, "alpha", "kernel"),
                (100, "beta", "turn"),
                (200, "beta", "worker"),
                (1_795_600_800_000, "beta", "mesh"),
            ]
        );
    }

    #[test]
    fn timeline_accepts_json_actor_and_aliases() {
        let artifacts = vec![artifact(
            "turn",
            &["{\"ts\":1000,\"type\":\"repair\",\"by\":\"doctor\",\"msg\":\"applied\"}"],
        )];
        let timeline = Timeline::from_artifacts(&artifacts);
        assert_eq!(timeline.events.len(), 1);
        let event = &timeline.events[0];
        assert_eq!(event.at_ms, 1000);
        assert_eq!(event.kind, "repair");
        assert_eq!(event.actor.as_deref(), Some("doctor"));
        assert_eq!(event.detail, "applied");
    }

    #[test]
    fn timeline_is_bounded_and_reports_truncation() {
        let lines: Vec<String> = (0..MAX_TIMELINE_EVENTS + 5)
            .map(|index| format!("{index}\tworker\tdetail-{index}"))
            .collect();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();

        let timeline = Timeline::from_artifacts(&[artifact("big", &refs)]);

        assert_eq!(timeline.len(), MAX_TIMELINE_EVENTS);
        assert!(timeline.truncated);
        assert_eq!(timeline.dropped, 5);
        assert_eq!(
            timeline.events.last().map(|event| event.at_ms),
            Some((MAX_TIMELINE_EVENTS - 1) as i64)
        );
    }

    #[test]
    fn redact_text_replaces_caller_values_and_strong_markers() {
        let (text, count) = redact_text(
            "token=sk-abc123 and ghp_xyz789 and AKIAIOSFODNN7EXAMPLE and abcd",
            &["abcd".to_string()],
        );
        assert!(!text.contains("sk-abc123"), "{text}");
        assert!(!text.contains("ghp_xyz789"), "{text}");
        assert!(!text.contains("AKIAIOSFODNN7EXAMPLE"), "{text}");
        assert!(!text.contains("abcd"), "{text}");
        assert_eq!(count, 4);
    }

    #[test]
    fn redact_text_keeps_ordinary_words_and_pem_bodies_hidden() {
        let (text, _) = redact_text("task-list and risk-management are words", &[]);
        assert!(text.contains("task-list"), "{text}");
        assert!(text.contains("risk-management"), "{text}");

        let (pem, count) = redact_text(
            "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\nafter",
            &[],
        );
        assert_eq!(count, 1);
        assert!(!pem.contains("BEGIN"), "{pem}");
        assert!(!pem.contains("MIIEowIBAAKCAQEA"), "{pem}");
        assert!(pem.starts_with("before\n"), "{pem}");
        assert!(pem.ends_with("after"), "{pem}");
    }

    // -- bundle -----------------------------------------------------------

    #[test]
    fn manifest_lists_files_sizes_and_hashes() {
        let dir = dir();
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join(".zero")).unwrap();
        std::fs::write(
            root.join(".zero").join("config.toml"),
            "[core]\nmodel = \"local\"\n",
        )
        .unwrap();
        let out = dir.path().join("bundle");

        let mut bundle_inputs = inputs(&root);
        bundle_inputs.extra_files = vec![PathBuf::from(".zero/config.toml")];
        bundle_inputs.timelines = vec![artifact("turn", &["1\tturn\tstarted"])];
        let report = build_bundle(&bundle_inputs, &out, &limits()).unwrap();

        let manifest_text = std::fs::read_to_string(&report.manifest_path).unwrap();
        let manifest: BundleManifest = serde_json::from_str(&manifest_text).unwrap();
        assert_eq!(manifest.schema_version, BUNDLE_SCHEMA_VERSION);
        assert_eq!(manifest.created_at_ms, 1_700_000_000_000);
        assert_eq!(manifest.network, "none");
        assert!(manifest.offline);
        assert_eq!(manifest.hash_algorithm, HASH_ALGORITHM);
        assert_eq!(manifest.timeline.events, 1);
        assert!(!manifest.truncation.timeline_truncated);
        assert_eq!(manifest.truncation.files_skipped, 0);
        assert_eq!(report.network, "none");

        let timeline = manifest
            .files
            .iter()
            .find(|file| file.path == TIMELINE_FILE)
            .expect("timeline listed");
        assert_eq!(
            timeline.hash,
            hash_hex(&std::fs::read(out.join(TIMELINE_FILE)).unwrap())
        );

        let config = manifest
            .files
            .iter()
            .find(|file| file.path == "files/.zero/config.toml")
            .expect("config listed");
        let config_bytes = std::fs::read(out.join("files/.zero/config.toml")).unwrap();
        assert_eq!(config.bytes, config_bytes.len() as u64);
        assert_eq!(config.hash, hash_hex(&config_bytes));
        assert!(config.hash.starts_with("fnv1a64:"));
        assert_eq!(
            manifest.total_bytes,
            manifest.files.iter().map(|file| file.bytes).sum::<u64>()
        );
    }

    #[test]
    fn injected_secrets_never_appear_in_any_bundle_file() {
        let dir = dir();
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).unwrap();

        let mut body = String::from("api = sk-live-abc123\n");
        body.push_str("git = ghp_abcdef123456\n");
        body.push_str("aws = AKIAIOSFODNN7EXAMPLE\n");
        body.push_str("caller = caller-secret-value\n");
        body.push_str("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n");
        body.push_str("-----END RSA PRIVATE KEY-----\n");
        std::fs::write(root.join("history.txt"), body).unwrap();

        let timeline_line = "1\tturn\tprovider sk-live-abc123".to_string();
        let out = dir.path().join("bundle");
        let mut bundle_inputs = inputs(&root);
        bundle_inputs.extra_files = vec![PathBuf::from("history.txt")];
        bundle_inputs.redactions = vec!["caller-secret-value".to_string(), "xy".to_string()];
        bundle_inputs.timelines = vec![artifact("turn", &[timeline_line.as_str()])];

        let report = build_bundle(&bundle_inputs, &out, &limits()).unwrap();
        assert!(report.redactions >= 4, "{}", report.redactions);

        let secrets = [
            "sk-live-abc123",
            "ghp_abcdef123456",
            "AKIAIOSFODNN7EXAMPLE",
            "caller-secret-value",
            "MIIEowIBAAKCAQEA",
            "-----BEGIN",
            "BEGIN RSA PRIVATE KEY",
        ];
        let files = read_bundle(&out).unwrap();
        assert!(files.contains_key(TIMELINE_FILE));
        assert!(files.contains_key("files/history.txt"));
        assert!(files.len() >= 3);
        for (path, bytes) in &files {
            let text = String::from_utf8_lossy(bytes);
            for secret in secrets {
                assert!(
                    !text.contains(secret),
                    "bundle file {path} still contains {secret}"
                );
            }
        }
        // The redacted copy is still readable evidence, not an empty file.
        let history = String::from_utf8(files["files/history.txt"].clone()).unwrap();
        assert!(history.contains(REDACTED), "{history}");
        assert!(history.contains("api ="), "{history}");
    }

    #[test]
    fn vault_key_credential_and_env_paths_are_excluded() {
        let dir = dir();
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join(".zero").join("vault")).unwrap();
        std::fs::create_dir_all(root.join(".zero").join("keys")).unwrap();
        for (path, body) in [
            (".zero/vault/data.json", "vault-data"),
            (".zero/keys/k1", "key-material"),
            (".zero/key", "key-material"),
            (".env", "TOKEN=abcdef"),
            ("credentials.json", "{}"),
            ("bundle.enc", "enc"),
            ("server.pem", "pem"),
            ("private.key", "key"),
            ("api-token.txt", "token"),
            ("tokenizer-notes.txt", "ok"),
            ("client-report.txt", "caller-declared path value"),
            ("notes.txt", "ok"),
        ] {
            std::fs::write(root.join(path), body).unwrap();
        }

        let out = dir.path().join("bundle");
        let mut bundle_inputs = inputs(&root);
        bundle_inputs.extra_files = vec![
            PathBuf::from(".zero/vault/data.json"),
            PathBuf::from(".zero/keys/k1"),
            PathBuf::from(".zero/key"),
            PathBuf::from(".env"),
            PathBuf::from("credentials.json"),
            PathBuf::from("bundle.enc"),
            PathBuf::from("server.pem"),
            PathBuf::from("private.key"),
            PathBuf::from("api-token.txt"),
            PathBuf::from("tokenizer-notes.txt"),
            PathBuf::from("client-report.txt"),
            PathBuf::from("notes.txt"),
        ];
        bundle_inputs.redactions = vec!["client-report".to_string()];
        let report = build_bundle(&bundle_inputs, &out, &limits()).unwrap();

        let paths: Vec<&str> = report.files.iter().map(|file| file.path.as_str()).collect();
        assert_eq!(paths, vec!["files/notes.txt", TIMELINE_FILE]);
        assert_eq!(report.truncation.files_skipped, 11);
        assert!(report
            .skipped
            .iter()
            .all(|skip| skip.reason == SkipReason::ExcludedPath));
        let manifest = std::fs::read_to_string(&report.manifest_path).unwrap();
        assert!(!manifest.contains("client-report"), "{manifest}");

        for (path, bytes) in read_bundle(&out).unwrap() {
            let text = String::from_utf8_lossy(&bytes);
            for leaked in ["vault-data", "key-material", "TOKEN=abcdef"] {
                assert!(!text.contains(leaked), "{path} contains {leaked}");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_outside_the_root_is_excluded() {
        use std::os::unix::fs::symlink;

        let dir = dir();
        let root = dir.path().join("root");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), "outside-secret").unwrap();
        std::fs::write(root.join("inside.txt"), "inside").unwrap();
        symlink(outside.join("secret.txt"), root.join("link.txt")).unwrap();
        symlink(&outside, root.join("linkdir")).unwrap();

        let out = dir.path().join("bundle");
        let mut bundle_inputs = inputs(&root);
        bundle_inputs.extra_files = vec![
            PathBuf::from("link.txt"),
            PathBuf::from("linkdir/secret.txt"),
            PathBuf::from("inside.txt"),
        ];
        let report = build_bundle(&bundle_inputs, &out, &limits()).unwrap();

        let paths: Vec<&str> = report.files.iter().map(|file| file.path.as_str()).collect();
        assert!(paths.contains(&"files/inside.txt"));
        assert!(!paths.iter().any(|path| path.contains("link")));
        assert!(report
            .skipped
            .iter()
            .any(|skip| skip.path == "link.txt" && skip.reason == SkipReason::Symlink));
        assert!(report
            .skipped
            .iter()
            .any(|skip| skip.reason == SkipReason::OutsideRoot));

        for bytes in read_bundle(&out).unwrap().values() {
            assert!(!String::from_utf8_lossy(bytes).contains("outside-secret"));
        }
    }

    #[test]
    fn per_file_and_total_caps_skip_and_report() {
        let dir = dir();
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("big.txt"), "x".repeat(4096)).unwrap();
        std::fs::write(root.join("small.txt"), "y".repeat(64)).unwrap();

        let out = dir.path().join("bundle");
        let mut bundle_inputs = inputs(&root);
        bundle_inputs.extra_files = vec![PathBuf::from("big.txt"), PathBuf::from("small.txt")];
        let mut caps = limits();
        caps.max_file_bytes = 1024;
        caps.max_total_bytes = 32;

        let report = build_bundle(&bundle_inputs, &out, &caps).unwrap();

        assert!(report.truncation.total_capped);
        assert_eq!(report.truncation.files_skipped, 2);
        assert!(report
            .skipped
            .iter()
            .any(|skip| skip.path == "big.txt" && skip.reason == SkipReason::Oversize));
        assert!(report
            .skipped
            .iter()
            .any(|skip| skip.path == "small.txt" && skip.reason == SkipReason::TotalLimit));
        assert!(report.files.iter().all(|file| file.path == TIMELINE_FILE));
        assert!(!out.join("files").exists());
    }

    #[test]
    fn binary_files_are_dropped_instead_of_copied() {
        let dir = dir();
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("blob.bin"), [0xff_u8, 0x00, 0x01, 0x02]).unwrap();

        let out = dir.path().join("bundle");
        let mut bundle_inputs = inputs(&root);
        bundle_inputs.extra_files = vec![PathBuf::from("blob.bin")];
        let report = build_bundle(&bundle_inputs, &out, &limits()).unwrap();

        assert_eq!(report.truncation.files_skipped, 1);
        assert_eq!(report.skipped[0].reason, SkipReason::Binary);
        assert!(!report
            .files
            .iter()
            .any(|file| file.path == "files/blob.bin"));
    }

    #[test]
    fn the_same_inputs_and_clock_produce_the_same_bundle() {
        let dir = dir();
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a.log"), "line sk-abc123\n").unwrap();
        std::fs::write(root.join("b.log"), "plain\n").unwrap();

        let mut bundle_inputs = inputs(&root);
        bundle_inputs.extra_files = vec![
            PathBuf::from("b.log"),
            PathBuf::from("a.log"),
            PathBuf::from("a.log"),
        ];
        bundle_inputs.timelines = vec![artifact("turn", &["2\tturn\tsecond", "1\tturn\tfirst"])];

        let out_a = dir.path().join("a");
        let out_b = dir.path().join("b");
        let first = build_bundle(&bundle_inputs, &out_a, &limits()).unwrap();
        let second = build_bundle(&bundle_inputs, &out_b, &limits()).unwrap();

        assert_eq!(first.files, second.files);
        assert_eq!(first.skipped, second.skipped);
        assert_eq!(first.redactions, second.redactions);
        assert_eq!(
            std::fs::read(out_a.join(MANIFEST_FILE)).unwrap(),
            std::fs::read(out_b.join(MANIFEST_FILE)).unwrap()
        );
        assert_eq!(read_bundle(&out_a).unwrap(), read_bundle(&out_b).unwrap());
        assert!(first
            .skipped
            .iter()
            .any(|skip| skip.reason == SkipReason::Duplicate));
    }

    #[test]
    fn a_missing_root_is_an_error_and_writes_nothing() {
        let dir = dir();
        let root = dir.path().join("absent");
        let out = dir.path().join("bundle");
        let bundle_inputs = inputs(&root);

        let error = build_bundle(&bundle_inputs, &out, &limits()).unwrap_err();
        assert!(matches!(error, ForensicsError::Root { .. }));
        assert!(!out.join(MANIFEST_FILE).exists());
    }
}
