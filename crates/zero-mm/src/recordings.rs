//! T-MM-05 verification and recordings: labeled shots, chapters, assertions,
//! shortcut flags, and project-local artifacts.
//!
//! A recording is a deterministic value: [`build`] turns a sequence of
//! [`FlowEvent`]s into a [`Recording`] with stable shot and assertion ids, and
//! [`Recording::validate`] enforces the structural bounds. Assertions are
//! evaluated by comparing their expected and actual JSON values; one failing
//! assertion never aborts the recording, it only makes [`verify`] report the
//! flow as failed.
//!
//! [`write_artifacts`] publishes a directory containing `manifest.json`,
//! `report.md`, and every labeled shot as `shots/<path-safe>.png`. A failing
//! flow still produces every artifact, plus a `FAILURES.md` file and an exit
//! summary naming the failing assertion ids (MM-05, MM-08, MM-09).
//!
//! Shot bytes are opaque PNG payloads in this slice: there is no image codec,
//! no screenshot capture, and no network access. [`LabeledShot::content_hash`]
//! is the BLAKE3 digest supplied by `zero_store::BlobId`, so a later verifier
//! can tell whether a stored artifact still matches the recording.

use std::borrow::Borrow;
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zero_store::BlobId;
use zero_types::{ErrorCode, Result, ZeroError};

/// Version of the manifest and recording schema this module writes.
pub const RECORDING_SCHEMA_VERSION: u32 = 1;
/// Manifest file name inside an artifact directory.
pub const MANIFEST_FILE: &str = "manifest.json";
/// Human-readable report file name inside an artifact directory.
pub const REPORT_FILE: &str = "report.md";
/// Failure report file name, written only when verification fails.
pub const FAILURES_FILE: &str = "FAILURES.md";
/// Shot directory name inside an artifact directory.
pub const SHOTS_DIR: &str = "shots";

/// Maximum characters in a flow name.
pub const MAX_FLOW_NAME_CHARS: usize = 256;
/// Maximum characters in a recording id.
pub const MAX_RECORDING_ID_CHARS: usize = 128;
/// Maximum characters in a chapter title.
pub const MAX_TITLE_CHARS: usize = 256;
/// Maximum characters in a shot label.
pub const MAX_LABEL_CHARS: usize = 256;
/// Maximum characters in a shot or assertion id.
pub const MAX_SHOT_ID_CHARS: usize = 128;
/// Maximum characters in a chapter note.
pub const MAX_NOTE_CHARS: usize = 4_096;
/// Maximum characters in an assertion description.
pub const MAX_ASSERTION_DESC_CHARS: usize = 4_096;
/// Maximum characters in a shortcut key.
pub const MAX_SHORTCUT_KEY_CHARS: usize = 64;
/// Maximum characters in a shortcut description.
pub const MAX_SHORTCUT_DESC_CHARS: usize = 1_024;
/// Maximum chapters in one recording.
pub const MAX_CHAPTERS: usize = 128;
/// Maximum shots in one recording across all chapters.
pub const MAX_SHOTS: usize = 1_024;
/// Maximum shots in one chapter.
pub const MAX_SHOTS_PER_CHAPTER: usize = 256;
/// Maximum notes in one chapter.
pub const MAX_NOTES_PER_CHAPTER: usize = 256;
/// Maximum assertions in one recording.
pub const MAX_ASSERTIONS: usize = 4_096;
/// Maximum shortcut flags in one recording.
pub const MAX_SHORTCUT_FLAGS: usize = 128;
/// Largest accepted shot width or height, in pixels.
pub const MAX_SHOT_EDGE: u32 = 16_384;
/// Byte cap for one PNG shot.
pub const MAX_SHOT_BYTES: u64 = 32 * 1024 * 1024;
/// Byte cap across every PNG shot in one recording.
pub const MAX_TOTAL_SHOT_BYTES: u64 = 512 * 1024 * 1024;
/// Character cap for the rendered report or failure file.
pub const MAX_REPORT_BYTES: u64 = 64 * 1024 * 1024;

static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/// One labeled screenshot in a chapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabeledShot {
    pub id: String,
    pub label: String,
    /// Opaque PNG payload. This module never decodes it.
    pub bytes_png: Vec<u8>,
    pub at_ms: u64,
    pub width: u32,
    pub height: u32,
}

impl LabeledShot {
    /// BLAKE3 hex digest of the PNG payload, so a later verifier can compare
    /// the stored artifact with the recording.
    pub fn content_hash(&self) -> String {
        BlobId::of(&self.bytes_png).to_hex()
    }

    fn validate_with(&self, limits: &ArtifactLimits) -> Result<()> {
        validate_id(&self.id, "shot id", MAX_SHOT_ID_CHARS)?;
        validate_text(&self.label, "shot label", MAX_LABEL_CHARS)?;
        if self.width == 0 || self.height == 0 {
            return Err(invalid(format!("shot `{}` has a zero dimension", self.id)));
        }
        if self.width > MAX_SHOT_EDGE || self.height > MAX_SHOT_EDGE {
            return Err(limit(format!(
                "shot `{}` is {}x{}; the largest accepted edge is {MAX_SHOT_EDGE}",
                self.id, self.width, self.height
            )));
        }
        if self.bytes_png.is_empty() {
            return Err(invalid(format!("shot `{}` has no PNG bytes", self.id)));
        }
        if self.bytes_png.len() as u64 > limits.max_shot_bytes {
            return Err(limit(format!(
                "shot `{}` is {} bytes; the cap is {}",
                self.id,
                self.bytes_png.len(),
                limits.max_shot_bytes
            )));
        }
        Ok(())
    }
}

/// A chapter of a recording: a title, a start time, labeled shots, and notes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chapter {
    pub title: String,
    pub start_ms: u64,
    pub shots: Vec<LabeledShot>,
    pub notes: Vec<String>,
}

/// One pass/fail assertion. `passed` is derived from `expected == actual` by
/// [`build`]; [`verify`] re-evaluates the comparison so a tampered flag fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assertion {
    pub id: String,
    pub description: String,
    pub expected: Value,
    pub actual: Value,
    pub passed: bool,
}

impl Assertion {
    /// Whether this assertion is true: the stored flag agrees and the values
    /// are equal.
    pub fn holds(&self) -> bool {
        self.passed && self.expected == self.actual
    }
}

/// A shortcut the flow took, flagged so a reader can see what was skipped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShortcutFlag {
    pub key: String,
    pub description: String,
    pub enabled: bool,
}

/// A complete recording. Chapters are ordered by start time, shots within a
/// chapter by time, and ids are unique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recording {
    pub schema_version: u32,
    pub id: String,
    pub flow_name: String,
    pub created_ms: u64,
    pub chapters: Vec<Chapter>,
    pub assertions: Vec<Assertion>,
    pub shortcut_flags: Vec<ShortcutFlag>,
}

impl Recording {
    /// Validate under the default [`ArtifactLimits`].
    pub fn validate(&self) -> Result<()> {
        self.validate_with(&ArtifactLimits::default())
    }

    /// Validate the structure and every bound in `limits`.
    pub fn validate_with(&self, limits: &ArtifactLimits) -> Result<()> {
        if self.schema_version != RECORDING_SCHEMA_VERSION {
            return Err(ZeroError::new(
                ErrorCode::SchemaVersion,
                format!(
                    "recording schema {} is not supported; this build writes and reads {}",
                    self.schema_version, RECORDING_SCHEMA_VERSION
                ),
            ));
        }
        validate_id(&self.id, "recording id", MAX_RECORDING_ID_CHARS)?;
        validate_text(&self.flow_name, "flow name", MAX_FLOW_NAME_CHARS)?;

        if self.chapters.is_empty() {
            return Err(invalid("a recording needs at least one chapter"));
        }
        if self.chapters.len() > limits.max_chapters {
            return Err(limit(format!(
                "recording has {} chapters; the cap is {}",
                self.chapters.len(),
                limits.max_chapters
            )));
        }

        let mut shot_ids: BTreeSet<String> = BTreeSet::new();
        let mut shot_count = 0usize;
        let mut total_shot_bytes = 0u64;
        let mut previous_chapter_start: Option<u64> = None;

        for (index, chapter) in self.chapters.iter().enumerate() {
            validate_text(&chapter.title, "chapter title", MAX_TITLE_CHARS)?;
            if let Some(previous) = previous_chapter_start {
                if chapter.start_ms < previous {
                    return Err(invalid(format!(
                        "chapter {} starts at {} ms, before the previous chapter at {previous} ms",
                        index + 1,
                        chapter.start_ms
                    )));
                }
            }
            previous_chapter_start = Some(chapter.start_ms);

            if chapter.shots.len() > limits.max_shots_per_chapter {
                return Err(limit(format!(
                    "chapter `{}` has {} shots; the cap is {}",
                    chapter.title,
                    chapter.shots.len(),
                    limits.max_shots_per_chapter
                )));
            }
            if chapter.notes.len() > MAX_NOTES_PER_CHAPTER {
                return Err(limit(format!(
                    "chapter `{}` has {} notes; the cap is {MAX_NOTES_PER_CHAPTER}",
                    chapter.title,
                    chapter.notes.len()
                )));
            }
            for note in &chapter.notes {
                validate_text(note, "chapter note", MAX_NOTE_CHARS)?;
            }

            let mut previous_shot_at: Option<u64> = None;
            for shot in &chapter.shots {
                shot.validate_with(limits)?;
                if !shot_ids.insert(shot.id.clone()) {
                    return Err(invalid(format!("shot id `{}` is not unique", shot.id)));
                }
                if let Some(previous) = previous_shot_at {
                    if shot.at_ms < previous {
                        return Err(invalid(format!(
                            "shot `{}` is at {} ms, before the previous shot at {previous} ms",
                            shot.id, shot.at_ms
                        )));
                    }
                }
                if shot.at_ms < chapter.start_ms {
                    return Err(invalid(format!(
                        "shot `{}` is at {} ms, before its chapter starts at {} ms",
                        shot.id, shot.at_ms, chapter.start_ms
                    )));
                }
                previous_shot_at = Some(shot.at_ms);
                shot_count += 1;
                total_shot_bytes = total_shot_bytes
                    .checked_add(shot.bytes_png.len() as u64)
                    .ok_or_else(|| limit("shot bytes overflowed"))?;
                if total_shot_bytes > limits.max_total_shot_bytes {
                    return Err(limit(format!(
                        "recording has {total_shot_bytes} shot bytes; the cap is {}",
                        limits.max_total_shot_bytes
                    )));
                }
            }
        }

        if shot_count > limits.max_shots {
            return Err(limit(format!(
                "recording has {shot_count} shots; the cap is {}",
                limits.max_shots
            )));
        }

        validate_assertions(&self.assertions, limits.max_assertions)?;
        validate_shortcut_flags(&self.shortcut_flags, limits.max_shortcut_flags)?;
        Ok(())
    }
}

/// Bounds applied while validating and writing artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactLimits {
    pub max_chapters: usize,
    pub max_shots: usize,
    pub max_shots_per_chapter: usize,
    pub max_shot_bytes: u64,
    pub max_total_shot_bytes: u64,
    pub max_assertions: usize,
    pub max_shortcut_flags: usize,
    pub max_report_bytes: u64,
}

impl Default for ArtifactLimits {
    fn default() -> Self {
        Self {
            max_chapters: MAX_CHAPTERS,
            max_shots: MAX_SHOTS,
            max_shots_per_chapter: MAX_SHOTS_PER_CHAPTER,
            max_shot_bytes: MAX_SHOT_BYTES,
            max_total_shot_bytes: MAX_TOTAL_SHOT_BYTES,
            max_assertions: MAX_ASSERTIONS,
            max_shortcut_flags: MAX_SHORTCUT_FLAGS,
            max_report_bytes: MAX_REPORT_BYTES,
        }
    }
}

/// The result of checking a recording's assertions, labels, and chapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verification {
    pub passed: bool,
    pub failed_assertions: Vec<String>,
    /// Empty chapters and shots with a missing label or payload, by id.
    pub missing_shots: Vec<String>,
}

impl Verification {
    /// One deterministic line naming every failing assertion id.
    pub fn exit_summary(&self) -> String {
        if self.passed {
            return "PASS".to_string();
        }
        let mut parts = Vec::new();
        if !self.failed_assertions.is_empty() {
            parts.push(format!(
                "failing assertions: {}",
                self.failed_assertions.join(", ")
            ));
        }
        if !self.missing_shots.is_empty() {
            parts.push(format!("missing shots: {}", self.missing_shots.join(", ")));
        }
        if parts.is_empty() {
            "FAIL".to_string()
        } else {
            format!("FAIL ({})", parts.join("; "))
        }
    }
}

// ---------------------------------------------------------------------------
// Flow builder
// ---------------------------------------------------------------------------

/// One event in a recorded flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowEvent {
    /// Set the current time in milliseconds. Time must not go backwards.
    At(u64),
    /// Start a new chapter at the current time.
    Chapter(String),
    /// Capture a labeled shot at the current time.
    Shot {
        label: String,
        bytes: Vec<u8>,
        w: u32,
        h: u32,
    },
    /// Record an assertion; `passed` is derived from `expected == actual`.
    Assert {
        description: String,
        expected: Value,
        actual: Value,
    },
    /// Flag a shortcut the flow took.
    Shortcut {
        key: String,
        description: String,
        enabled: bool,
    },
    /// Attach a note to the current chapter.
    Note(String),
}

/// Build a recording from events.
///
/// Shot ids are `shot-0001`, assertion ids are `assert-0001`, and chapter and
/// shot order follows the events. A shot or note before the first
/// [`FlowEvent::Chapter`] opens an implicit `Intro` chapter so that a partial
/// flow still produces a valid (if incomplete) recording. `created_ms` is the
/// greatest time seen in an [`FlowEvent::At`], which keeps the value
/// deterministic; this function never reads a clock.
///
/// A failing assertion is recorded with `passed = false` and does not return an
/// error. Structural violations (empty flow name, backwards time, an empty
/// event list, or a bound) are errors.
pub fn build(flow_name: &str, events: &[FlowEvent]) -> Result<Recording> {
    validate_text(flow_name, "flow name", MAX_FLOW_NAME_CHARS)?;

    let mut chapters: Vec<Chapter> = Vec::new();
    let mut assertions: Vec<Assertion> = Vec::new();
    let mut shortcut_flags: Vec<ShortcutFlag> = Vec::new();
    let mut current_ms = 0u64;
    let mut created_ms = 0u64;
    let mut shot_count = 0usize;

    for event in events {
        match event {
            FlowEvent::At(ms) => {
                if *ms < current_ms {
                    return Err(invalid(format!(
                        "flow time goes backwards: {ms} ms after {current_ms} ms"
                    )));
                }
                current_ms = *ms;
                created_ms = created_ms.max(*ms);
            }
            FlowEvent::Chapter(title) => {
                validate_text(title, "chapter title", MAX_TITLE_CHARS)?;
                chapters.push(Chapter {
                    title: title.clone(),
                    start_ms: current_ms,
                    shots: Vec::new(),
                    notes: Vec::new(),
                });
            }
            FlowEvent::Shot { label, bytes, w, h } => {
                validate_text(label, "shot label", MAX_LABEL_CHARS)?;
                if bytes.is_empty() {
                    return Err(invalid("a shot needs PNG bytes"));
                }
                if *w == 0 || *h == 0 {
                    return Err(invalid("shot dimensions must be positive"));
                }
                if chapters.is_empty() {
                    chapters.push(Chapter {
                        title: "Intro".to_string(),
                        start_ms: current_ms,
                        shots: Vec::new(),
                        notes: Vec::new(),
                    });
                }
                shot_count += 1;
                chapters
                    .last_mut()
                    .expect("a chapter was just opened")
                    .shots
                    .push(LabeledShot {
                        id: format!("shot-{shot_count:04}"),
                        label: label.clone(),
                        bytes_png: bytes.clone(),
                        at_ms: current_ms,
                        width: *w,
                        height: *h,
                    });
            }
            FlowEvent::Assert {
                description,
                expected,
                actual,
            } => {
                validate_text(
                    description,
                    "assertion description",
                    MAX_ASSERTION_DESC_CHARS,
                )?;
                assertions.push(Assertion {
                    id: format!("assert-{:04}", assertions.len() + 1),
                    description: description.clone(),
                    expected: expected.clone(),
                    actual: actual.clone(),
                    passed: expected == actual,
                });
            }
            FlowEvent::Shortcut {
                key,
                description,
                enabled,
            } => {
                validate_key(key, "shortcut key", MAX_SHORTCUT_KEY_CHARS)?;
                validate_text(description, "shortcut description", MAX_SHORTCUT_DESC_CHARS)?;
                shortcut_flags.push(ShortcutFlag {
                    key: key.clone(),
                    description: description.clone(),
                    enabled: *enabled,
                });
            }
            FlowEvent::Note(text) => {
                validate_text(text, "chapter note", MAX_NOTE_CHARS)?;
                if chapters.is_empty() {
                    chapters.push(Chapter {
                        title: "Intro".to_string(),
                        start_ms: current_ms,
                        shots: Vec::new(),
                        notes: Vec::new(),
                    });
                }
                chapters
                    .last_mut()
                    .expect("a chapter was just opened")
                    .notes
                    .push(text.clone());
            }
        }
    }

    let recording = Recording {
        schema_version: RECORDING_SCHEMA_VERSION,
        id: recording_id(
            flow_name,
            created_ms,
            &chapters,
            &assertions,
            &shortcut_flags,
        ),
        flow_name: flow_name.to_string(),
        created_ms,
        chapters,
        assertions,
        shortcut_flags,
    };
    recording.validate()?;
    Ok(recording)
}

/// Check every assertion, every label, and every chapter.
///
/// Each assertion is evaluated from `expected == actual` (not just the stored
/// flag), so a tampered `passed` value is still reported. A chapter with no
/// shots and a shot with an empty label or payload are reported in
/// [`Verification::missing_shots`]. A recording with no chapters cannot pass.
pub fn verify(recording: &Recording) -> Verification {
    let mut failed_assertions = Vec::new();
    for assertion in &recording.assertions {
        if !assertion.holds() {
            failed_assertions.push(assertion.id.clone());
        }
    }

    let mut missing_shots = Vec::new();
    if recording.chapters.is_empty() {
        missing_shots.push("(no chapters)".to_string());
    }
    for (index, chapter) in recording.chapters.iter().enumerate() {
        if chapter.shots.is_empty() {
            missing_shots.push(format!("chapter-{:04}", index + 1));
        }
        for shot in &chapter.shots {
            if shot.label.trim().is_empty()
                || shot.label.chars().any(char::is_control)
                || shot.bytes_png.is_empty()
            {
                missing_shots.push(shot.id.clone());
            }
        }
    }

    let passed = failed_assertions.is_empty() && missing_shots.is_empty();
    Verification {
        passed,
        failed_assertions,
        missing_shots,
    }
}

// ---------------------------------------------------------------------------
// Artifacts
// ---------------------------------------------------------------------------

/// A shot as recorded in `manifest.json`; the payload lives in `file`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestShot {
    pub id: String,
    pub label: String,
    pub at_ms: u64,
    pub width: u32,
    pub height: u32,
    pub bytes: u64,
    pub content_hash: String,
    /// Portable path such as `shots/ch01-shot001-label-0123456789ab.png`.
    pub file: String,
}

/// A chapter as recorded in `manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestChapter {
    pub title: String,
    pub start_ms: u64,
    pub notes: Vec<String>,
    pub shots: Vec<ManifestShot>,
}

/// The artifact manifest. It mirrors the recording without embedding PNG
/// payloads, and carries the [`Verification`] snapshot for later checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub id: String,
    pub flow_name: String,
    pub created_ms: u64,
    pub chapters: Vec<ManifestChapter>,
    pub assertions: Vec<Assertion>,
    pub shortcut_flags: Vec<ShortcutFlag>,
    pub shots_total: u64,
    pub bytes_total: u64,
    pub verification: Verification,
}

impl Manifest {
    /// Validate the manifest's structure, paths, and totals.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != RECORDING_SCHEMA_VERSION {
            return Err(ZeroError::new(
                ErrorCode::SchemaVersion,
                format!(
                    "manifest schema {} is not supported; this build reads {}",
                    self.schema_version, RECORDING_SCHEMA_VERSION
                ),
            ));
        }
        validate_id(&self.id, "recording id", MAX_RECORDING_ID_CHARS)?;
        validate_text(&self.flow_name, "flow name", MAX_FLOW_NAME_CHARS)?;
        if self.chapters.is_empty() {
            return Err(invalid("a manifest needs at least one chapter"));
        }
        if self.chapters.len() > MAX_CHAPTERS {
            return Err(limit(format!(
                "manifest has {} chapters; the cap is {MAX_CHAPTERS}",
                self.chapters.len()
            )));
        }
        if self.shots_total > MAX_SHOTS as u64 {
            return Err(limit(format!(
                "manifest says {} shots; the cap is {MAX_SHOTS}",
                self.shots_total
            )));
        }
        if self.bytes_total > MAX_TOTAL_SHOT_BYTES {
            return Err(limit(format!(
                "manifest says {} shot bytes; the cap is {MAX_TOTAL_SHOT_BYTES}",
                self.bytes_total
            )));
        }

        let mut shot_ids: BTreeSet<String> = BTreeSet::new();
        let mut shot_files: BTreeSet<&str> = BTreeSet::new();
        let mut shots_total = 0u64;
        let mut bytes_total = 0u64;
        let mut previous_chapter_start: Option<u64> = None;
        for chapter in &self.chapters {
            validate_text(&chapter.title, "chapter title", MAX_TITLE_CHARS)?;
            if let Some(previous) = previous_chapter_start {
                if chapter.start_ms < previous {
                    return Err(invalid(format!(
                        "manifest chapter `{}` starts before the previous chapter",
                        chapter.title
                    )));
                }
            }
            previous_chapter_start = Some(chapter.start_ms);
            if chapter.shots.len() > MAX_SHOTS_PER_CHAPTER {
                return Err(limit(format!(
                    "manifest chapter `{}` has {} shots; the cap is {MAX_SHOTS_PER_CHAPTER}",
                    chapter.title,
                    chapter.shots.len()
                )));
            }
            if chapter.notes.len() > MAX_NOTES_PER_CHAPTER {
                return Err(limit(format!(
                    "manifest chapter `{}` has {} notes; the cap is {MAX_NOTES_PER_CHAPTER}",
                    chapter.title,
                    chapter.notes.len()
                )));
            }
            for note in &chapter.notes {
                validate_text(note, "chapter note", MAX_NOTE_CHARS)?;
            }
            for shot in &chapter.shots {
                validate_id(&shot.id, "shot id", MAX_SHOT_ID_CHARS)?;
                validate_text(&shot.label, "shot label", MAX_LABEL_CHARS)?;
                if !shot_ids.insert(shot.id.clone()) {
                    return Err(invalid(format!("shot id `{}` is not unique", shot.id)));
                }
                if !shot_files.insert(shot.file.as_str()) {
                    return Err(invalid(format!("shot file `{}` is not unique", shot.file)));
                }
                if shot.width == 0
                    || shot.height == 0
                    || shot.width > MAX_SHOT_EDGE
                    || shot.height > MAX_SHOT_EDGE
                {
                    return Err(invalid(format!(
                        "shot `{}` has an invalid {}x{} size",
                        shot.id, shot.width, shot.height
                    )));
                }
                if !is_portable_shot_path(&shot.file) {
                    return Err(invalid(format!(
                        "shot `{}` has an unsafe artifact path `{}`",
                        shot.id, shot.file
                    )));
                }
                if BlobId::parse(&shot.content_hash).is_err() {
                    return Err(invalid(format!(
                        "shot `{}` has a malformed content hash",
                        shot.id
                    )));
                }
                if shot.bytes == 0 || shot.bytes > MAX_SHOT_BYTES {
                    return Err(limit(format!(
                        "shot `{}` records {} bytes; the cap is {MAX_SHOT_BYTES}",
                        shot.id, shot.bytes
                    )));
                }
                shots_total += 1;
                bytes_total = bytes_total
                    .checked_add(shot.bytes)
                    .ok_or_else(|| limit("manifest shot bytes overflowed"))?;
            }
        }
        if shots_total != self.shots_total {
            return Err(invalid(format!(
                "manifest says {} shots but lists {shots_total}",
                self.shots_total
            )));
        }
        if bytes_total != self.bytes_total {
            return Err(invalid(format!(
                "manifest says {} shot bytes but lists {bytes_total}",
                self.bytes_total
            )));
        }
        if bytes_total > MAX_TOTAL_SHOT_BYTES {
            return Err(limit(format!(
                "manifest shot bytes {bytes_total} exceed the cap {MAX_TOTAL_SHOT_BYTES}"
            )));
        }
        validate_assertions(&self.assertions, MAX_ASSERTIONS)?;
        validate_shortcut_flags(&self.shortcut_flags, MAX_SHORTCUT_FLAGS)?;
        Ok(())
    }
}

/// Paths and the parsed manifest produced by [`write_artifacts`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactBundle {
    pub dir: PathBuf,
    pub manifest: Manifest,
    pub report_md: PathBuf,
}

/// Write `manifest.json`, `report.md`, `shots/*.png`, and, for a failing flow,
/// `FAILURES.md` into a new directory and publish it atomically.
///
/// The directory is assembled in a hidden sibling staging directory and then
/// renamed into place, so a partially written bundle is never exposed as
/// `out_dir`. An existing `out_dir` is [`ErrorCode::AlreadyExists`] and is left
/// untouched. Filesystem I/O is local; no network call is made.
pub fn write_artifacts(
    recording: &Recording,
    out_dir: impl AsRef<Path>,
    limits: impl Borrow<ArtifactLimits>,
) -> Result<ArtifactBundle> {
    let limits = limits.borrow();
    recording.validate_with(limits)?;

    let out_dir = out_dir.as_ref();
    if out_dir.as_os_str().is_empty() {
        return Err(invalid("artifact directory cannot be empty"));
    }
    if out_dir.exists() {
        return Err(ZeroError::new(
            ErrorCode::AlreadyExists,
            format!(
                "artifact directory `{}` already exists; pick a new path",
                out_dir.display()
            ),
        ));
    }

    let verification = verify(recording);
    let shot_files = shot_file_names(recording);
    let manifest = manifest_for(recording, &shot_files, &verification);
    manifest.validate()?;
    let report = render_report(recording, &manifest);
    if report.len() as u64 > limits.max_report_bytes {
        return Err(limit(format!(
            "report is {} bytes; the cap is {}",
            report.len(),
            limits.max_report_bytes
        )));
    }
    let failures = if verification.passed {
        None
    } else {
        let text = render_failures(recording, &verification);
        if text.len() as u64 > limits.max_report_bytes {
            return Err(limit(format!(
                "failure report is {} bytes; the cap is {}",
                text.len(),
                limits.max_report_bytes
            )));
        }
        Some(text)
    };
    let manifest_json = format!("{}\n", serde_json::to_string_pretty(&manifest)?);

    let parent = out_dir
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let staging = staging_dir(parent);
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }

    let written = (|| -> Result<()> {
        fs::create_dir_all(staging.join(SHOTS_DIR))?;
        for (chapter_index, chapter) in recording.chapters.iter().enumerate() {
            for (shot_index, shot) in chapter.shots.iter().enumerate() {
                let relative = &shot_files[chapter_index][shot_index];
                let name = relative
                    .strip_prefix(&format!("{SHOTS_DIR}/"))
                    .ok_or_else(|| invalid("internal shot path is malformed"))?;
                fs::write(staging.join(SHOTS_DIR).join(name), &shot.bytes_png)?;
            }
        }
        fs::write(staging.join(REPORT_FILE), report.as_bytes())?;
        if let Some(failures) = &failures {
            fs::write(staging.join(FAILURES_FILE), failures.as_bytes())?;
        }
        fs::write(staging.join(MANIFEST_FILE), manifest_json.as_bytes())?;
        fs::rename(&staging, out_dir)?;
        Ok(())
    })();

    if let Err(error) = written {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }

    Ok(ArtifactBundle {
        dir: out_dir.to_path_buf(),
        manifest,
        report_md: out_dir.join(REPORT_FILE),
    })
}

/// Read and validate `manifest.json` from an artifact directory.
///
/// This checks the schema version, the structure, the portable shot paths, and
/// the recorded totals. It does not re-hash the shot files; use
/// [`LabeledShot::content_hash`] when the recording itself is available.
pub fn read_manifest(out_dir: impl AsRef<Path>) -> Result<Manifest> {
    let path = out_dir.as_ref().join(MANIFEST_FILE);
    let bytes = fs::read(&path).map_err(|error| {
        let code = if error.kind() == std::io::ErrorKind::NotFound {
            ErrorCode::NotFound
        } else {
            ErrorCode::Io
        };
        ZeroError::new(code, format!("cannot read `{}`: {error}", path.display()))
    })?;
    if bytes.len() as u64 > MAX_REPORT_BYTES {
        return Err(limit(format!(
            "manifest `{}` is {} bytes; the cap is {MAX_REPORT_BYTES}",
            path.display(),
            bytes.len()
        )));
    }
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    manifest.validate()?;
    Ok(manifest)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validate_text(value: &str, label: &str, max: usize) -> Result<()> {
    if value.trim().is_empty() {
        return Err(invalid(format!("{label} cannot be empty")));
    }
    if value.chars().count() > max {
        return Err(limit(format!(
            "{label} is {} characters; the cap is {max}",
            value.chars().count()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid(format!("{label} contains a control character")));
    }
    Ok(())
}

fn validate_id(value: &str, label: &str, max: usize) -> Result<()> {
    validate_text(value, label, max)?;
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(invalid(format!(
            "{label} `{value}` may only use ASCII letters, digits, `.`, `_`, and `-`"
        )));
    }
    Ok(())
}

fn validate_key(value: &str, label: &str, max: usize) -> Result<()> {
    validate_text(value, label, max)?;
    if value.chars().any(char::is_whitespace) {
        return Err(invalid(format!(
            "{label} `{value}` cannot contain whitespace"
        )));
    }
    Ok(())
}

fn validate_assertions(assertions: &[Assertion], max: usize) -> Result<()> {
    if assertions.len() > max {
        return Err(limit(format!(
            "recording has {} assertions; the cap is {max}",
            assertions.len()
        )));
    }
    let mut ids: BTreeSet<&str> = BTreeSet::new();
    for assertion in assertions {
        validate_id(&assertion.id, "assertion id", MAX_SHOT_ID_CHARS)?;
        validate_text(
            &assertion.description,
            "assertion description",
            MAX_ASSERTION_DESC_CHARS,
        )?;
        if !ids.insert(assertion.id.as_str()) {
            return Err(invalid(format!(
                "assertion id `{}` is not unique",
                assertion.id
            )));
        }
    }
    Ok(())
}

fn validate_shortcut_flags(flags: &[ShortcutFlag], max: usize) -> Result<()> {
    if flags.len() > max {
        return Err(limit(format!(
            "recording has {} shortcut flags; the cap is {max}",
            flags.len()
        )));
    }
    let mut keys: BTreeSet<&str> = BTreeSet::new();
    for flag in flags {
        validate_key(&flag.key, "shortcut key", MAX_SHORTCUT_KEY_CHARS)?;
        validate_text(
            &flag.description,
            "shortcut description",
            MAX_SHORTCUT_DESC_CHARS,
        )?;
        if !keys.insert(flag.key.as_str()) {
            return Err(invalid(format!(
                "shortcut key `{}` is not unique",
                flag.key
            )));
        }
    }
    Ok(())
}

fn recording_id(
    flow_name: &str,
    created_ms: u64,
    chapters: &[Chapter],
    assertions: &[Assertion],
    shortcut_flags: &[ShortcutFlag],
) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    feed(&mut hash, flow_name, &created_ms.to_string());
    for chapter in chapters {
        feed(&mut hash, &chapter.title, &chapter.start_ms.to_string());
        for note in &chapter.notes {
            feed(&mut hash, note, "");
        }
        for shot in &chapter.shots {
            feed(&mut hash, &shot.id, &shot.label);
            feed(&mut hash, &shot.at_ms.to_string(), &shot.content_hash());
            feed(
                &mut hash,
                &format!("{}x{}", shot.width, shot.height),
                &shot.bytes_png.len().to_string(),
            );
        }
    }
    for assertion in assertions {
        feed(&mut hash, &assertion.id, &assertion.description);
        feed(
            &mut hash,
            &assertion.expected.to_string(),
            &assertion.actual.to_string(),
        );
    }
    for flag in shortcut_flags {
        feed(&mut hash, &flag.key, &flag.description);
        feed(&mut hash, if flag.enabled { "1" } else { "0" }, "");
    }
    format!("rec-{hash:016x}")
}

fn feed(hash: &mut u64, left: &str, right: &str) {
    for bytes in [left.as_bytes(), b"\0", right.as_bytes(), b"\0"] {
        for &byte in bytes {
            *hash ^= u64::from(byte);
            *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
}

fn shot_file_names(recording: &Recording) -> Vec<Vec<String>> {
    recording
        .chapters
        .iter()
        .enumerate()
        .map(|(chapter_index, chapter)| {
            chapter
                .shots
                .iter()
                .enumerate()
                .map(|(shot_index, shot)| {
                    format!(
                        "{SHOTS_DIR}/{}",
                        shot_file_name(chapter_index, shot_index, shot)
                    )
                })
                .collect()
        })
        .collect()
}

fn shot_file_name(chapter_index: usize, shot_index: usize, shot: &LabeledShot) -> String {
    let hash = shot.content_hash();
    format!(
        "ch{:02}-shot{:03}-{}-{}.png",
        chapter_index + 1,
        shot_index + 1,
        slugify(&shot.label),
        &hash[..12]
    )
}

fn slugify(label: &str) -> String {
    let mut slug = String::new();
    let mut last_dash = false;
    for character in label.chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            slug.push('-');
            last_dash = true;
        }
        if slug.len() >= 24 {
            break;
        }
    }
    let trimmed = slug.trim_matches('-');
    if trimmed.is_empty() {
        "shot".to_string()
    } else {
        trimmed.to_string()
    }
}

fn staging_dir(parent: &Path) -> PathBuf {
    let count = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(
        ".zero-recording-{}-{count}.partial",
        std::process::id()
    ))
}

fn manifest_for(
    recording: &Recording,
    shot_files: &[Vec<String>],
    verification: &Verification,
) -> Manifest {
    let mut shots_total = 0u64;
    let mut bytes_total = 0u64;
    let chapters = recording
        .chapters
        .iter()
        .enumerate()
        .map(|(chapter_index, chapter)| ManifestChapter {
            title: chapter.title.clone(),
            start_ms: chapter.start_ms,
            notes: chapter.notes.clone(),
            shots: chapter
                .shots
                .iter()
                .enumerate()
                .map(|(shot_index, shot)| {
                    shots_total += 1;
                    bytes_total += shot.bytes_png.len() as u64;
                    ManifestShot {
                        id: shot.id.clone(),
                        label: shot.label.clone(),
                        at_ms: shot.at_ms,
                        width: shot.width,
                        height: shot.height,
                        bytes: shot.bytes_png.len() as u64,
                        content_hash: shot.content_hash(),
                        file: shot_files[chapter_index][shot_index].clone(),
                    }
                })
                .collect(),
        })
        .collect();

    Manifest {
        schema_version: recording.schema_version,
        id: recording.id.clone(),
        flow_name: recording.flow_name.clone(),
        created_ms: recording.created_ms,
        chapters,
        assertions: recording.assertions.clone(),
        shortcut_flags: recording.shortcut_flags.clone(),
        shots_total,
        bytes_total,
        verification: verification.clone(),
    }
}

fn render_report(recording: &Recording, manifest: &Manifest) -> String {
    let mut out = String::new();
    let passed_assertions = recording
        .assertions
        .iter()
        .filter(|assertion| assertion.holds())
        .count();
    let failed_assertions = recording.assertions.len() - passed_assertions;
    let enabled_shortcuts = recording
        .shortcut_flags
        .iter()
        .filter(|flag| flag.enabled)
        .count();

    line(
        &mut out,
        format_args!("# Recording: {}", recording.flow_name),
    );
    line(&mut out, format_args!(""));
    line(
        &mut out,
        format_args!("- schema version: {}", manifest.schema_version),
    );
    line(&mut out, format_args!("- recording id: {}", recording.id));
    line(
        &mut out,
        format_args!("- created: {} ms", recording.created_ms),
    );
    line(
        &mut out,
        format_args!("- chapters: {}", recording.chapters.len()),
    );
    line(&mut out, format_args!("- shots: {}", manifest.shots_total));
    line(
        &mut out,
        format_args!(
            "- assertions: {} ({passed_assertions} passed, {failed_assertions} failed)",
            recording.assertions.len()
        ),
    );
    line(
        &mut out,
        format_args!(
            "- shortcut flags: {} ({enabled_shortcuts} enabled, {} disabled)",
            recording.shortcut_flags.len(),
            recording.shortcut_flags.len() - enabled_shortcuts
        ),
    );
    line(
        &mut out,
        format_args!(
            "- result: {}",
            if manifest.verification.passed {
                "PASS"
            } else {
                "FAIL"
            }
        ),
    );
    line(&mut out, format_args!(""));

    line(&mut out, format_args!("## Chapters"));
    line(&mut out, format_args!(""));
    for (chapter_index, chapter) in manifest.chapters.iter().enumerate() {
        line(
            &mut out,
            format_args!(
                "### {}. {} ({} ms)",
                chapter_index + 1,
                chapter.title,
                chapter.start_ms
            ),
        );
        line(&mut out, format_args!(""));
        if chapter.notes.is_empty() {
            line(&mut out, format_args!("_No notes._"));
        } else {
            line(&mut out, format_args!("Notes:"));
            for note in &chapter.notes {
                line(&mut out, format_args!("- {}", md_cell(note)));
            }
        }
        line(&mut out, format_args!(""));
        if chapter.shots.is_empty() {
            line(&mut out, format_args!("_No shots in this chapter._"));
        } else {
            line(
                &mut out,
                format_args!("| # | label | id | at (ms) | size | bytes | content hash | file |"),
            );
            line(&mut out, format_args!("|---|---|---|---|---|---|---|---|"));
            for (shot_index, shot) in chapter.shots.iter().enumerate() {
                line(
                    &mut out,
                    format_args!(
                        "| {} | {} | {} | {} | {}x{} | {} | `{}` | `{}` |",
                        shot_index + 1,
                        md_cell(&shot.label),
                        shot.id,
                        shot.at_ms,
                        shot.width,
                        shot.height,
                        shot.bytes,
                        shot.content_hash,
                        shot.file
                    ),
                );
            }
        }
        line(&mut out, format_args!(""));
    }

    line(&mut out, format_args!("## Assertions"));
    line(&mut out, format_args!(""));
    if manifest.assertions.is_empty() {
        line(&mut out, format_args!("_No assertions._"));
    } else {
        line(
            &mut out,
            format_args!("| id | description | expected | actual | result |"),
        );
        line(&mut out, format_args!("|---|---|---|---|---|"));
        for assertion in &manifest.assertions {
            line(
                &mut out,
                format_args!(
                    "| {} | {} | {} | {} | {} |",
                    assertion.id,
                    md_cell(&assertion.description),
                    json_cell(&assertion.expected),
                    json_cell(&assertion.actual),
                    if assertion.holds() { "pass" } else { "fail" }
                ),
            );
        }
    }
    line(&mut out, format_args!(""));

    line(&mut out, format_args!("## Shortcut flags"));
    line(&mut out, format_args!(""));
    if manifest.shortcut_flags.is_empty() {
        line(&mut out, format_args!("_No shortcut flags._"));
    } else {
        line(&mut out, format_args!("| key | description | enabled |"));
        line(&mut out, format_args!("|---|---|---|"));
        for flag in &manifest.shortcut_flags {
            line(
                &mut out,
                format_args!(
                    "| {} | {} | {} |",
                    md_cell(&flag.key),
                    md_cell(&flag.description),
                    if flag.enabled { "yes" } else { "no" }
                ),
            );
        }
    }
    line(&mut out, format_args!(""));

    line(&mut out, format_args!("## Failures"));
    line(&mut out, format_args!(""));
    if manifest.verification.passed {
        line(&mut out, format_args!("None."));
    } else {
        for assertion in manifest
            .assertions
            .iter()
            .filter(|assertion| !assertion.holds())
        {
            line(
                &mut out,
                format_args!(
                    "- {}: expected {}, got {}",
                    assertion.id,
                    json_cell(&assertion.expected),
                    json_cell(&assertion.actual)
                ),
            );
        }
        for missing in &manifest.verification.missing_shots {
            line(&mut out, format_args!("- missing shot: {missing}"));
        }
    }
    line(
        &mut out,
        format_args!("Exit summary: {}", manifest.verification.exit_summary()),
    );
    line(&mut out, format_args!(""));
    out
}

fn render_failures(recording: &Recording, verification: &Verification) -> String {
    let mut out = String::new();
    line(
        &mut out,
        format_args!("# Failures: {}", recording.flow_name),
    );
    line(&mut out, format_args!(""));
    line(&mut out, format_args!("- recording id: {}", recording.id));
    line(
        &mut out,
        format_args!("- created: {} ms", recording.created_ms),
    );
    line(
        &mut out,
        format_args!("- exit summary: {}", verification.exit_summary()),
    );
    line(&mut out, format_args!(""));

    line(&mut out, format_args!("## Failed assertions"));
    line(&mut out, format_args!(""));
    if verification.failed_assertions.is_empty() {
        line(&mut out, format_args!("None."));
    } else {
        line(
            &mut out,
            format_args!("| id | description | expected | actual |"),
        );
        line(&mut out, format_args!("|---|---|---|---|"));
        for assertion in recording
            .assertions
            .iter()
            .filter(|assertion| !assertion.holds())
        {
            line(
                &mut out,
                format_args!(
                    "| {} | {} | {} | {} |",
                    assertion.id,
                    md_cell(&assertion.description),
                    json_cell(&assertion.expected),
                    json_cell(&assertion.actual)
                ),
            );
        }
    }
    line(&mut out, format_args!(""));

    line(&mut out, format_args!("## Missing shots"));
    line(&mut out, format_args!(""));
    if verification.missing_shots.is_empty() {
        line(&mut out, format_args!("None."));
    } else {
        for missing in &verification.missing_shots {
            line(&mut out, format_args!("- {missing}"));
        }
    }
    line(&mut out, format_args!(""));
    out
}

fn line(out: &mut String, args: fmt::Arguments<'_>) {
    use std::fmt::Write as _;
    writeln!(out, "{args}").expect("writing to a String cannot fail");
}

fn md_cell(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace(['\r', '\n'], " ")
}

fn json_cell(value: &Value) -> String {
    md_cell(&value.to_string())
}

fn is_portable_shot_path(file: &str) -> bool {
    let Some(name) = file.strip_prefix("shots/") else {
        return false;
    };
    !name.is_empty()
        && name.ends_with(".png")
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
        && !is_reserved_windows_name(name)
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

fn is_reserved_windows_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit())
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn limit(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;
    use tempfile::TempDir;

    fn temp_out() -> (TempDir, PathBuf) {
        let temp = tempfile::tempdir().expect("tempdir");
        let out = temp.path().join("bundle");
        (temp, out)
    }

    fn passing_events() -> Vec<FlowEvent> {
        vec![
            FlowEvent::At(0),
            FlowEvent::Chapter("Start".to_string()),
            FlowEvent::Note("Opened the app".to_string()),
            FlowEvent::Shot {
                label: "Home screen".to_string(),
                bytes: b"\x89PNG home".to_vec(),
                w: 1_280,
                h: 720,
            },
            FlowEvent::Assert {
                description: "window title".to_string(),
                expected: json!("Zero"),
                actual: json!("Zero"),
            },
            FlowEvent::Shortcut {
                key: "Ctrl+S".to_string(),
                description: "saved without a dialog".to_string(),
                enabled: true,
            },
            FlowEvent::At(250),
            FlowEvent::Chapter("Finish".to_string()),
            FlowEvent::Shot {
                label: "Saved dialog".to_string(),
                bytes: b"\x89PNG saved".to_vec(),
                w: 800,
                h: 600,
            },
            FlowEvent::Assert {
                description: "dialog visible".to_string(),
                expected: json!(true),
                actual: json!(true),
            },
        ]
    }

    #[test]
    fn passing_flow_writes_every_artifact_and_reports_pass() {
        let (_temp, out) = temp_out();
        let recording = build("save flow", &passing_events()).expect("build");
        assert_eq!(recording.created_ms, 250);
        assert_eq!(recording.chapters.len(), 2);
        assert_eq!(recording.chapters[0].shots.len(), 1);
        assert_eq!(recording.chapters[0].notes.len(), 1);
        assert_eq!(recording.chapters[0].shots[0].content_hash().len(), 64);
        assert_eq!(
            recording.chapters[0].shots[0].content_hash(),
            BlobId::of(b"\x89PNG home").to_hex()
        );

        let verification = verify(&recording);
        assert!(verification.passed, "{verification:?}");
        assert!(verification.failed_assertions.is_empty());
        assert!(verification.missing_shots.is_empty());

        let bundle =
            write_artifacts(&recording, &out, ArtifactLimits::default()).expect("write artifacts");
        assert!(out.is_dir());
        assert!(bundle.dir.join(MANIFEST_FILE).is_file());
        assert!(bundle.report_md.is_file());
        assert!(!out.join(FAILURES_FILE).exists());
        assert_eq!(
            fs::read_dir(out.join(SHOTS_DIR))
                .expect("shots dir")
                .count(),
            2
        );

        let report = fs::read_to_string(&bundle.report_md).expect("report");
        assert!(report.contains("- result: PASS"), "{report}");
        assert!(report.contains("Exit summary: PASS"));
        assert!(report.contains("Home screen"));
        assert!(report.contains("Saved dialog"));
        assert!(report.contains("window title"));
        assert!(report.contains("Ctrl+S"));
        assert!(!report.contains("Exit summary: FAIL"));

        let manifest = read_manifest(&out).expect("read manifest");
        assert_eq!(manifest, bundle.manifest);
        assert_eq!(manifest.shots_total, 2);
        assert_eq!(manifest.bytes_total, 19);
        assert!(manifest.verification.passed);
        assert_eq!(manifest.chapters.len(), 2);
        assert_eq!(manifest.assertions.len(), 2);
        assert!(manifest.assertions.iter().all(Assertion::holds));

        let first = &manifest.chapters[0].shots[0];
        assert_eq!(
            fs::read(out.join(&first.file)).expect("shot file"),
            b"\x89PNG home"
        );
        assert_eq!(
            first.content_hash,
            recording.chapters[0].shots[0].content_hash()
        );
    }

    #[test]
    fn failing_flow_writes_every_artifact_and_names_the_failures() {
        let (_temp, out) = temp_out();
        let events = vec![
            FlowEvent::At(0),
            FlowEvent::Chapter("Checkout".to_string()),
            FlowEvent::Shot {
                label: "Cart".to_string(),
                bytes: b"\x89PNG cart".to_vec(),
                w: 640,
                h: 480,
            },
            FlowEvent::Assert {
                description: "total matches".to_string(),
                expected: json!(10),
                actual: json!(12),
            },
            FlowEvent::Assert {
                description: "button present".to_string(),
                expected: json!("Pay"),
                actual: json!("Pay"),
            },
        ];

        let recording = build("checkout", &events).expect("build does not abort");
        assert_eq!(recording.assertions.len(), 2);
        let failing_id = recording.assertions[0].id.clone();
        let passing_id = recording.assertions[1].id.clone();
        assert!(!recording.assertions[0].passed);

        let verification = verify(&recording);
        assert!(!verification.passed);
        assert_eq!(verification.failed_assertions, vec![failing_id.clone()]);
        assert!(verification.missing_shots.is_empty());
        assert!(verification.exit_summary().contains(&failing_id));

        let bundle =
            write_artifacts(&recording, &out, ArtifactLimits::default()).expect("write artifacts");
        assert!(out.join(MANIFEST_FILE).is_file());
        assert!(out.join(REPORT_FILE).is_file());
        assert!(out.join(FAILURES_FILE).is_file());
        assert_eq!(
            fs::read_dir(out.join(SHOTS_DIR))
                .expect("shots dir")
                .count(),
            1
        );

        let report = fs::read_to_string(&bundle.report_md).expect("report");
        assert!(report.contains("- result: FAIL"), "{report}");
        assert!(report.contains("Exit summary: FAIL"));
        assert!(report.contains(&failing_id));
        assert!(!report.contains(&format!("{passing_id}: expected")));

        let failures = fs::read_to_string(out.join(FAILURES_FILE)).expect("failures");
        assert!(failures.contains(&failing_id));
        assert!(failures.contains("total matches"));
        assert!(failures.contains("- exit summary: FAIL"));

        let manifest = read_manifest(&out).expect("read manifest");
        assert!(!manifest.verification.passed);
        assert_eq!(manifest.verification.failed_assertions, vec![failing_id]);
        assert!(manifest.assertions[1].holds());

        let mut tampered = recording.clone();
        tampered.assertions[0].passed = true;
        assert_eq!(
            verify(&tampered).failed_assertions,
            vec![tampered.assertions[0].id.clone()],
            "verify re-evaluates the values, not just the stored flag"
        );
    }

    #[test]
    fn ids_and_chapter_times_are_unique_and_monotonic() {
        let recording = build(
            "ids",
            &[
                FlowEvent::At(10),
                FlowEvent::Chapter("First".to_string()),
                FlowEvent::Shot {
                    label: "same label".to_string(),
                    bytes: b"one".to_vec(),
                    w: 1,
                    h: 1,
                },
                FlowEvent::Shot {
                    label: "same label".to_string(),
                    bytes: b"two".to_vec(),
                    w: 1,
                    h: 1,
                },
                FlowEvent::At(20),
                FlowEvent::Chapter("Second".to_string()),
                FlowEvent::Shot {
                    label: "third".to_string(),
                    bytes: b"three".to_vec(),
                    w: 1,
                    h: 1,
                },
                FlowEvent::Assert {
                    description: "true".to_string(),
                    expected: json!(1),
                    actual: json!(1),
                },
            ],
        )
        .expect("build");
        assert!(recording.validate().is_ok());

        let shot_ids: BTreeSet<&str> = recording
            .chapters
            .iter()
            .flat_map(|chapter| chapter.shots.iter().map(|shot| shot.id.as_str()))
            .collect();
        assert_eq!(shot_ids.len(), 3);
        assert_eq!(recording.chapters[0].shots[0].id, "shot-0001");
        assert_eq!(recording.chapters[1].shots[0].id, "shot-0003");
        assert_eq!(recording.assertions[0].id, "assert-0001");

        let mut duplicate_shot = recording.clone();
        duplicate_shot.chapters[0].shots[1].id = duplicate_shot.chapters[0].shots[0].id.clone();
        assert_eq!(
            duplicate_shot
                .validate()
                .expect_err("duplicate shot id")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut duplicate_assertion = recording.clone();
        duplicate_assertion
            .assertions
            .push(duplicate_assertion.assertions[0].clone());
        assert_eq!(
            duplicate_assertion
                .validate()
                .expect_err("duplicate assertion id")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut backwards = recording.clone();
        backwards.chapters[1].start_ms = 5;
        assert!(backwards.validate().is_err());

        let mut unordered_shot = recording.clone();
        unordered_shot.chapters[0].shots[1].at_ms = 1;
        assert!(unordered_shot.validate().is_err());
    }

    #[test]
    fn empty_and_unstructured_recordings_are_rejected() {
        assert!(build("empty", &[]).is_err());
        assert!(build("", &[FlowEvent::Chapter("A".to_string())]).is_err());
        assert!(build(
            "bad label",
            &[
                FlowEvent::At(0),
                FlowEvent::Chapter("A".to_string()),
                FlowEvent::Shot {
                    label: "  ".to_string(),
                    bytes: b"x".to_vec(),
                    w: 1,
                    h: 1,
                },
            ]
        )
        .is_err());
        assert!(build(
            "control label",
            &[
                FlowEvent::At(0),
                FlowEvent::Chapter("A".to_string()),
                FlowEvent::Shot {
                    label: "bad\nlabel".to_string(),
                    bytes: b"x".to_vec(),
                    w: 1,
                    h: 1,
                },
            ]
        )
        .is_err());
        assert!(build("backwards", &[FlowEvent::At(10), FlowEvent::At(5)]).is_err());

        let empty_chapter = build(
            "chapter only",
            &[FlowEvent::At(0), FlowEvent::Chapter("Only".to_string())],
        )
        .expect("structure is valid");
        let verification = verify(&empty_chapter);
        assert!(!verification.passed);
        assert_eq!(verification.missing_shots, vec!["chapter-0001".to_string()]);

        let mut no_chapters = empty_chapter;
        no_chapters.chapters.clear();
        assert_eq!(
            no_chapters.validate().expect_err("no chapters").code(),
            ErrorCode::InvalidInput
        );
        assert!(!verify(&no_chapters).passed);
    }

    #[test]
    fn shot_size_and_count_caps_are_enforced() {
        let recording = build(
            "caps",
            &[
                FlowEvent::At(0),
                FlowEvent::Chapter("A".to_string()),
                FlowEvent::Shot {
                    label: "one".to_string(),
                    bytes: b"0123456789".to_vec(),
                    w: 1,
                    h: 1,
                },
                FlowEvent::Shot {
                    label: "two".to_string(),
                    bytes: b"abcdefghij".to_vec(),
                    w: 1,
                    h: 1,
                },
            ],
        )
        .expect("build");

        let (temp, _) = temp_out();

        let too_many = temp.path().join("too-many");
        let limits = ArtifactLimits {
            max_shots: 1,
            ..ArtifactLimits::default()
        };
        let error = write_artifacts(&recording, &too_many, limits).expect_err("shot count cap");
        assert_eq!(error.code(), ErrorCode::LimitExceeded);
        assert!(!too_many.exists());

        let per_chapter = temp.path().join("per-chapter");
        let limits = ArtifactLimits {
            max_shots_per_chapter: 1,
            ..ArtifactLimits::default()
        };
        let error = write_artifacts(&recording, &per_chapter, limits).expect_err("per-chapter cap");
        assert_eq!(error.code(), ErrorCode::LimitExceeded);

        let too_big = temp.path().join("too-big");
        let limits = ArtifactLimits {
            max_shot_bytes: 4,
            ..ArtifactLimits::default()
        };
        let error = write_artifacts(&recording, &too_big, limits).expect_err("shot byte cap");
        assert_eq!(error.code(), ErrorCode::LimitExceeded);

        let total = temp.path().join("total");
        let limits = ArtifactLimits {
            max_total_shot_bytes: 15,
            ..ArtifactLimits::default()
        };
        let error = write_artifacts(&recording, &total, limits).expect_err("total byte cap");
        assert_eq!(error.code(), ErrorCode::LimitExceeded);
        assert!(!total.exists());
    }

    #[test]
    fn shot_file_names_are_path_safe() {
        let labels = [
            "../../etc/passwd",
            "a/b\\c:d",
            "CON",
            "登录 屏幕",
            "normal-shot",
        ];
        let mut events = vec![FlowEvent::At(0), FlowEvent::Chapter("Paths".to_string())];
        for label in labels {
            events.push(FlowEvent::Shot {
                label: label.to_string(),
                bytes: label.as_bytes().to_vec(),
                w: 1,
                h: 1,
            });
        }

        let recording = build("paths", &events).expect("build");
        let (_temp, out) = temp_out();
        let bundle = write_artifacts(&recording, &out, ArtifactLimits::default()).expect("write");

        let mut names = BTreeSet::new();
        for chapter in &bundle.manifest.chapters {
            for shot in &chapter.shots {
                let name = shot
                    .file
                    .strip_prefix("shots/")
                    .expect("shots prefix")
                    .to_string();
                assert!(!name.contains('/'), "{name}");
                assert!(!name.contains('\\'), "{name}");
                assert!(!name.contains(".."), "{name}");
                assert!(name.ends_with(".png"), "{name}");
                assert!(
                    name.chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-')),
                    "{name} is not portable"
                );
                assert!(out.join(&shot.file).is_file(), "{}", shot.file);
                assert!(names.insert(name), "shot file names must be unique");
            }
        }
        assert_eq!(names.len(), labels.len());
    }

    #[test]
    fn manifest_round_trips_and_is_deterministic() {
        let (temp, _) = temp_out();
        let recording = build("determinism", &passing_events()).expect("build");
        let first = temp.path().join("first");
        let second = temp.path().join("second");

        let first_bundle =
            write_artifacts(&recording, &first, ArtifactLimits::default()).expect("first write");
        let second_bundle =
            write_artifacts(&recording, &second, ArtifactLimits::default()).expect("second write");

        assert_eq!(first_bundle.manifest, second_bundle.manifest);
        assert_eq!(
            fs::read(first.join(MANIFEST_FILE)).expect("first manifest"),
            fs::read(second.join(MANIFEST_FILE)).expect("second manifest")
        );
        assert_eq!(
            read_manifest(&first).expect("read manifest"),
            first_bundle.manifest
        );

        let manifest_path = first.join(MANIFEST_FILE);
        let mut tampered: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).expect("manifest bytes"))
                .expect("manifest json");
        tampered["chapters"][0]["shots"][0]["file"] = json!("shots/../escape.png");
        fs::write(
            &manifest_path,
            serde_json::to_vec(&tampered).expect("tampered json"),
        )
        .expect("write tampered manifest");
        assert_eq!(
            read_manifest(&first)
                .expect_err("unsafe manifest path")
                .code(),
            ErrorCode::InvalidInput
        );

        let missing = temp.path().join("missing");
        assert_eq!(
            read_manifest(&missing)
                .expect_err("missing manifest")
                .code(),
            ErrorCode::NotFound
        );

        let existing = temp.path().join("existing");
        fs::create_dir(&existing).expect("create existing");
        assert_eq!(
            write_artifacts(&recording, &existing, ArtifactLimits::default())
                .expect_err("existing directory")
                .code(),
            ErrorCode::AlreadyExists
        );
    }

    #[test]
    fn no_network_code_path_exists() {
        let source = include_str!("recordings.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("recordings.rs has a production half");
        for needle in [
            "std::net",
            "TcpStream",
            "UdpSocket",
            "reqwest",
            "hyper",
            "ureq",
            "isahc",
            "curl",
            "Command::new",
            "fn fetch",
            "fn download",
        ] {
            assert!(
                !production.contains(needle),
                "`{needle}` must not appear in the recordings module; it never fetches or runs a process"
            );
        }
    }
}
