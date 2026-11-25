//! MM-01 inputs: attachments, `@` references, typed blocks, and accounting.
//!
//! Every input route — inline prompt text, pasted or dropped attachments, a
//! local path, a URL, or an `@` reference — is normalised into an
//! [`InputMessage`] of typed [`ContentBlock`]s. Attachments are validated
//! against one [`AttachmentStore`] policy: a MIME type that matches the
//! modality, a per-modality byte cap, an absolute path inside an allowed root,
//! or an `http(s)` URL without userinfo. [`account`] then sums per-modality
//! usage without inventing dimensions it does not know.
//!
//! `@` references are resolved through the injected [`AttachmentStore`].
//! `@file:` and `@image:` read a local file (the store records the canonical
//! path and the real byte length); `@url:` records a URL without any network
//! access; a bare `@name` selects an attachment by its [`Attachment::name`].
//! An unresolvable reference is [`ErrorCode::NotFound`] and its message lists
//! the candidates; an ambiguous name is [`ErrorCode::InvalidInput`] and lists
//! the candidate ids.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, Result, ZeroError};

/// Maximum characters in one text block.
pub const MAX_TEXT_CHARS: usize = 32_768;
/// Maximum characters in a tool-result summary.
pub const MAX_SUMMARY_CHARS: usize = 4_096;
/// Maximum characters in an image alt text.
pub const MAX_ALT_CHARS: usize = 1_024;
/// Maximum characters in an attachment id or tool-use id.
pub const MAX_ID_CHARS: usize = 128;
/// Maximum characters in a bare `@name`.
pub const MAX_NAME_CHARS: usize = 256;
/// Byte cap for a text attachment.
pub const MAX_TEXT_BYTES: u64 = 8 * 1024 * 1024;
/// Byte cap for an image attachment.
pub const MAX_IMAGE_BYTES: u64 = 20 * 1024 * 1024;
/// Byte cap for an audio attachment.
pub const MAX_AUDIO_BYTES: u64 = 200 * 1024 * 1024;
/// Byte cap for a video attachment.
pub const MAX_VIDEO_BYTES: u64 = 1024 * 1024 * 1024;
/// Byte cap for a document attachment.
pub const MAX_DOCUMENT_BYTES: u64 = 64 * 1024 * 1024;

const MAX_CANDIDATES: usize = 8;

/// The five modalities MM-01 accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Modality {
    Text,
    Image,
    Audio,
    Video,
    Document,
}

impl Modality {
    /// Every modality in deterministic order.
    pub const ALL: [Modality; 5] = [
        Modality::Text,
        Modality::Image,
        Modality::Audio,
        Modality::Video,
        Modality::Document,
    ];

    /// Stable lowercase name used in JSON and error messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            Modality::Text => "text",
            Modality::Image => "image",
            Modality::Audio => "audio",
            Modality::Video => "video",
            Modality::Document => "document",
        }
    }

    /// The byte cap for one attachment of this modality.
    pub const fn byte_cap(self) -> u64 {
        match self {
            Modality::Text => MAX_TEXT_BYTES,
            Modality::Image => MAX_IMAGE_BYTES,
            Modality::Audio => MAX_AUDIO_BYTES,
            Modality::Video => MAX_VIDEO_BYTES,
            Modality::Document => MAX_DOCUMENT_BYTES,
        }
    }
}

impl fmt::Display for Modality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where the attachment bytes live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Source {
    /// Standard padded base64 carried in the message.
    Inline { bytes_b64: String },
    /// An absolute local path. It must sit inside an allowed store root.
    Path { path: PathBuf },
    /// An `http(s)` URL. The attachment is recorded, never fetched here.
    Url { url: String },
}

/// One typed input attachment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    pub id: String,
    pub kind: Modality,
    pub source: Source,
    pub mime: String,
    /// Declared size in bytes. `0` on a URL means the size is unknown.
    pub bytes: u64,
    pub name: Option<String>,
}

impl Attachment {
    /// Validate the attachment against a set of allowed filesystem roots.
    ///
    /// Path checks are lexical (absolute, no `..`, inside a root). The store
    /// canonicalises again when it reads a file, which also catches symlink
    /// escapes. URL checks never touch the network.
    pub fn validate(&self, roots: &[PathBuf]) -> Result<()> {
        validate_id(&self.id, "attachment id")?;
        let essence = validate_mime(&self.mime)?;
        if !mime_matches(self.kind, &essence) {
            return Err(invalid(format!(
                "mime `{}` is not valid for a {} attachment",
                self.mime,
                self.kind.as_str()
            )));
        }
        if let Some(name) = &self.name {
            validate_name(name)?;
        }

        let cap = self.kind.byte_cap();
        match &self.source {
            Source::Inline { bytes_b64 } => {
                // Reject an obviously oversized payload before allocating it.
                if bytes_b64.len() as u64 > cap.saturating_mul(4) / 3 + 4 {
                    return Err(limit(format!(
                        "inline attachment `{}` is larger than the {} byte cap",
                        self.id, cap
                    )));
                }
                let decoded = decode_base64(bytes_b64)?;
                if decoded.len() as u64 > cap {
                    return Err(limit(format!(
                        "inline attachment `{}` is {} bytes; the {} cap is {}",
                        self.id,
                        decoded.len(),
                        self.kind.as_str(),
                        cap
                    )));
                }
                if decoded.len() as u64 != self.bytes {
                    return Err(invalid(format!(
                        "inline attachment `{}` declares {} bytes but decodes to {}",
                        self.id,
                        self.bytes,
                        decoded.len()
                    )));
                }
            }
            Source::Path { path } => {
                if self.bytes > cap {
                    return Err(limit(format!(
                        "attachment `{}` is {} bytes; the {} cap is {}",
                        self.id,
                        self.bytes,
                        self.kind.as_str(),
                        cap
                    )));
                }
                validate_path(path, roots)?;
            }
            Source::Url { url } => {
                if self.bytes > cap {
                    return Err(limit(format!(
                        "attachment `{}` is {} bytes; the {} cap is {}",
                        self.id,
                        self.bytes,
                        self.kind.as_str(),
                        cap
                    )));
                }
                validate_http_url(url)?;
            }
        }
        Ok(())
    }
}

/// An injected resolver for `@` references and the attachments already known
/// to the turn.
#[derive(Debug, Clone)]
pub struct AttachmentStore {
    roots: Vec<PathBuf>,
    entries: Vec<Attachment>,
}

impl AttachmentStore {
    /// Create a store. At least one absolute allowed root is required, and
    /// every root must exist; roots are canonicalised once here so lexical
    /// checks compare real paths rather than 8.3 short names.
    pub fn new(roots: Vec<PathBuf>) -> Result<Self> {
        if roots.is_empty() {
            return Err(invalid(
                "an attachment store needs at least one allowed root",
            ));
        }
        let mut normalised = Vec::with_capacity(roots.len());
        for root in roots {
            if !root.is_absolute() {
                return Err(invalid(format!(
                    "allowed root `{}` must be absolute",
                    root.display()
                )));
            }
            let canonical = fs::canonicalize(&root).map_err(|error| {
                ZeroError::new(
                    ErrorCode::NotFound,
                    format!(
                        "allowed root `{}` is not accessible: {error}",
                        root.display()
                    ),
                )
            })?;
            if !canonical.is_dir() {
                return Err(invalid(format!(
                    "allowed root `{}` is not a directory",
                    root.display()
                )));
            }
            normalised.push(canonical);
        }
        Ok(Self {
            roots: normalised,
            entries: Vec::new(),
        })
    }

    /// The allowed roots, normalised.
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// The attachments already inserted into the store.
    pub fn entries(&self) -> &[Attachment] {
        &self.entries
    }

    /// Look up an attachment by id.
    pub fn get(&self, id: &str) -> Option<&Attachment> {
        self.entries.iter().find(|entry| entry.id == id)
    }

    /// Validate and insert an attachment. Re-inserting an identical attachment
    /// is a no-op; a conflicting id is rejected.
    pub fn insert(&mut self, attachment: Attachment) -> Result<()> {
        attachment.validate(&self.roots)?;
        if let Some(existing) = self.get(&attachment.id) {
            if existing == &attachment {
                return Ok(());
            }
            return Err(invalid(format!(
                "attachment id `{}` is already taken by a different attachment",
                attachment.id
            )));
        }
        self.entries.push(attachment);
        Ok(())
    }

    /// Resolve one parsed reference.
    pub fn resolve(&self, reference: &Reference<'_>) -> Result<Attachment> {
        match reference.kind {
            ReferenceKind::File => self.open_path(Path::new(reference.target), None),
            ReferenceKind::Image => {
                self.open_path(Path::new(reference.target), Some(Modality::Image))
            }
            ReferenceKind::Url => url_attachment(reference.target),
            ReferenceKind::Name => self.resolve_name(reference.target),
        }
    }

    /// Resolve a bare `@name` against the store only.
    pub fn resolve_name(&self, name: &str) -> Result<Attachment> {
        resolve_name(name, &[], self)
    }

    /// Open a local file relative to the allowed roots, or an absolute path
    /// inside one, and build a validated attachment from its real length.
    pub fn open_path(&self, path: &Path, forced: Option<Modality>) -> Result<Attachment> {
        let mut candidates = Vec::new();
        if path.is_absolute() {
            let normalised = normalize_lexical(path)?;
            match fs::canonicalize(&normalised) {
                Ok(canonical) => {
                    if !self.roots.iter().any(|root| is_within(&canonical, root)) {
                        return Err(denied(format!(
                            "path `{}` is outside the allowed roots",
                            path.display()
                        )));
                    }
                    candidates.push(canonical);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    candidates.push(normalised);
                }
                Err(error) => return Err(error.into()),
            }
        } else {
            for root in &self.roots {
                candidates.push(root.join(path));
            }
        }

        let mut found = Vec::new();
        for candidate in candidates {
            if candidate.is_file() {
                found.push(candidate);
            }
        }
        match found.len() {
            0 => {
                return Err(not_found(format!(
                    "no file matches `{}` under the allowed roots; candidates: {}",
                    path.display(),
                    candidate_list(path_candidates(path, &self.roots).into_iter())
                )));
            }
            1 => {}
            _ => {
                return Err(invalid(format!(
                    "path `{}` is ambiguous: {}",
                    path.display(),
                    candidate_list(found.iter().map(|item| item.display().to_string()))
                )));
            }
        }

        let canonical = canonical_file(&found[0], &self.roots)?;
        let extension = canonical
            .extension()
            .and_then(OsStr::to_str)
            .map(str::to_ascii_lowercase);
        let (inferred, mime) = extension
            .as_deref()
            .and_then(infer_modality)
            .ok_or_else(|| {
                invalid(format!(
                    "cannot infer a MIME type for `{}`; insert the attachment explicitly",
                    canonical.display()
                ))
            })?;
        if let Some(forced) = forced {
            if forced != inferred {
                return Err(invalid(format!(
                    "`{}` is a {} file ({}), not {}",
                    canonical.display(),
                    inferred.as_str(),
                    mime,
                    forced.as_str()
                )));
            }
        }
        let kind = forced.unwrap_or(inferred);
        let metadata = fs::metadata(&canonical)?;
        let bytes = metadata.len();
        if bytes > kind.byte_cap() {
            return Err(limit(format!(
                "attachment `{}` is {} bytes; the {} cap is {}",
                canonical.display(),
                bytes,
                kind.as_str(),
                kind.byte_cap()
            )));
        }
        let name = canonical
            .file_name()
            .and_then(OsStr::to_str)
            .map(str::to_string);
        if let Some(name) = &name {
            validate_name(name)?;
        }
        let id = stable_id(kind, mime, &canonical.to_string_lossy(), bytes);
        Ok(Attachment {
            id,
            kind,
            source: Source::Path { path: canonical },
            mime: mime.to_string(),
            bytes,
            name,
        })
    }
}

/// The kind of an `@` reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReferenceKind {
    File,
    Image,
    Url,
    Name,
}

/// One parsed `@` reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reference<'a> {
    /// The token including the leading `@`.
    pub raw: &'a str,
    pub kind: ReferenceKind,
    /// The path, URL, or bare name after the prefix.
    pub target: &'a str,
}

/// Parse `@file:path`, `@image:path`, `@url:https://...`, or a bare `@name`.
///
/// Paths may not contain whitespace; the grammar has no quoting. That is why a
/// file with a space in its name is an explicit, documented limitation: use a
/// direct attachment route instead.
pub fn parse_reference(token: &str) -> Result<Reference<'_>> {
    let rest = token
        .strip_prefix('@')
        .ok_or_else(|| invalid(format!("reference `{token}` must start with `@`")))?;
    if rest.is_empty() {
        return Err(invalid("a reference needs a target after `@`"));
    }

    let (kind, target) = if let Some(target) = rest.strip_prefix("file:") {
        (ReferenceKind::File, target)
    } else if let Some(target) = rest.strip_prefix("image:") {
        (ReferenceKind::Image, target)
    } else if let Some(target) = rest.strip_prefix("url:") {
        (ReferenceKind::Url, target)
    } else {
        (ReferenceKind::Name, rest)
    };

    if target.is_empty() {
        return Err(invalid(format!("reference `{token}` has an empty target")));
    }
    if target
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(invalid(format!(
            "reference `{token}` contains whitespace or a control character"
        )));
    }
    match kind {
        ReferenceKind::Name => {
            if !target
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
            {
                return Err(invalid(format!(
                    "bare reference `{token}` may only use ASCII letters, digits, `.`, `_`, and `-`"
                )));
            }
        }
        ReferenceKind::Url => validate_http_url(target)?,
        ReferenceKind::File | ReferenceKind::Image => {}
    }
    Ok(Reference {
        raw: token,
        kind,
        target,
    })
}

/// Parse every reference in free text without resolving any of them.
pub fn scan_references(text: &str) -> Result<Vec<Reference<'_>>> {
    let mut references = Vec::new();
    for segment in split_segments(text) {
        if let Segment::Reference(token) = segment {
            references.push(parse_reference(token)?);
        }
    }
    Ok(references)
}

/// What one reference resolved to while building a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefMapping {
    /// The token as it appeared in the text, including `@`.
    pub reference: String,
    /// The attachment the reference resolved to.
    pub attachment_id: String,
    /// `false` when the attachment was already emitted and deduped.
    pub added: bool,
}

/// One typed block in an input message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    Text {
        text: String,
    },
    Image {
        attachment_id: String,
        alt: Option<String>,
    },
    Audio {
        attachment_id: String,
        duration_ms: Option<u64>,
    },
    Video {
        attachment_id: String,
        duration_ms: Option<u64>,
    },
    Document {
        attachment_id: String,
        page_hint: Option<u32>,
    },
    ToolResult {
        tool_use_id: String,
        summary: String,
    },
}

/// Who produced an input message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

/// A message made of typed blocks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputMessage {
    pub role: Role,
    pub blocks: Vec<ContentBlock>,
}

impl InputMessage {
    /// Create a message. Validation is separate so callers can assemble first.
    pub fn new(role: Role, blocks: Vec<ContentBlock>) -> Self {
        Self { role, blocks }
    }

    /// Every attachment id referenced by a block, in block order.
    pub fn attachment_ids(&self) -> Vec<&str> {
        self.blocks
            .iter()
            .filter_map(|block| match block {
                ContentBlock::Image { attachment_id, .. }
                | ContentBlock::Audio { attachment_id, .. }
                | ContentBlock::Video { attachment_id, .. }
                | ContentBlock::Document { attachment_id, .. } => Some(attachment_id.as_str()),
                ContentBlock::Text { .. } | ContentBlock::ToolResult { .. } => None,
            })
            .collect()
    }

    /// Validate the blocks against the attachments the turn knows about.
    pub fn validate(&self, attachments: &[Attachment]) -> Result<()> {
        let ids: BTreeSet<String> = attachments.iter().map(|item| item.id.clone()).collect();
        self.validate_blocks(&ids)
    }

    fn validate_blocks(&self, ids: &BTreeSet<String>) -> Result<()> {
        if self.blocks.is_empty() {
            return Err(invalid("an input message needs at least one block"));
        }
        for block in &self.blocks {
            validate_block(block, ids)?;
        }
        Ok(())
    }
}

/// A message plus the reference mappings recorded while expanding it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltInput {
    pub message: InputMessage,
    pub mappings: Vec<RefMapping>,
}

/// Build a user message from prompt text and the attachments already in hand.
///
/// Attachments in `attachments` (paste, drag and drop, clipboard, share sheet)
/// are emitted first in list order, then the text is walked left to right:
/// literal runs become [`ContentBlock::Text`] and each `@` reference expands in
/// place. An attachment referenced more than once is emitted once; the extra
/// reference is recorded with `added = false`.
pub fn build_input(
    text_with_refs: &str,
    attachments: &[Attachment],
    store: &AttachmentStore,
) -> Result<InputMessage> {
    Ok(build_input_for_role(Role::User, text_with_refs, attachments, store)?.message)
}

/// [`build_input`] with the reference mapping kept.
pub fn build_input_with_mapping(
    text_with_refs: &str,
    attachments: &[Attachment],
    store: &AttachmentStore,
) -> Result<BuiltInput> {
    build_input_for_role(Role::User, text_with_refs, attachments, store)
}

/// [`build_input_with_mapping`] for an explicit role.
pub fn build_input_for_role(
    role: Role,
    text_with_refs: &str,
    attachments: &[Attachment],
    store: &AttachmentStore,
) -> Result<BuiltInput> {
    for attachment in attachments {
        attachment.validate(store.roots())?;
    }

    let mut blocks = Vec::new();
    let mut emitted: Vec<Attachment> = Vec::new();
    let mut mappings = Vec::new();

    for attachment in attachments {
        emit_attachment(
            attachment,
            store.roots(),
            &mut blocks,
            &mut emitted,
            None,
            &mut mappings,
        )?;
    }

    for segment in split_segments(text_with_refs) {
        match segment {
            Segment::Text(text) => {
                if !text.trim().is_empty() {
                    blocks.push(ContentBlock::Text {
                        text: text.to_string(),
                    });
                }
            }
            Segment::Reference(token) => {
                let reference = parse_reference(token)?;
                let attachment = resolve_reference(&reference, attachments, store)?;
                attachment.validate(store.roots())?;
                emit_attachment(
                    &attachment,
                    store.roots(),
                    &mut blocks,
                    &mut emitted,
                    Some(token),
                    &mut mappings,
                )?;
            }
        }
    }

    let message = InputMessage::new(role, blocks);
    let mut known = attachments.to_vec();
    for attachment in &emitted {
        if !known.iter().any(|item| item.id == attachment.id) {
            known.push(attachment.clone());
        }
    }
    message.validate(&known)?;
    Ok(BuiltInput { message, mappings })
}

/// Known dimensions for an attachment. Anything `None` is unknown and is
/// reported by [`account`] rather than guessed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentMeta {
    pub id: String,
    pub kind: Modality,
    pub mime: String,
    pub bytes: Option<u64>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub duration_ms: Option<u64>,
    pub pages: Option<u32>,
}

impl AttachmentMeta {
    /// Metadata known directly from an [`Attachment`]. Dimensions, duration,
    /// and page count stay unknown; `0` bytes on a URL stays unknown too.
    pub fn from_attachment(attachment: &Attachment) -> Self {
        let bytes = match &attachment.source {
            Source::Url { .. } if attachment.bytes == 0 => None,
            _ => Some(attachment.bytes),
        };
        Self {
            id: attachment.id.clone(),
            kind: attachment.kind,
            mime: attachment.mime.clone(),
            bytes,
            width: None,
            height: None,
            duration_ms: None,
            pages: None,
        }
    }

    /// Record pixel dimensions.
    pub fn with_pixels(mut self, width: u32, height: u32) -> Self {
        self.width = Some(width);
        self.height = Some(height);
        self
    }

    /// Record a duration.
    pub fn with_duration_ms(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }

    /// Record a page count.
    pub fn with_pages(mut self, pages: u32) -> Self {
        self.pages = Some(pages);
        self
    }

    /// Record a byte size.
    pub fn with_bytes(mut self, bytes: u64) -> Self {
        self.bytes = Some(bytes);
        self
    }
}

/// An accounting dimension the message used but the metadata could not supply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Dimension {
    Bytes,
    Pixels,
    DurationMs,
    Pages,
}

impl Dimension {
    /// Stable lowercase name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Dimension::Bytes => "bytes",
            Dimension::Pixels => "pixels",
            Dimension::DurationMs => "duration_ms",
            Dimension::Pages => "pages",
        }
    }
}

/// One unknown dimension for one attachment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UnknownDimension {
    pub attachment_id: String,
    pub dimension: Dimension,
}

/// Per-modality usage for one message. Only known values are summed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModalityUsage {
    pub text_chars: u64,
    pub image_count: u64,
    pub image_pixels: u64,
    pub audio_ms: u64,
    pub video_ms: u64,
    pub document_pages: u64,
    pub bytes_by_modality: BTreeMap<Modality, u64>,
    /// Sorted, deduplicated list of dimensions that were unavailable.
    pub unknown: Vec<UnknownDimension>,
}

impl ModalityUsage {
    /// Bytes summed across every modality.
    pub fn total_bytes(&self) -> u64 {
        self.bytes_by_modality.values().copied().sum()
    }

    /// Known bytes for one modality.
    pub fn bytes_for(&self, modality: Modality) -> u64 {
        self.bytes_by_modality.get(&modality).copied().unwrap_or(0)
    }
}

/// Account one message against attachment metadata.
///
/// Attachment ids are validated first. Counts follow block occurrences (a block
/// that repeats an attachment is content the model receives twice). Bytes come
/// from the metadata; text bytes come from the text itself. Missing width,
/// height, duration, page count, or byte size is reported in
/// [`ModalityUsage::unknown`] and left out of the totals.
pub fn account(
    message: &InputMessage,
    attachment_meta: &[AttachmentMeta],
) -> Result<ModalityUsage> {
    let ids: BTreeSet<String> = attachment_meta.iter().map(|meta| meta.id.clone()).collect();
    message.validate_blocks(&ids)?;

    let mut meta_by_id: BTreeMap<&str, &AttachmentMeta> = BTreeMap::new();
    for meta in attachment_meta {
        meta_by_id.entry(meta.id.as_str()).or_insert(meta);
    }

    let mut usage = ModalityUsage::default();
    let mut unknown: BTreeSet<(String, Dimension)> = BTreeSet::new();
    for block in &message.blocks {
        match block {
            ContentBlock::Text { text } => {
                usage.text_chars += text.chars().count() as u64;
                add_bytes(&mut usage, Modality::Text, text.len() as u64);
            }
            ContentBlock::ToolResult { summary, .. } => {
                usage.text_chars += summary.chars().count() as u64;
                add_bytes(&mut usage, Modality::Text, summary.len() as u64);
            }
            ContentBlock::Image { attachment_id, .. } => {
                usage.image_count += 1;
                let meta = meta(attachment_id, &meta_by_id)?;
                match (meta.width, meta.height) {
                    (Some(width), Some(height)) if width > 0 && height > 0 => {
                        usage.image_pixels += u64::from(width) * u64::from(height);
                    }
                    _ => {
                        unknown.insert((meta.id.clone(), Dimension::Pixels));
                    }
                }
                add_meta_bytes(&mut usage, meta, &mut unknown);
            }
            ContentBlock::Audio {
                attachment_id,
                duration_ms,
            } => {
                let meta = meta(attachment_id, &meta_by_id)?;
                match duration_ms.or(meta.duration_ms) {
                    Some(duration) if duration > 0 => usage.audio_ms += duration,
                    _ => {
                        unknown.insert((meta.id.clone(), Dimension::DurationMs));
                    }
                }
                add_meta_bytes(&mut usage, meta, &mut unknown);
            }
            ContentBlock::Video {
                attachment_id,
                duration_ms,
            } => {
                let meta = meta(attachment_id, &meta_by_id)?;
                match duration_ms.or(meta.duration_ms) {
                    Some(duration) if duration > 0 => usage.video_ms += duration,
                    _ => {
                        unknown.insert((meta.id.clone(), Dimension::DurationMs));
                    }
                }
                add_meta_bytes(&mut usage, meta, &mut unknown);
            }
            ContentBlock::Document { attachment_id, .. } => {
                let meta = meta(attachment_id, &meta_by_id)?;
                match meta.pages {
                    Some(pages) if pages > 0 => usage.document_pages += u64::from(pages),
                    _ => {
                        unknown.insert((meta.id.clone(), Dimension::Pages));
                    }
                }
                add_meta_bytes(&mut usage, meta, &mut unknown);
            }
        }
    }
    usage.unknown = unknown
        .into_iter()
        .map(|(attachment_id, dimension)| UnknownDimension {
            attachment_id,
            dimension,
        })
        .collect();
    Ok(usage)
}

/// Strict, standard padded base64 decoding (no whitespace, no URL-safe
/// alphabet). Kept local so the crate needs no extra dependency.
pub fn decode_base64(text: &str) -> Result<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err(invalid("inline base64 length must be a multiple of four"));
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let last_chunk = bytes.len() / 4;
    for (index, chunk) in bytes.chunks(4).enumerate() {
        let mut values = [0u8; 4];
        let mut padding = 0usize;
        for (offset, &byte) in chunk.iter().enumerate() {
            if byte == b'=' {
                if index + 1 != last_chunk || offset < 2 {
                    return Err(invalid("inline base64 padding is misplaced"));
                }
                padding += 1;
                continue;
            }
            if padding > 0 {
                return Err(invalid("inline base64 padding is misplaced"));
            }
            values[offset] = b64_value(byte)
                .ok_or_else(|| invalid("inline base64 contains an invalid character"))?;
        }
        out.push((values[0] << 2) | (values[1] >> 4));
        if padding < 2 {
            out.push(((values[1] & 0x0f) << 4) | (values[2] >> 2));
        }
        if padding == 0 {
            out.push(((values[2] & 0x03) << 6) | values[3]);
        }
    }
    Ok(out)
}

enum Segment<'a> {
    Text(&'a str),
    Reference(&'a str),
}

fn split_segments(text: &str) -> Vec<Segment<'_>> {
    let mut segments = Vec::new();
    let mut plain_start = 0usize;
    let mut index = 0usize;
    while index < text.len() {
        let Some(character) = text[index..].chars().next() else {
            break;
        };
        if character == '@' && reference_starts_at(text, index) {
            let end = reference_end(text, index);
            if end > index + 1 {
                if plain_start < index {
                    segments.push(Segment::Text(&text[plain_start..index]));
                }
                segments.push(Segment::Reference(&text[index..end]));
                plain_start = end;
                index = end;
                continue;
            }
        }
        index += character.len_utf8();
    }
    if plain_start < text.len() {
        segments.push(Segment::Text(&text[plain_start..]));
    }
    segments
}

fn reference_starts_at(text: &str, index: usize) -> bool {
    match text[..index].chars().next_back() {
        None => true,
        Some(previous) => {
            previous.is_whitespace() || matches!(previous, '(' | '[' | '{' | '<' | '"' | '\'')
        }
    }
}

fn reference_end(text: &str, start: usize) -> usize {
    let mut end = start + 1;
    for (offset, character) in text[start + 1..].char_indices() {
        if character.is_whitespace()
            || character.is_control()
            || matches!(character, ',' | ';' | ')' | ']' | '}' | '>' | '"' | '\'')
        {
            break;
        }
        end = start + 1 + offset + character.len_utf8();
    }
    let token = &text[start..end];
    let bare = !token.starts_with("@file:")
        && !token.starts_with("@image:")
        && !token.starts_with("@url:");
    if bare {
        // Sentence punctuation is not part of a bare name.
        while end > start + 1 && text.as_bytes()[end - 1] == b'.' {
            end -= 1;
        }
    }
    end
}

fn resolve_reference(
    reference: &Reference<'_>,
    attachments: &[Attachment],
    store: &AttachmentStore,
) -> Result<Attachment> {
    match reference.kind {
        ReferenceKind::Name => resolve_name(reference.target, attachments, store),
        _ => store.resolve(reference),
    }
}

fn resolve_name(
    name: &str,
    attachments: &[Attachment],
    store: &AttachmentStore,
) -> Result<Attachment> {
    let mut matches: Vec<&Attachment> = Vec::new();
    for attachment in attachments.iter().chain(store.entries()) {
        if attachment.name.as_deref() == Some(name)
            && !matches.iter().any(|item| item.id == attachment.id)
        {
            matches.push(attachment);
        }
    }
    match matches.len() {
        0 => {
            let candidates = attachments
                .iter()
                .chain(store.entries())
                .filter_map(|attachment| attachment.name.clone());
            Err(not_found(format!(
                "no attachment named `{name}`; candidates: {}",
                candidate_list(candidates)
            )))
        }
        1 => Ok(matches[0].clone()),
        _ => Err(invalid(format!(
            "attachment name `{name}` is ambiguous; candidates: {}",
            candidate_list(matches.iter().map(|item| item.id.clone()))
        ))),
    }
}

fn emit_attachment(
    attachment: &Attachment,
    roots: &[PathBuf],
    blocks: &mut Vec<ContentBlock>,
    emitted: &mut Vec<Attachment>,
    reference: Option<&str>,
    mappings: &mut Vec<RefMapping>,
) -> Result<bool> {
    let duplicate = emitted
        .iter()
        .any(|existing| same_content(existing, attachment));
    if !duplicate {
        blocks.push(block_for_attachment(attachment, roots)?);
        emitted.push(attachment.clone());
    }
    if let Some(reference) = reference {
        mappings.push(RefMapping {
            reference: reference.to_string(),
            attachment_id: attachment.id.clone(),
            added: !duplicate,
        });
    }
    Ok(!duplicate)
}

fn block_for_attachment(attachment: &Attachment, roots: &[PathBuf]) -> Result<ContentBlock> {
    match attachment.kind {
        Modality::Text => Ok(ContentBlock::Text {
            text: text_content(attachment, roots)?,
        }),
        Modality::Image => Ok(ContentBlock::Image {
            attachment_id: attachment.id.clone(),
            alt: attachment.name.clone(),
        }),
        Modality::Audio => Ok(ContentBlock::Audio {
            attachment_id: attachment.id.clone(),
            duration_ms: None,
        }),
        Modality::Video => Ok(ContentBlock::Video {
            attachment_id: attachment.id.clone(),
            duration_ms: None,
        }),
        Modality::Document => Ok(ContentBlock::Document {
            attachment_id: attachment.id.clone(),
            page_hint: None,
        }),
    }
}

fn text_content(attachment: &Attachment, roots: &[PathBuf]) -> Result<String> {
    match &attachment.source {
        Source::Inline { bytes_b64 } => {
            let decoded = decode_base64(bytes_b64)?;
            String::from_utf8(decoded).map_err(|_| {
                invalid(format!(
                    "inline text `{}` is not valid UTF-8",
                    attachment.id
                ))
            })
        }
        Source::Path { path } => {
            let canonical = canonical_file(path, roots)?;
            fs::read_to_string(&canonical).map_err(|error| {
                ZeroError::new(
                    ErrorCode::Io,
                    format!(
                        "cannot read text attachment `{}`: {error}",
                        canonical.display()
                    ),
                )
            })
        }
        Source::Url { url } => Err(ZeroError::new(
            ErrorCode::Unsupported,
            format!("text URL `{url}` is not fetched; attach the bytes inline or as a local path"),
        )),
    }
}

fn same_content(left: &Attachment, right: &Attachment) -> bool {
    left.kind == right.kind
        && left.mime.eq_ignore_ascii_case(&right.mime)
        && left.bytes == right.bytes
        && left.source == right.source
}

fn validate_block(block: &ContentBlock, ids: &BTreeSet<String>) -> Result<()> {
    match block {
        ContentBlock::Text { text } => {
            if text.trim().is_empty() {
                return Err(invalid("a text block cannot be empty"));
            }
            if text.chars().count() > MAX_TEXT_CHARS {
                return Err(limit(format!(
                    "a text block is {} characters; the cap is {MAX_TEXT_CHARS}",
                    text.chars().count()
                )));
            }
            if text.contains('\0') {
                return Err(invalid("a text block cannot contain NUL"));
            }
        }
        ContentBlock::Image { attachment_id, alt } => {
            validate_id(attachment_id, "attachment id")?;
            ensure_known(attachment_id, ids)?;
            if let Some(alt) = alt {
                if alt.chars().count() > MAX_ALT_CHARS {
                    return Err(limit(format!(
                        "image alt text is {} characters; the cap is {MAX_ALT_CHARS}",
                        alt.chars().count()
                    )));
                }
                if alt.chars().any(char::is_control) {
                    return Err(invalid("image alt text cannot contain control characters"));
                }
            }
        }
        ContentBlock::Audio {
            attachment_id,
            duration_ms,
        }
        | ContentBlock::Video {
            attachment_id,
            duration_ms,
        } => {
            validate_id(attachment_id, "attachment id")?;
            ensure_known(attachment_id, ids)?;
            if duration_ms == &Some(0) {
                return Err(invalid("an audio or video duration must be positive"));
            }
        }
        ContentBlock::Document {
            attachment_id,
            page_hint,
        } => {
            validate_id(attachment_id, "attachment id")?;
            ensure_known(attachment_id, ids)?;
            if page_hint == &Some(0) {
                return Err(invalid("a document page hint must be positive"));
            }
        }
        ContentBlock::ToolResult {
            tool_use_id,
            summary,
        } => {
            validate_id(tool_use_id, "tool-use id")?;
            if summary.trim().is_empty() {
                return Err(invalid("a tool result summary cannot be empty"));
            }
            if summary.chars().count() > MAX_SUMMARY_CHARS {
                return Err(limit(format!(
                    "a tool result summary is {} characters; the cap is {MAX_SUMMARY_CHARS}",
                    summary.chars().count()
                )));
            }
            if summary.contains('\0') {
                return Err(invalid("a tool result summary cannot contain NUL"));
            }
        }
    }
    Ok(())
}

fn ensure_known(attachment_id: &str, ids: &BTreeSet<String>) -> Result<()> {
    if ids.contains(attachment_id) {
        return Ok(());
    }
    Err(not_found(format!(
        "attachment `{attachment_id}` does not exist; candidates: {}",
        candidate_list(ids.iter().cloned())
    )))
}

fn meta<'a>(id: &str, by_id: &'a BTreeMap<&str, &'a AttachmentMeta>) -> Result<&'a AttachmentMeta> {
    by_id.get(id).copied().ok_or_else(|| {
        not_found(format!(
            "no metadata for attachment `{id}`; candidates: {}",
            candidate_list(by_id.keys().map(|key| (*key).to_string()))
        ))
    })
}

fn add_meta_bytes(
    usage: &mut ModalityUsage,
    meta: &AttachmentMeta,
    unknown: &mut BTreeSet<(String, Dimension)>,
) {
    match meta.bytes {
        Some(bytes) => add_bytes(usage, meta.kind, bytes),
        None => {
            unknown.insert((meta.id.clone(), Dimension::Bytes));
        }
    }
}

fn add_bytes(usage: &mut ModalityUsage, modality: Modality, bytes: u64) {
    *usage.bytes_by_modality.entry(modality).or_insert(0) += bytes;
}

fn validate_id(id: &str, label: &str) -> Result<()> {
    if id.is_empty() {
        return Err(invalid(format!("{label} cannot be empty")));
    }
    if id.chars().count() > MAX_ID_CHARS {
        return Err(limit(format!(
            "{label} `{id}` is longer than {MAX_ID_CHARS} characters"
        )));
    }
    if id.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
        return Err(invalid(format!(
            "{label} `{id}` contains a control character or whitespace"
        )));
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(invalid("an attachment name cannot be empty"));
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(limit(format!(
            "attachment name is longer than {MAX_NAME_CHARS} characters"
        )));
    }
    if name.chars().any(char::is_control) {
        return Err(invalid(format!(
            "attachment name `{name}` contains a control character"
        )));
    }
    Ok(())
}

fn validate_mime(mime: &str) -> Result<String> {
    if mime.chars().any(char::is_control) {
        return Err(invalid(format!(
            "mime `{mime}` contains a control character"
        )));
    }
    let essence = mime.split(';').next().unwrap_or("").trim();
    let Some((category, subtype)) = essence.split_once('/') else {
        return Err(invalid(format!("mime `{mime}` is missing `type/subtype`")));
    };
    if category.is_empty()
        || subtype.is_empty()
        || subtype.contains('/')
        || essence.chars().any(char::is_whitespace)
    {
        return Err(invalid(format!("mime `{mime}` is malformed")));
    }
    Ok(essence.to_ascii_lowercase())
}

fn mime_matches(kind: Modality, essence: &str) -> bool {
    match kind {
        Modality::Text => {
            essence.starts_with("text/")
                || matches!(
                    essence,
                    "application/json"
                        | "application/xml"
                        | "application/yaml"
                        | "application/x-yaml"
                )
        }
        Modality::Image => essence.starts_with("image/"),
        Modality::Audio => essence.starts_with("audio/"),
        Modality::Video => essence.starts_with("video/"),
        Modality::Document => matches!(
            essence,
            "application/pdf"
                | "application/rtf"
                | "application/msword"
                | "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                | "application/vnd.oasis.opendocument.text"
                | "application/epub+zip"
                | "application/octet-stream"
                | "text/plain"
                | "text/markdown"
                | "text/csv"
                | "text/html"
        ),
    }
}

fn infer_modality(extension: &str) -> Option<(Modality, &'static str)> {
    let inferred = match extension {
        "png" => (Modality::Image, "image/png"),
        "jpg" | "jpeg" => (Modality::Image, "image/jpeg"),
        "gif" => (Modality::Image, "image/gif"),
        "webp" => (Modality::Image, "image/webp"),
        "bmp" => (Modality::Image, "image/bmp"),
        "tif" | "tiff" => (Modality::Image, "image/tiff"),
        "svg" => (Modality::Image, "image/svg+xml"),
        "wav" => (Modality::Audio, "audio/wav"),
        "mp3" => (Modality::Audio, "audio/mpeg"),
        "m4a" => (Modality::Audio, "audio/mp4"),
        "flac" => (Modality::Audio, "audio/flac"),
        "ogg" => (Modality::Audio, "audio/ogg"),
        "opus" => (Modality::Audio, "audio/opus"),
        "mp4" => (Modality::Video, "video/mp4"),
        "mov" => (Modality::Video, "video/quicktime"),
        "webm" => (Modality::Video, "video/webm"),
        "mkv" => (Modality::Video, "video/x-matroska"),
        "avi" => (Modality::Video, "video/x-msvideo"),
        "pdf" => (Modality::Document, "application/pdf"),
        "doc" => (Modality::Document, "application/msword"),
        "docx" => (
            Modality::Document,
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ),
        "odt" => (
            Modality::Document,
            "application/vnd.oasis.opendocument.text",
        ),
        "epub" => (Modality::Document, "application/epub+zip"),
        "rtf" => (Modality::Document, "application/rtf"),
        "csv" => (Modality::Document, "text/csv"),
        "txt" | "rs" | "py" | "js" | "ts" | "tsx" | "jsx" | "go" | "java" | "c" | "h" | "cc"
        | "cpp" | "cs" | "rb" | "sh" | "toml" | "ini" | "cfg" | "log" | "md" | "markdown" => {
            (Modality::Text, "text/plain")
        }
        "json" => (Modality::Text, "application/json"),
        "xml" => (Modality::Text, "application/xml"),
        "yaml" | "yml" => (Modality::Text, "application/yaml"),
        _ => return None,
    };
    Some(inferred)
}

fn url_attachment(url: &str) -> Result<Attachment> {
    validate_http_url(url)?;
    let name = url_path(url)
        .rsplit('/')
        .find(|segment| !segment.is_empty())
        .map(str::to_string);
    let extension = name
        .as_deref()
        .and_then(|value| value.rsplit_once('.').map(|(_, extension)| extension));
    let (kind, mime) = extension
        .and_then(infer_modality)
        .unwrap_or((Modality::Document, "application/octet-stream"));
    let id = stable_id(kind, mime, url, 0);
    let attachment = Attachment {
        id,
        kind,
        source: Source::Url {
            url: url.to_string(),
        },
        mime: mime.to_string(),
        bytes: 0,
        name,
    };
    attachment.validate(&[])?;
    Ok(attachment)
}

fn url_path(url: &str) -> &str {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let after_authority = after_scheme
        .find('/')
        .map(|index| &after_scheme[index..])
        .unwrap_or("");
    let without_fragment = after_authority.split('#').next().unwrap_or("");
    without_fragment.split('?').next().unwrap_or("")
}

fn validate_http_url(url: &str) -> Result<()> {
    if url.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
        return Err(invalid("URL contains whitespace or a control character"));
    }
    let Some((scheme, rest)) = url.split_once("://") else {
        return Err(invalid(format!("URL `{url}` is missing a scheme")));
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(invalid(format!(
            "URL `{url}` uses `{scheme}`; only http and https are allowed"
        )));
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err(invalid(format!("URL `{url}` has no host")));
    }
    if authority.contains('@') {
        return Err(invalid(format!(
            "URL `{url}` carries userinfo; credentials in a URL are not allowed"
        )));
    }
    if authority.contains('\\') {
        return Err(invalid(format!("URL `{url}` has an invalid host")));
    }
    let host = if let Some(remainder) = authority.strip_prefix('[') {
        remainder.split(']').next().unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    };
    if host.is_empty() {
        return Err(invalid(format!("URL `{url}` has no host")));
    }
    Ok(())
}

fn validate_path(path: &Path, roots: &[PathBuf]) -> Result<()> {
    if !path.is_absolute() {
        return Err(invalid(format!(
            "attachment path `{}` must be absolute",
            path.display()
        )));
    }
    let normalised = normalize_lexical(path)?;
    if roots.is_empty() {
        return Err(denied(
            "no allowed roots are configured for path attachments",
        ));
    }
    // Canonicalising resolves 8.3 short names and symlinks before the root
    // comparison; a local attachment therefore has to exist.
    let canonical = fs::canonicalize(&normalised)?;
    let mut inside = false;
    for root in roots {
        if !root.is_absolute() {
            return Err(invalid(format!(
                "allowed root `{}` must be absolute",
                root.display()
            )));
        }
        let root = normalize_lexical(root)?;
        if is_within(&canonical, &root) {
            inside = true;
            break;
        }
    }
    if inside {
        Ok(())
    } else {
        Err(denied(format!(
            "path `{}` is outside the allowed roots",
            path.display()
        )))
    }
}

fn path_candidates(path: &Path, roots: &[PathBuf]) -> Vec<String> {
    let mut directories = Vec::new();
    if path.is_absolute() {
        if let Some(parent) = path.parent() {
            directories.push(parent.to_path_buf());
        }
    } else {
        directories.extend(roots.iter().cloned());
    }
    let mut names = Vec::new();
    for directory in directories {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            if !entry.path().is_file() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    names
}

fn canonical_file(path: &Path, roots: &[PathBuf]) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)?;
    if !canonical.is_file() {
        return Err(invalid(format!(
            "`{}` is not a regular file",
            canonical.display()
        )));
    }
    let mut inside = false;
    for root in roots {
        if let Ok(root) = fs::canonicalize(root) {
            if is_within(&canonical, &root) {
                inside = true;
                break;
            }
        }
    }
    if inside {
        Ok(canonical)
    } else {
        Err(denied(format!(
            "path `{}` is outside the allowed roots",
            canonical.display()
        )))
    }
}

fn normalize_lexical(path: &Path) -> Result<PathBuf> {
    let mut normalised = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalised.push(prefix.as_os_str()),
            Component::RootDir => normalised.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(invalid(format!(
                    "path `{}` contains a `..` component",
                    path.display()
                )));
            }
            Component::Normal(part) => normalised.push(part),
        }
    }
    Ok(normalised)
}

fn is_within(path: &Path, root: &Path) -> bool {
    let mut path_components = path.components();
    for root_component in root.components() {
        match path_components.next() {
            Some(component)
                if components_equal(component.as_os_str(), root_component.as_os_str()) => {}
            _ => return false,
        }
    }
    // Strictly inside: the root itself is a directory, not an attachment.
    path_components.next().is_some()
}

fn components_equal(left: &OsStr, right: &OsStr) -> bool {
    if cfg!(windows) {
        // `fs::canonicalize` yields a verbatim (`\\?\C:`) prefix while a
        // configured root may be a plain drive path. Compare them as the same.
        component_text(left).eq_ignore_ascii_case(&component_text(right))
    } else {
        left == right
    }
}

fn component_text(value: &OsStr) -> String {
    let text = value.to_string_lossy();
    text.strip_prefix(r"\\?\").unwrap_or(&text).to_string()
}

fn stable_id(kind: Modality, mime: &str, source: &str, bytes: u64) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for part in [kind.as_str(), mime, source, &bytes.to_string()] {
        hash = fnv1a(hash, part.as_bytes());
        hash = fnv1a(hash, b"\0");
    }
    format!("att-{hash:016x}")
}

fn fnv1a(mut hash: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn candidate_list(items: impl Iterator<Item = String>) -> String {
    let mut listed: Vec<String> = Vec::new();
    let mut extra = 0usize;
    for item in items {
        if listed.len() < MAX_CANDIDATES {
            listed.push(item);
        } else {
            extra += 1;
        }
    }
    if listed.is_empty() {
        return "(none)".to_string();
    }
    let mut text = listed.join(", ");
    if extra > 0 {
        text.push_str(&format!(" (+{extra} more)"));
    }
    text
}

const fn b64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn limit(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

fn not_found(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::NotFound, message)
}

fn denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PermissionDenied, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_accepts_padding_and_rejects_malformed_input() {
        assert_eq!(decode_base64("").expect("empty"), Vec::<u8>::new());
        assert_eq!(decode_base64("QQ==").expect("one byte"), b"A");
        assert_eq!(decode_base64("QUI=").expect("two bytes"), b"AB");
        assert_eq!(decode_base64("QUJD").expect("three bytes"), b"ABC");
        for bad in ["A", "QQ=", "Q===", "=QQ=", "QQ==QQ==", "Q Q==", "QUJD\n"] {
            assert!(decode_base64(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn a_reference_only_starts_after_a_boundary() {
        let references =
            scan_references("mail a@b.com and @shot, then (@url:https://example.com/x.png)")
                .expect("parse");
        assert_eq!(references.len(), 2);
        assert_eq!(references[0].kind, ReferenceKind::Name);
        assert_eq!(references[0].target, "shot");
        assert_eq!(references[1].kind, ReferenceKind::Url);

        let segments = split_segments("ends with @note.");
        assert_eq!(segments.len(), 3);
        match &segments[1] {
            Segment::Reference(token) => assert_eq!(*token, "@note"),
            Segment::Text(_) => panic!("expected a reference"),
        }
        match &segments[2] {
            Segment::Text(text) => assert_eq!(*text, "."),
            Segment::Reference(_) => panic!("expected trailing punctuation"),
        }
    }

    #[test]
    fn mime_inference_covers_every_modality() {
        assert_eq!(infer_modality("png").expect("png").0, Modality::Image);
        assert_eq!(infer_modality("wav").expect("wav").0, Modality::Audio);
        assert_eq!(infer_modality("mp4").expect("mp4").0, Modality::Video);
        assert_eq!(infer_modality("pdf").expect("pdf").0, Modality::Document);
        assert_eq!(infer_modality("rs").expect("rs").0, Modality::Text);
        assert!(infer_modality("bin").is_none());
    }
}
