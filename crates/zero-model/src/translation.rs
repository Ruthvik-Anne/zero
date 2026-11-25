//! Cross-provider transcript translation (MDL-13, MDL-05).
//!
//! Escalation can change the provider in the middle of a task, so the
//! transcript has to be rewritten in the target's shape without losing a tool
//! call that is still in flight. This module owns the provider-neutral
//! [`Transcript`], the target-specific [`ProviderFormat`] rules, and the
//! [`Translation`] report.
//!
//! The canonical transcript is intentionally small: text, tool use, tool
//! result, image, thinking, and system blocks. [`translate`] validates the
//! input, normalises system placement, drops blocks the target cannot carry
//! (recording every drop), and remaps tool ids when the target needs a
//! different shape. Tool use and tool result are never dropped, because losing
//! either half would break the pairing that an in-flight call depends on.
//!
//! `Transcript::render` is a mapping check and a caller helper: it turns the
//! canonical transcript into the provider wire shape as `serde_json::Value`.
//! Translation itself returns a canonical [`Transcript`].

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use zero_types::error::{ErrorCode, Result, ZeroError};

/// Maximum bytes in one text, thinking, or system block.
pub const MAX_TEXT_BYTES: usize = 1024 * 1024;

/// Maximum bytes in one base64 image payload.
pub const MAX_IMAGE_B64_BYTES: usize = 8 * 1024 * 1024;

/// Maximum bytes in one image media type.
pub const MAX_MEDIA_TYPE_BYTES: usize = 128;

/// Maximum bytes in one tool-use id.
pub const MAX_TOOL_ID_BYTES: usize = 512;

/// Maximum bytes in one tool name.
pub const MAX_TOOL_NAME_BYTES: usize = 128;

/// Maximum bytes in serialised tool arguments.
pub const MAX_TOOL_ARGUMENT_BYTES: usize = 1024 * 1024;

/// Maximum bytes in serialised tool-result content.
pub const MAX_TOOL_CONTENT_BYTES: usize = 1024 * 1024;

/// Conservative OpenAI tool-call id bound.
const OPENAI_TOOL_ID_MAX: usize = 40;

/// Conservative Anthropic tool-use id bound.
const ANTHROPIC_TOOL_ID_MAX: usize = 64;

/// Image media types OpenAI accepts.
const OPENAI_IMAGE_TYPES: &[&str] = &["image/png", "image/jpeg", "image/webp", "image/gif"];

/// Image media types Anthropic accepts.
const ANTHROPIC_IMAGE_TYPES: &[&str] = &["image/png", "image/jpeg", "image/webp", "image/gif"];

/// Image media types Gemini accepts.
const GEMINI_IMAGE_TYPES: &[&str] =
    &["image/png", "image/jpeg", "image/webp", "image/heic", "image/heif"];

/// The role of a canonical message.
///
/// System content is a [`Block::System`] inside a message rather than a third
/// role, so the canonical model has only the two conversational roles. A
/// leading user message containing only a system block is the canonical system
/// slot; see [`Transcript::system_text`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRole {
    User,
    Assistant,
}

/// A provider-neutral content block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Block {
    /// Plain text.
    Text { text: String },
    /// An assistant request to invoke a tool.
    ToolUse {
        id: String,
        name: String,
        arguments: Value,
    },
    /// The result of a preceding tool use.
    ToolResult {
        tool_use_id: String,
        content: Value,
        is_error: bool,
    },
    /// An inline base64 image.
    Image {
        media_type: String,
        data_b64: String,
    },
    /// A provider-specific reasoning block.
    Thinking { text: String },
    /// A system instruction.
    System { text: String },
}

impl Block {
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text { text: text.into() }
    }

    pub fn tool_use(id: impl Into<String>, name: impl Into<String>, arguments: Value) -> Self {
        Self::ToolUse { id: id.into(), name: name.into(), arguments }
    }

    pub fn tool_result(
        tool_use_id: impl Into<String>,
        content: Value,
        is_error: bool,
    ) -> Self {
        Self::ToolResult { tool_use_id: tool_use_id.into(), content, is_error }
    }

    pub fn image(media_type: impl Into<String>, data_b64: impl Into<String>) -> Self {
        Self::Image { media_type: media_type.into(), data_b64: data_b64.into() }
    }

    pub fn thinking(text: impl Into<String>) -> Self {
        Self::Thinking { text: text.into() }
    }

    pub fn system(text: impl Into<String>) -> Self {
        Self::System { text: text.into() }
    }

    /// Stable label used in a [`DroppedBlock`].
    pub const fn kind(&self) -> &'static str {
        match self {
            Block::Text { .. } => "text",
            Block::ToolUse { .. } => "tool_use",
            Block::ToolResult { .. } => "tool_result",
            Block::Image { .. } => "image",
            Block::Thinking { .. } => "thinking",
            Block::System { .. } => "system",
        }
    }
}

/// One canonical message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub role: MessageRole,
    pub blocks: Vec<Block>,
}

impl Message {
    pub fn user(blocks: Vec<Block>) -> Self {
        Self { role: MessageRole::User, blocks }
    }

    pub fn assistant(blocks: Vec<Block>) -> Self {
        Self { role: MessageRole::Assistant, blocks }
    }
}

/// A canonical transcript.
///
/// `tool_ids` is a derived index of every tool-use id in `messages`.
/// [`Transcript::new`] computes it; [`Transcript::validate`] verifies it after
/// a struct literal or deserialization.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transcript {
    pub messages: Vec<Message>,
    pub tool_ids: BTreeSet<String>,
}

impl Transcript {
    /// Validate a transcript and compute its tool-id index.
    pub fn new(messages: Vec<Message>) -> Result<Self> {
        let tool_ids = validate_messages(&messages)?;
        Ok(Self { messages, tool_ids })
    }

    /// An empty transcript.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Re-check every invariant, including the `tool_ids` index.
    pub fn validate(&self) -> Result<()> {
        let expected = validate_messages(&self.messages)?;
        if expected != self.tool_ids {
            return Err(invalid(
                "transcript tool_ids does not match its tool_use blocks",
            ));
        }
        Ok(())
    }

    /// The merged system instruction, in transcript order.
    ///
    /// Empty system blocks are ignored; multiple blocks are joined with a
    /// blank line. `None` means the transcript has no non-empty system block.
    pub fn system_text(&self) -> Option<String> {
        let parts: Vec<&str> = self
            .messages
            .iter()
            .flat_map(|message| message.blocks.iter())
            .filter_map(|block| match block {
                Block::System { text } if !text.is_empty() => Some(text.as_str()),
                _ => None,
            })
            .collect();
        if parts.is_empty() {
            None
        } else {
            Some(parts.join("\n\n"))
        }
    }

    /// Render the canonical transcript as the target's wire shape.
    ///
    /// This is deliberately a separate step from [`translate`]: translation
    /// returns a canonical transcript so the caller can inspect and re-validate
    /// it. Rendering refuses a block the target cannot carry (a thinking block
    /// for OpenAI or Gemini, an unsupported image media type) instead of
    /// silently omitting it; call `translate` first to get the recorded drop.
    pub fn render(&self, format: ProviderFormat) -> Result<Value> {
        self.validate()?;
        match format {
            ProviderFormat::OpenAi => self.render_openai(),
            ProviderFormat::Anthropic => self.render_anthropic(),
            ProviderFormat::Gemini => self.render_gemini(),
        }
    }

    fn render_openai(&self) -> Result<Value> {
        let mut messages = Vec::new();
        if let Some(system) = self.system_text() {
            messages.push(json!({ "role": "system", "content": system }));
        }
        for message in &self.messages {
            match message.role {
                MessageRole::Assistant => {
                    if let Some(value) = render_openai_assistant(message)? {
                        messages.push(value);
                    }
                }
                MessageRole::User => messages.extend(render_openai_user(message)?),
            }
        }
        Ok(json!({ "messages": messages }))
    }

    fn render_anthropic(&self) -> Result<Value> {
        let mut messages = Vec::new();
        for message in &self.messages {
            let mut content = Vec::new();
            for block in &message.blocks {
                match block {
                    Block::System { .. } => {}
                    Block::Text { text } => {
                        content.push(json!({ "type": "text", "text": text }));
                    }
                    Block::Image { media_type, data_b64 } => {
                        require_image(ProviderFormat::Anthropic, media_type)?;
                        content.push(json!({
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": media_type,
                                "data": data_b64,
                            },
                        }));
                    }
                    Block::ToolUse { id, name, arguments } => {
                        content.push(json!({
                            "type": "tool_use",
                            "id": id,
                            "name": name,
                            "input": arguments,
                        }));
                    }
                    Block::ToolResult { tool_use_id, content: value, is_error } => {
                        content.push(json!({
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": value_as_tool_text(value),
                            "is_error": is_error,
                        }));
                    }
                    Block::Thinking { text } => {
                        content.push(json!({ "type": "thinking", "thinking": text }));
                    }
                }
            }
            if !content.is_empty() {
                let role = match message.role {
                    MessageRole::User => "user",
                    MessageRole::Assistant => "assistant",
                };
                messages.push(json!({ "role": role, "content": content }));
            }
        }
        let mut root = Map::new();
        if let Some(system) = self.system_text() {
            root.insert("system".to_owned(), Value::String(system));
        }
        root.insert("messages".to_owned(), Value::Array(messages));
        Ok(Value::Object(root))
    }

    fn render_gemini(&self) -> Result<Value> {
        let mut names = BTreeMap::new();
        for message in &self.messages {
            for block in &message.blocks {
                if let Block::ToolUse { id, name, .. } = block {
                    names.insert(id.as_str(), name.as_str());
                }
            }
        }

        let mut contents = Vec::new();
        for message in &self.messages {
            let mut parts = Vec::new();
            for block in &message.blocks {
                match block {
                    Block::System { .. } => {}
                    Block::Text { text } => parts.push(json!({ "text": text })),
                    Block::Image { media_type, data_b64 } => {
                        require_image(ProviderFormat::Gemini, media_type)?;
                        parts.push(json!({
                            "inlineData": { "mimeType": media_type, "data": data_b64 },
                        }));
                    }
                    Block::ToolUse { name, arguments, .. } => {
                        parts.push(json!({
                            "functionCall": {
                                "name": name,
                                "args": gemini_args(arguments),
                            },
                        }));
                    }
                    Block::ToolResult { tool_use_id, content, is_error } => {
                        let name = names
                            .get(tool_use_id.as_str())
                            .copied()
                            .ok_or_else(|| protocol("tool_result does not match a tool_use"))?;
                        parts.push(json!({
                            "functionResponse": {
                                "name": name,
                                "response": gemini_response(content, *is_error),
                            },
                        }));
                    }
                    Block::Thinking { .. } => {
                        return Err(protocol(
                            "thinking blocks are not portable to gemini; translate before rendering",
                        ));
                    }
                }
            }
            if !parts.is_empty() {
                let role = match message.role {
                    MessageRole::User => "user",
                    MessageRole::Assistant => "model",
                };
                contents.push(json!({ "role": role, "parts": parts }));
            }
        }

        let mut root = Map::new();
        if let Some(system) = self.system_text() {
            root.insert(
                "systemInstruction".to_owned(),
                json!({ "parts": [{ "text": system }] }),
            );
        }
        root.insert("contents".to_owned(), Value::Array(contents));
        Ok(Value::Object(root))
    }
}

/// A provider wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFormat {
    #[serde(rename = "openai")]
    OpenAi,
    Anthropic,
    Gemini,
}

impl ProviderFormat {
    /// Every provider format, in declaration order.
    pub const ALL: [ProviderFormat; 3] =
        [ProviderFormat::OpenAi, ProviderFormat::Anthropic, ProviderFormat::Gemini];

    /// Stable wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            ProviderFormat::OpenAi => "openai",
            ProviderFormat::Anthropic => "anthropic",
            ProviderFormat::Gemini => "gemini",
        }
    }

    /// Parse a stable label, case-insensitively. `google` is accepted as an
    /// alias for Gemini because the provider id in the pool is `google`.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "openai" | "open_ai" => Some(ProviderFormat::OpenAi),
            "anthropic" => Some(ProviderFormat::Anthropic),
            "gemini" | "google" => Some(ProviderFormat::Gemini),
            _ => None,
        }
    }

    /// True when the format carries a portable reasoning block.
    pub const fn supports_thinking(self) -> bool {
        matches!(self, ProviderFormat::Anthropic)
    }

    /// How the target places the canonical system slot.
    pub const fn system_placement(self) -> &'static str {
        match self {
            ProviderFormat::OpenAi => "a leading system message",
            ProviderFormat::Anthropic => "the separate system parameter",
            ProviderFormat::Gemini => "the systemInstruction field",
        }
    }

    /// Conservative id length bound for this format.
    const fn id_max(self) -> usize {
        match self {
            ProviderFormat::OpenAi => OPENAI_TOOL_ID_MAX,
            ProviderFormat::Anthropic => ANTHROPIC_TOOL_ID_MAX,
            ProviderFormat::Gemini => 64,
        }
    }
}

impl std::fmt::Display for ProviderFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Target capabilities that can narrow what a translation keeps.
///
/// All three built-in formats support images, so the default from
/// [`TargetCapabilities::for_format`] keeps them. A test or a text-only adapter
/// can pass [`TargetCapabilities::text_only`] to drop every image with a
/// recorded reason. Thinking is additionally clamped to the target: a caller
/// cannot ask for thinking on a format that has no reasoning block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetCapabilities {
    pub images: bool,
    pub thinking: bool,
}

impl TargetCapabilities {
    /// The full capabilities of a built-in format.
    pub const fn for_format(format: ProviderFormat) -> Self {
        Self { images: true, thinking: format.supports_thinking() }
    }

    /// A text-only target: no images, no thinking.
    pub const fn text_only() -> Self {
        Self { images: false, thinking: false }
    }
}

/// One block that the target could not carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DroppedBlock {
    /// Zero-based flattened block position in the input transcript.
    pub index: usize,
    /// Stable block kind, e.g. `thinking` or `image`.
    pub kind: String,
    /// Why this block was dropped, naming the target and the constraint.
    pub reason: String,
}

/// What changed during a translation.
///
/// `dropped` is the lossy part; `remapped_ids` records every id that changed
/// shape so a caller can apply the same mapping to a tool result that arrives
/// after the translation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranslationReport {
    pub dropped: Vec<DroppedBlock>,
    pub remapped_ids: Vec<(String, String)>,
    pub notes: Vec<String>,
}

impl TranslationReport {
    /// True when no block was dropped. Id remapping is not loss: both sides of
    /// the pairing were rewritten consistently.
    pub fn is_lossless(&self) -> bool {
        self.dropped.is_empty()
    }

    /// The new id for `old`, or `None` when the id was preserved.
    ///
    /// Use this to rewrite a tool result that arrives after an escalation:
    /// `None` means the old id is still valid in the translated transcript.
    pub fn mapped_id<'a>(&'a self, old: &str) -> Option<&'a str> {
        self.remapped_ids
            .iter()
            .find(|(from, _)| from == old)
            .map(|(_, to)| to.as_str())
    }
}

/// A translated transcript plus its change report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Translation {
    pub transcript: Transcript,
    pub report: TranslationReport,
}

/// Translate a canonical transcript from one provider format to another.
///
/// `from` names the source format for the report; the input is already a
/// provider-neutral [`Transcript`]. `to` decides the id shape, system
/// placement, and which blocks are portable. Every dropped block and remapped
/// id is recorded in [`TranslationReport`].
pub fn translate(
    transcript: &Transcript,
    from: ProviderFormat,
    to: ProviderFormat,
) -> Result<Translation> {
    translate_with_capabilities(transcript, from, to, TargetCapabilities::for_format(to))
}

/// Translate with an explicit, narrower target capability set.
///
/// Capabilities can only narrow the target: thinking is always clamped to
/// [`ProviderFormat::supports_thinking`]. Images are dropped with a reason when
/// `capabilities.images` is false. Tool use and tool result are never dropped.
pub fn translate_with_capabilities(
    transcript: &Transcript,
    from: ProviderFormat,
    to: ProviderFormat,
    capabilities: TargetCapabilities,
) -> Result<Translation> {
    transcript.validate()?;

    let capabilities = TargetCapabilities {
        images: capabilities.images,
        thinking: capabilities.thinking && to.supports_thinking(),
    };

    // Assign every tool id in transcript order so a tool_use and its result
    // always receive the same new id.
    let mut mapper = IdMapper::new(to);
    let mut id_map: BTreeMap<String, String> = BTreeMap::new();
    let mut name_ordinals: BTreeMap<String, usize> = BTreeMap::new();
    let mut remapped_ids = Vec::new();
    for message in &transcript.messages {
        for block in &message.blocks {
            if let Block::ToolUse { id, name, .. } = block {
                let ordinal = name_ordinals.entry(name.clone()).or_insert(0);
                *ordinal += 1;
                let new_id = mapper.assign(id, name, *ordinal);
                if new_id != *id {
                    remapped_ids.push((id.clone(), new_id.clone()));
                }
                id_map.insert(id.clone(), new_id);
            }
        }
    }

    let mut dropped = Vec::new();
    let mut system_parts = Vec::new();
    let mut output = Vec::new();
    let mut index = 0usize;

    for message in &transcript.messages {
        let mut blocks = Vec::new();
        for block in &message.blocks {
            match block {
                Block::System { text } => {
                    if !text.is_empty() {
                        system_parts.push(text.clone());
                    }
                }
                Block::Text { text } => blocks.push(Block::Text { text: text.clone() }),
                Block::ToolUse { id, name, arguments } => {
                    let new_id = id_map
                        .get(id)
                        .ok_or_else(|| protocol("tool_use id was not assigned a target id"))?;
                    blocks.push(Block::ToolUse {
                        id: new_id.clone(),
                        name: name.clone(),
                        arguments: arguments.clone(),
                    });
                }
                Block::ToolResult { tool_use_id, content, is_error } => {
                    let new_id = id_map.get(tool_use_id).ok_or_else(|| {
                        protocol("tool_result does not match a preceding tool_use")
                    })?;
                    blocks.push(Block::ToolResult {
                        tool_use_id: new_id.clone(),
                        content: content.clone(),
                        is_error: *is_error,
                    });
                }
                Block::Image { media_type, data_b64 } => {
                    if !capabilities.images {
                        dropped.push(DroppedBlock {
                            index,
                            kind: block.kind().to_owned(),
                            reason: format!(
                                "images are not supported by the target capabilities for {}",
                                to.as_str()
                            ),
                        });
                    } else if !image_supported(to, media_type) {
                        dropped.push(DroppedBlock {
                            index,
                            kind: block.kind().to_owned(),
                            reason: format!(
                                "image media type {:?} is not accepted by {}",
                                base_media_type(media_type),
                                to.as_str()
                            ),
                        });
                    } else {
                        blocks.push(Block::Image {
                            media_type: media_type.clone(),
                            data_b64: data_b64.clone(),
                        });
                    }
                }
                Block::Thinking { text } => {
                    if capabilities.thinking {
                        blocks.push(Block::Thinking { text: text.clone() });
                    } else {
                        let reason = if to.supports_thinking() {
                            format!(
                                "thinking blocks are disabled by the target capabilities for {}",
                                to.as_str()
                            )
                        } else {
                            format!(
                                "thinking blocks are not portable to {} because the target has no reasoning block",
                                to.as_str()
                            )
                        };
                        dropped.push(DroppedBlock {
                            index,
                            kind: block.kind().to_owned(),
                            reason,
                        });
                    }
                }
            }
            index += 1;
        }
        if !blocks.is_empty() {
            output.push(Message { role: message.role, blocks });
        }
    }

    if !system_parts.is_empty() {
        output.insert(
            0,
            Message {
                role: MessageRole::User,
                blocks: vec![Block::System { text: system_parts.join("\n\n") }],
            },
        );
    }

    let mut notes = Vec::new();
    notes.push(format!("translation: {} -> {}", from.as_str(), to.as_str()));
    if !system_parts.is_empty() {
        notes.push(format!(
            "system: merged {} non-empty system block(s) into the leading slot for {} ({})",
            system_parts.len(),
            to.as_str(),
            to.system_placement()
        ));
    }
    if !dropped.is_empty() {
        let kinds: Vec<&str> = dropped.iter().map(|drop| drop.kind.as_str()).collect();
        notes.push(format!(
            "dropped {} non-portable block(s): {}",
            dropped.len(),
            kinds.join(", ")
        ));
    }
    if !remapped_ids.is_empty() {
        notes.push(format!(
            "remapped {} tool id(s) to the {} shape",
            remapped_ids.len(),
            to.as_str()
        ));
    }
    if to != ProviderFormat::Anthropic && has_error_result(transcript) {
        notes.push(format!(
            "{} has no tool_result error flag; is_error is preserved in the canonical block and rendered into the tool content",
            to.as_str()
        ));
    }
    if to == ProviderFormat::Gemini && has_duplicate_tool_names(transcript) {
        notes.push(
            "gemini pairs functionResponse by function name; repeated calls to one function rely on transcript order"
                .to_owned(),
        );
    }
    if to == ProviderFormat::Anthropic
        && capabilities.thinking
        && has_thinking(transcript)
    {
        notes.push(
            "thinking: text preserved; the provider signature is not represented in the canonical block"
                .to_owned(),
        );
    }

    let translated = Transcript::new(output)?;
    Ok(Translation {
        transcript: translated,
        report: TranslationReport { dropped, remapped_ids, notes },
    })
}

/// Translate for an escalation that happens mid-task (T-MDL-05 Done).
///
/// This is [`translate`] plus an explicit pairing audit of the output and an
/// escalation note. A pending tool use is kept, and every tool result still
/// points at its tool use. When the target remaps ids, the report's
/// `remapped_ids` / [`TranslationReport::mapped_id`] give the caller the new id
/// to apply to a result that arrives after the switch.
pub fn translate_for_escalation(
    transcript: &Transcript,
    from: ProviderFormat,
    to: ProviderFormat,
) -> Result<Translation> {
    let mut translation = translate(transcript, from, to)?;

    let mut seen = BTreeSet::new();
    for message in &translation.transcript.messages {
        for block in &message.blocks {
            match block {
                Block::ToolUse { id, .. } => {
                    seen.insert(id.clone());
                }
                Block::ToolResult { tool_use_id, .. } if !seen.contains(tool_use_id) => {
                    return Err(protocol(
                        "escalation translation produced an unpaired tool_result",
                    ));
                }
                _ => {}
            }
        }
    }

    if translation.report.remapped_ids.is_empty() {
        translation.report.notes.push(format!(
            "escalation: {} -> {} preserved {} tool id(s); every tool_result still matches its tool_use",
            from.as_str(),
            to.as_str(),
            translation.transcript.tool_ids.len()
        ));
    } else {
        translation.report.notes.push(format!(
            "escalation: {} -> {} remapped {} tool id(s) consistently; apply the remapping to any in-flight tool_result",
            from.as_str(),
            to.as_str(),
            translation.report.remapped_ids.len()
        ));
    }
    if !translation.report.dropped.is_empty() {
        translation.report.notes.push(format!(
            "escalation: dropped {} non-portable block(s); every tool_use and tool_result was kept",
            translation.report.dropped.len()
        ));
    }

    Ok(translation)
}

/// Assigns target ids deterministically.
struct IdMapper {
    format: ProviderFormat,
    used: BTreeSet<String>,
}

impl IdMapper {
    fn new(format: ProviderFormat) -> Self {
        Self { format, used: BTreeSet::new() }
    }

    fn assign(&mut self, old: &str, name: &str, ordinal: usize) -> String {
        let candidate = match self.format {
            ProviderFormat::Gemini => {
                format!("{}__{ordinal}", gemini_name(name))
            }
            ProviderFormat::OpenAi => {
                if is_valid_id(old, OPENAI_TOOL_ID_MAX) {
                    old.to_owned()
                } else {
                    make_id("call", old, OPENAI_TOOL_ID_MAX)
                }
            }
            ProviderFormat::Anthropic => {
                if is_valid_id(old, ANTHROPIC_TOOL_ID_MAX) {
                    old.to_owned()
                } else {
                    make_id("call", old, ANTHROPIC_TOOL_ID_MAX)
                }
            }
        };
        let unique = self.unique(candidate);
        self.used.insert(unique.clone());
        unique
    }

    fn unique(&self, candidate: String) -> String {
        if !self.used.contains(&candidate) {
            return candidate;
        }
        // Never truncate below the candidate itself; only the suffix needs room.
        let max = self.format.id_max().max(candidate.len());
        for suffix in 2u32.. {
            let suffix = format!("_{suffix}");
            let keep = max.saturating_sub(suffix.len());
            let mut base = candidate.clone();
            truncate_ascii(&mut base, keep);
            let next = format!("{base}{suffix}");
            if !self.used.contains(&next) {
                return next;
            }
        }
        unreachable!("the suffix space is unbounded")
    }
}

/// Validate every block and return the set of tool-use ids.
fn validate_messages(messages: &[Message]) -> Result<BTreeSet<String>> {
    let mut tool_ids = BTreeSet::new();
    let mut results = BTreeSet::new();
    let mut index = 0usize;

    for message in messages {
        for block in &message.blocks {
            match block {
                Block::Text { text } | Block::System { text } | Block::Thinking { text } => {
                    if text.len() > MAX_TEXT_BYTES {
                        return Err(oversized(
                            "text block",
                            index,
                            text.len(),
                            MAX_TEXT_BYTES,
                        ));
                    }
                }
                Block::Image { media_type, data_b64 } => {
                    validate_image(index, media_type, data_b64)?;
                }
                Block::ToolUse { id, name, arguments } => {
                    if message.role != MessageRole::Assistant {
                        return Err(protocol(format!(
                            "tool_use at block {index} must be in an assistant message"
                        )));
                    }
                    validate_tool_id(index, id)?;
                    validate_tool_name(index, name)?;
                    validate_value_size(
                        "tool_use arguments",
                        index,
                        arguments,
                        MAX_TOOL_ARGUMENT_BYTES,
                    )?;
                    if !tool_ids.insert(id.clone()) {
                        return Err(protocol(format!(
                            "duplicate tool_use id at block {index}"
                        )));
                    }
                }
                Block::ToolResult { tool_use_id, content, .. } => {
                    if message.role != MessageRole::User {
                        return Err(protocol(format!(
                            "tool_result at block {index} must be in a user message"
                        )));
                    }
                    if !tool_ids.contains(tool_use_id) {
                        return Err(protocol(format!(
                            "tool_result at block {index} does not reference a preceding tool_use"
                        )));
                    }
                    if !results.insert(tool_use_id.clone()) {
                        return Err(protocol(format!(
                            "tool_result at block {index} repeats a tool_use that already has a result"
                        )));
                    }
                    validate_value_size(
                        "tool_result content",
                        index,
                        content,
                        MAX_TOOL_CONTENT_BYTES,
                    )?;
                }
            }
            index += 1;
        }
    }
    Ok(tool_ids)
}

fn validate_tool_id(index: usize, id: &str) -> Result<()> {
    if id.trim().is_empty() {
        return Err(invalid(format!("tool_use id at block {index} is empty")));
    }
    if id.len() > MAX_TOOL_ID_BYTES {
        return Err(oversized("tool_use id", index, id.len(), MAX_TOOL_ID_BYTES));
    }
    if id.chars().any(|character| character.is_control()) {
        return Err(invalid(format!(
            "tool_use id at block {index} contains a control character"
        )));
    }
    Ok(())
}

fn validate_tool_name(index: usize, name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(invalid(format!("tool name at block {index} is empty")));
    }
    if name.len() > MAX_TOOL_NAME_BYTES {
        return Err(oversized(
            "tool name",
            index,
            name.len(),
            MAX_TOOL_NAME_BYTES,
        ));
    }
    if name.chars().any(|character| character.is_control()) {
        return Err(invalid(format!(
            "tool name at block {index} contains a control character"
        )));
    }
    Ok(())
}

fn validate_value_size(what: &str, index: usize, value: &Value, max: usize) -> Result<()> {
    let len = value.to_string().len();
    if len > max {
        Err(oversized(what, index, len, max))
    } else {
        Ok(())
    }
}

fn validate_image(index: usize, media_type: &str, data_b64: &str) -> Result<()> {
    let media = media_type.trim();
    if media.is_empty() {
        return Err(invalid(format!("image media type at block {index} is empty")));
    }
    if media.len() > MAX_MEDIA_TYPE_BYTES {
        return Err(oversized(
            "image media type",
            index,
            media.len(),
            MAX_MEDIA_TYPE_BYTES,
        ));
    }
    if media.chars().any(|character| character.is_control()) {
        return Err(invalid(format!(
            "image media type at block {index} contains a control character"
        )));
    }
    if !base_media_type(media).starts_with("image/") {
        return Err(invalid(format!(
            "image media type at block {index} must be an image/* type"
        )));
    }
    if data_b64.is_empty() {
        return Err(invalid(format!("image data at block {index} is empty")));
    }
    if data_b64.len() > MAX_IMAGE_B64_BYTES {
        return Err(oversized(
            "image data",
            index,
            data_b64.len(),
            MAX_IMAGE_B64_BYTES,
        ));
    }
    if !data_b64
        .chars()
        .all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '/' | '=' | '-' | '_')
        })
    {
        return Err(invalid(format!(
            "image data at block {index} is not base64 text"
        )));
    }
    Ok(())
}

fn oversized(what: &str, index: usize, len: usize, max: usize) -> ZeroError {
    ZeroError::new(
        ErrorCode::LimitExceeded,
        format!("{what} at block {index} is {len} bytes; the limit is {max}"),
    )
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn protocol(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::ProviderProtocol, message)
}

fn is_valid_id(id: &str, max: usize) -> bool {
    !id.is_empty()
        && id.len() <= max
        && id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

fn make_id(prefix: &str, old: &str, max: usize) -> String {
    let mut id = String::with_capacity(max);
    id.push_str(prefix);
    id.push('_');
    for character in old.chars() {
        if id.len() >= max {
            break;
        }
        id.push(if character.is_ascii_alphanumeric() {
            character
        } else {
            '_'
        });
    }
    if id.len() == prefix.len() + 1 {
        id.push('x');
    }
    truncate_ascii(&mut id, max);
    id
}

fn gemini_name(name: &str) -> String {
    let mut out = String::new();
    for character in name.chars() {
        if out.len() >= 48 {
            break;
        }
        if character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '-') {
            out.push(character);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("tool");
    }
    let first = out.chars().next().unwrap_or('_');
    if !(first.is_ascii_alphabetic() || first == '_') {
        out.insert(0, '_');
    }
    out
}

fn truncate_ascii(value: &mut String, max: usize) {
    if value.len() > max {
        value.truncate(max);
    }
}

fn base_media_type(media_type: &str) -> String {
    media_type
        .split(';')
        .next()
        .unwrap_or(media_type)
        .trim()
        .to_ascii_lowercase()
}

fn image_supported(format: ProviderFormat, media_type: &str) -> bool {
    let media = base_media_type(media_type);
    let supported = match format {
        ProviderFormat::OpenAi => OPENAI_IMAGE_TYPES,
        ProviderFormat::Anthropic => ANTHROPIC_IMAGE_TYPES,
        ProviderFormat::Gemini => GEMINI_IMAGE_TYPES,
    };
    supported.contains(&media.as_str())
}

fn require_image(format: ProviderFormat, media_type: &str) -> Result<()> {
    if image_supported(format, media_type) {
        Ok(())
    } else {
        Err(protocol(format!(
            "image media type {:?} is not portable to {}; translate before rendering",
            base_media_type(media_type),
            format.as_str()
        )))
    }
}

fn render_openai_assistant(message: &Message) -> Result<Option<Value>> {
    let mut parts = Vec::new();
    let mut has_image = false;
    let mut tool_calls = Vec::new();
    for block in &message.blocks {
        match block {
            Block::Text { text } => parts.push(json!({ "type": "text", "text": text })),
            Block::Image { media_type, data_b64 } => {
                require_image(ProviderFormat::OpenAi, media_type)?;
                has_image = true;
                parts.push(json!({
                    "type": "image_url",
                    "image_url": { "url": format!("data:{media_type};base64,{data_b64}") },
                }));
            }
            Block::ToolUse { id, name, arguments } => tool_calls.push(json!({
                "id": id,
                "type": "function",
                "function": { "name": name, "arguments": arguments.to_string() },
            })),
            Block::System { .. } => {}
            Block::Thinking { .. } => {
                return Err(protocol(
                    "thinking blocks are not portable to openai; translate before rendering",
                ));
            }
            Block::ToolResult { .. } => {
                return Err(protocol("tool_result is not valid in an assistant message"));
            }
        }
    }
    if parts.is_empty() && tool_calls.is_empty() {
        return Ok(None);
    }

    let mut object = Map::new();
    object.insert("role".to_owned(), Value::String("assistant".to_owned()));
    if parts.is_empty() {
        object.insert("content".to_owned(), Value::Null);
    } else {
        object.insert("content".to_owned(), openai_content(parts, has_image));
    }
    if !tool_calls.is_empty() {
        object.insert("tool_calls".to_owned(), Value::Array(tool_calls));
    }
    Ok(Some(Value::Object(object)))
}

fn render_openai_user(message: &Message) -> Result<Vec<Value>> {
    let mut parts = Vec::new();
    let mut has_image = false;
    let mut tools = Vec::new();
    for block in &message.blocks {
        match block {
            Block::Text { text } => parts.push(json!({ "type": "text", "text": text })),
            Block::Image { media_type, data_b64 } => {
                require_image(ProviderFormat::OpenAi, media_type)?;
                has_image = true;
                parts.push(json!({
                    "type": "image_url",
                    "image_url": { "url": format!("data:{media_type};base64,{data_b64}") },
                }));
            }
            Block::ToolResult { tool_use_id, content, is_error } => {
                tools.push(json!({
                    "role": "tool",
                    "tool_call_id": tool_use_id,
                    "content": openai_tool_content(content, *is_error),
                }));
            }
            Block::System { .. } => {}
            Block::Thinking { .. } => {
                return Err(protocol(
                    "thinking blocks are not portable to openai; translate before rendering",
                ));
            }
            Block::ToolUse { .. } => {
                return Err(protocol("tool_use is not valid in a user message"));
            }
        }
    }

    let mut messages = tools;
    if !parts.is_empty() {
        messages.push(json!({ "role": "user", "content": openai_content(parts, has_image) }));
    }
    Ok(messages)
}

/// OpenAI accepts a plain string for text-only content and an array of parts
/// when an image is present. Keeping text-only messages as strings is the most
/// widely accepted shape.
fn openai_content(parts: Vec<Value>, has_image: bool) -> Value {
    if has_image {
        Value::Array(parts)
    } else {
        let text = parts
            .iter()
            .filter_map(|part| part.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n");
        Value::String(text)
    }
}

fn openai_tool_content(content: &Value, is_error: bool) -> String {
    if is_error {
        json!({ "is_error": true, "content": content }).to_string()
    } else {
        value_as_tool_text(content)
    }
}

fn value_as_tool_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn gemini_args(arguments: &Value) -> Value {
    match arguments {
        Value::Object(_) => arguments.clone(),
        other => json!({ "value": other }),
    }
}

fn gemini_response(content: &Value, is_error: bool) -> Value {
    let mut response = match content {
        Value::Object(map) => map.clone(),
        other => {
            let mut map = Map::new();
            map.insert("content".to_owned(), other.clone());
            map
        }
    };
    if is_error {
        response.insert("error".to_owned(), Value::Bool(true));
    }
    Value::Object(response)
}

fn has_error_result(transcript: &Transcript) -> bool {
    transcript
        .messages
        .iter()
        .flat_map(|message| message.blocks.iter())
        .any(|block| matches!(block, Block::ToolResult { is_error: true, .. }))
}

fn has_thinking(transcript: &Transcript) -> bool {
    transcript
        .messages
        .iter()
        .flat_map(|message| message.blocks.iter())
        .any(|block| matches!(block, Block::Thinking { .. }))
}

fn has_duplicate_tool_names(transcript: &Transcript) -> bool {
    let mut names = BTreeSet::new();
    transcript
        .messages
        .iter()
        .flat_map(|message| message.blocks.iter())
        .any(|block| match block {
            Block::ToolUse { name, .. } => !names.insert(name.as_str()),
            _ => false,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "TOP-SECRET-PLACEHOLDER-abc123";

    fn transcript(messages: Vec<Message>) -> Transcript {
        Transcript::new(messages).expect("valid transcript")
    }

    fn rich(with_thinking: bool) -> Transcript {
        let mut assistant = vec![Block::text("Searching the workspace.")];
        if with_thinking {
            assistant.insert(0, Block::thinking("I should look for config.toml."));
        }
        assistant.push(Block::tool_use(
            "call_1",
            "search",
            json!({ "query": "config.toml" }),
        ));
        transcript(vec![
            Message::user(vec![Block::system("You are a careful assistant.")]),
            Message::user(vec![
                Block::text("Find the file config.toml."),
                Block::image("image/png", "iVBORw0KGgoAAAANSUhEUg=="),
            ]),
            Message::assistant(assistant),
            Message::user(vec![Block::tool_result(
                "call_1",
                json!({ "path": "/tmp/config.toml" }),
                false,
            )]),
            Message::assistant(vec![Block::text("Found it.")]),
        ])
    }

    fn assert_pairing(transcript: &Transcript) {
        let mut seen = BTreeSet::new();
        let mut results = BTreeSet::new();
        for message in &transcript.messages {
            for block in &message.blocks {
                match block {
                    Block::ToolUse { id, .. } => {
                        assert!(seen.insert(id.clone()), "duplicate tool_use id {id}");
                    }
                    Block::ToolResult { tool_use_id, .. } => {
                        assert!(
                            seen.contains(tool_use_id),
                            "orphan tool_result for {tool_use_id}"
                        );
                        assert!(
                            results.insert(tool_use_id.clone()),
                            "repeated tool_result for {tool_use_id}"
                        );
                    }
                    _ => {}
                }
            }
        }
        assert_eq!(seen, transcript.tool_ids);
    }

    fn non_system_roles(transcript: &Transcript) -> Vec<MessageRole> {
        transcript
            .messages
            .iter()
            .filter(|message| {
                !message
                    .blocks
                    .iter()
                    .all(|block| matches!(block, Block::System { .. }))
            })
            .map(|message| message.role)
            .collect()
    }

    fn texts(transcript: &Transcript) -> Vec<&str> {
        transcript
            .messages
            .iter()
            .flat_map(|message| message.blocks.iter())
            .filter_map(|block| match block {
                Block::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }

    fn tool_pairs(transcript: &Transcript) -> Vec<(String, String)> {
        transcript
            .messages
            .iter()
            .flat_map(|message| message.blocks.iter())
            .filter_map(|block| match block {
                Block::ToolUse { id, name, .. } => Some((id.clone(), name.clone())),
                _ => None,
            })
            .collect()
    }

    fn tool_result_ids(transcript: &Transcript) -> Vec<String> {
        transcript
            .messages
            .iter()
            .flat_map(|message| message.blocks.iter())
            .filter_map(|block| match block {
                Block::ToolResult { tool_use_id, .. } => Some(tool_use_id.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn every_provider_pair_preserves_text_roles_tool_pairing_and_images() {
        let input = rich(false);
        let expected_roles =
            vec![MessageRole::User, MessageRole::Assistant, MessageRole::User, MessageRole::Assistant];
        let expected_texts =
            vec!["Find the file config.toml.", "Searching the workspace.", "Found it."];

        for from in ProviderFormat::ALL {
            for to in ProviderFormat::ALL {
                let translated = translate(&input, from, to).expect("translation succeeds");
                assert_pairing(&translated.transcript);
                assert_eq!(non_system_roles(&translated.transcript), expected_roles);
                assert_eq!(texts(&translated.transcript), expected_texts);
                assert_eq!(
                    translated.transcript.system_text().as_deref(),
                    Some("You are a careful assistant.")
                );
                let expected_id = if to == ProviderFormat::Gemini {
                    translated
                        .report
                        .mapped_id("call_1")
                        .expect("gemini remaps the id")
                        .to_owned()
                } else {
                    "call_1".to_owned()
                };
                assert_eq!(
                    tool_pairs(&translated.transcript),
                    vec![(expected_id.clone(), "search".to_owned())]
                );
                assert_eq!(tool_result_ids(&translated.transcript), vec![expected_id]);
                assert!(translated.report.dropped.is_empty(), "{from}->{to} dropped a portable block");
                if to == ProviderFormat::Gemini {
                    assert_eq!(translated.report.remapped_ids.len(), 1, "{from}->gemini remaps");
                } else {
                    assert!(translated.report.remapped_ids.is_empty(), "{from}->{to} keeps valid ids");
                }
                let images: Vec<&str> = translated
                    .transcript
                    .messages
                    .iter()
                    .flat_map(|message| message.blocks.iter())
                    .filter_map(|block| match block {
                        Block::Image { data_b64, .. } => Some(data_b64.as_str()),
                        _ => None,
                    })
                    .collect();
                assert_eq!(images, vec!["iVBORw0KGgoAAAANSUhEUg=="]);
            }
        }
    }

    #[test]
    fn system_is_hoisted_and_merged_for_every_target() {
        let input = transcript(vec![
            Message::user(vec![Block::system("one"), Block::text("hello")]),
            Message::assistant(vec![Block::text("hi")]),
            Message::user(vec![Block::system("two")]),
        ]);

        for to in ProviderFormat::ALL {
            let translated = translate(&input, ProviderFormat::OpenAi, to).expect("translation");
            let first = &translated.transcript.messages[0];
            assert_eq!(first.role, MessageRole::User);
            assert_eq!(first.blocks.len(), 1);
            assert_eq!(first.blocks[0], Block::System { text: "one\n\ntwo".to_owned() });
            assert_eq!(translated.transcript.system_text().as_deref(), Some("one\n\ntwo"));
            assert!(
                translated.report.notes.iter().any(|note| {
                    note.starts_with("system:") && note.contains(to.as_str())
                }),
                "{to}: {:?}",
                translated.report.notes
            );

            let wire = translated.transcript.render(to).expect("render");
            match to {
                ProviderFormat::OpenAi => {
                    assert_eq!(wire["messages"][0]["role"], "system");
                    assert_eq!(wire["messages"][0]["content"], "one\n\ntwo");
                }
                ProviderFormat::Anthropic => {
                    assert_eq!(wire["system"], "one\n\ntwo");
                }
                ProviderFormat::Gemini => {
                    assert_eq!(wire["systemInstruction"]["parts"][0]["text"], "one\n\ntwo");
                }
            }
        }
    }

    #[test]
    fn openai_render_uses_system_tool_calls_and_tool_messages() {
        let translated =
            translate(&rich(false), ProviderFormat::Anthropic, ProviderFormat::OpenAi)
                .expect("translation");
        let wire = translated.transcript.render(ProviderFormat::OpenAi).expect("render");

        assert_eq!(wire["messages"][0]["role"], "system");
        assert_eq!(wire["messages"][0]["content"], "You are a careful assistant.");

        let assistant = wire["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|message| message["role"] == "assistant" && message.get("tool_calls").is_some())
            .expect("assistant tool-call message");
        let call = &assistant["tool_calls"][0];
        assert_eq!(call["id"], "call_1");
        assert_eq!(call["type"], "function");
        assert_eq!(call["function"]["name"], "search");
        assert_eq!(assistant["content"], "Searching the workspace.");
        assert!(
            call["function"]["arguments"]
                .as_str()
                .unwrap()
                .contains("config.toml")
        );

        let tool = wire["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|message| message["role"] == "tool")
            .expect("tool message");
        assert_eq!(tool["tool_call_id"], "call_1");
        assert!(tool["content"].as_str().unwrap().contains("/tmp/config.toml"));

        let image = wire["messages"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|message| message["content"].as_array().cloned().unwrap_or_default())
            .find(|part| part["type"] == "image_url")
            .expect("image part");
        assert!(
            image["image_url"]["url"]
                .as_str()
                .unwrap()
                .starts_with("data:image/png;base64,")
        );
    }

    #[test]
    fn anthropic_render_uses_tool_use_and_tool_result_blocks() {
        let translated =
            translate(&rich(false), ProviderFormat::OpenAi, ProviderFormat::Anthropic)
                .expect("translation");
        let wire = translated
            .transcript
            .render(ProviderFormat::Anthropic)
            .expect("render");

        assert_eq!(wire["system"], "You are a careful assistant.");
        let tool_use = wire["messages"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|message| message["content"].as_array().cloned().unwrap_or_default())
            .find(|block| block["type"] == "tool_use")
            .expect("tool_use block");
        assert_eq!(tool_use["id"], "call_1");
        assert_eq!(tool_use["name"], "search");
        assert_eq!(tool_use["input"]["query"], "config.toml");

        let tool_result = wire["messages"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|message| message["content"].as_array().cloned().unwrap_or_default())
            .find(|block| block["type"] == "tool_result")
            .expect("tool_result block");
        assert_eq!(tool_result["tool_use_id"], "call_1");
        assert_eq!(tool_result["is_error"], false);
        assert!(tool_result["content"].as_str().unwrap().contains("/tmp/config.toml"));

        let image = wire["messages"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|message| message["content"].as_array().cloned().unwrap_or_default())
            .find(|block| block["type"] == "image")
            .expect("image block");
        assert_eq!(image["source"]["type"], "base64");
        assert_eq!(image["source"]["media_type"], "image/png");
        assert_eq!(image["source"]["data"], "iVBORw0KGgoAAAANSUhEUg==");
    }

    #[test]
    fn gemini_render_uses_function_call_and_response() {
        let translated =
            translate(&rich(false), ProviderFormat::Anthropic, ProviderFormat::Gemini)
                .expect("translation");
        let wire = translated
            .transcript
            .render(ProviderFormat::Gemini)
            .expect("render");

        assert_eq!(
            wire["systemInstruction"]["parts"][0]["text"],
            "You are a careful assistant."
        );
        let call = wire["contents"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|content| content["parts"].as_array().cloned().unwrap_or_default())
            .find(|part| part.get("functionCall").is_some())
            .expect("functionCall part");
        assert_eq!(call["functionCall"]["name"], "search");
        assert_eq!(call["functionCall"]["args"]["query"], "config.toml");

        let response = wire["contents"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|content| content["parts"].as_array().cloned().unwrap_or_default())
            .find(|part| part.get("functionResponse").is_some())
            .expect("functionResponse part");
        assert_eq!(response["functionResponse"]["name"], "search");
        assert!(response["functionResponse"]["response"]["path"]
            .as_str()
            .unwrap()
            .contains("config.toml"));

        let image = wire["contents"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|content| content["parts"].as_array().cloned().unwrap_or_default())
            .find(|part| part.get("inlineData").is_some())
            .expect("inlineData part");
        assert_eq!(image["inlineData"]["mimeType"], "image/png");
        assert_eq!(image["inlineData"]["data"], "iVBORw0KGgoAAAANSUhEUg==");

        let new_id = translated.report.mapped_id("call_1").expect("gemini remaps");
        assert_eq!(tool_pairs(&translated.transcript), vec![(new_id.to_owned(), "search".to_owned())]);
        assert_eq!(tool_result_ids(&translated.transcript), vec![new_id.to_owned()]);
        assert_pairing(&translated.transcript);
    }

    #[test]
    fn thinking_is_dropped_for_targets_without_it_with_a_reason() {
        let input = rich(true);

        for target in [ProviderFormat::OpenAi, ProviderFormat::Gemini] {
            let translated = translate(&input, ProviderFormat::Anthropic, target).expect("translate");
            assert_eq!(translated.report.dropped.len(), 1);
            let drop = &translated.report.dropped[0];
            assert_eq!(drop.kind, "thinking");
            assert!(drop.reason.contains(target.as_str()), "{}", drop.reason);
            assert!(!has_thinking(&translated.transcript));
            assert_pairing(&translated.transcript);
        }

        let preserved =
            translate(&input, ProviderFormat::Anthropic, ProviderFormat::Anthropic)
                .expect("same format");
        assert!(preserved.report.dropped.is_empty());
        assert!(has_thinking(&preserved.transcript));
        assert!(
            preserved
                .report
                .notes
                .iter()
                .any(|note| note.contains("signature")),
            "{:?}",
            preserved.report.notes
        );
    }

    #[test]
    fn images_are_portable_but_unsupported_media_types_are_dropped() {
        let png = transcript(vec![
            Message::user(vec![
                Block::text("look"),
                Block::image("image/png", "iVBORw0KGgoAAAANSUhEUg=="),
            ]),
            Message::assistant(vec![Block::text("ok")]),
        ]);
        for target in ProviderFormat::ALL {
            let translated = translate(&png, ProviderFormat::OpenAi, target).expect("translate");
            assert!(translated.report.dropped.is_empty(), "{target} drops a png");
            assert_eq!(texts(&translated.transcript), vec!["look", "ok"]);
        }

        let svg = transcript(vec![
            Message::user(vec![
                Block::text("look"),
                Block::image("image/svg+xml", "PHN2Zy8+"),
            ]),
            Message::assistant(vec![Block::text("ok")]),
        ]);
        let dropped = translate(&svg, ProviderFormat::OpenAi, ProviderFormat::Anthropic)
            .expect("translate");
        assert_eq!(dropped.report.dropped.len(), 1);
        assert_eq!(dropped.report.dropped[0].kind, "image");
        assert!(
            dropped.report.dropped[0].reason.contains("image/svg+xml")
                && dropped.report.dropped[0].reason.contains("anthropic"),
            "{}",
            dropped.report.dropped[0].reason
        );
        assert_eq!(texts(&dropped.transcript), vec!["look", "ok"]);
    }

    #[test]
    fn a_text_only_target_drops_images_and_thinking_with_reasons() {
        let translated = translate_with_capabilities(
            &rich(true),
            ProviderFormat::Anthropic,
            ProviderFormat::Anthropic,
            TargetCapabilities::text_only(),
        )
        .expect("translate");
        assert_eq!(translated.report.dropped.len(), 2);
        let image_drop = translated
            .report
            .dropped
            .iter()
            .find(|drop| drop.kind == "image")
            .expect("image drop");
        assert!(image_drop.reason.contains("images"));
        let thinking_drop = translated
            .report
            .dropped
            .iter()
            .find(|drop| drop.kind == "thinking")
            .expect("thinking drop");
        assert!(
            thinking_drop.reason.contains("disabled by the target capabilities"),
            "{}",
            thinking_drop.reason
        );
        assert_pairing(&translated.transcript);
        assert_eq!(texts(&translated.transcript), vec![
            "Find the file config.toml.",
            "Searching the workspace.",
            "Found it."
        ]);
    }

    #[test]
    fn tool_error_flags_are_preserved_and_projected_into_each_wire_shape() {
        let input = transcript(vec![
            Message::assistant(vec![Block::tool_use(
                "call_1",
                "read",
                json!({ "path": "missing.txt" }),
            )]),
            Message::user(vec![Block::tool_result(
                "call_1",
                json!({ "error": "not found" }),
                true,
            )]),
        ]);

        let openai = translate(&input, ProviderFormat::Anthropic, ProviderFormat::OpenAi)
            .expect("translate");
        assert!(
            openai
                .report
                .notes
                .iter()
                .any(|note| note.contains("error flag")),
            "{:?}",
            openai.report.notes
        );
        let wire = openai.transcript.render(ProviderFormat::OpenAi).expect("render");
        let content = wire["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|message| message["role"] == "tool")
            .expect("tool message")["content"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(content.contains("\"is_error\":true"), "{content}");

        let gemini = translate(&input, ProviderFormat::Anthropic, ProviderFormat::Gemini)
            .expect("translate");
        let wire = gemini.transcript.render(ProviderFormat::Gemini).expect("render");
        let response = wire["contents"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|content| content["parts"].as_array().cloned().unwrap_or_default())
            .find(|part| part.get("functionResponse").is_some())
            .expect("functionResponse");
        assert_eq!(response["functionResponse"]["response"]["error"], true);

        let back = translate(&gemini.transcript, ProviderFormat::Gemini, ProviderFormat::Anthropic)
            .expect("translate back");
        let block = back
            .transcript
            .messages
            .iter()
            .flat_map(|message| message.blocks.iter())
            .find(|block| matches!(block, Block::ToolResult { .. }))
            .expect("tool result");
        assert!(matches!(block, Block::ToolResult { is_error: true, .. }));
    }

    #[test]
    fn invalid_and_oversized_ids_are_remapped_for_openai_and_anthropic() {
        let spaced = transcript(vec![
            Message::assistant(vec![Block::tool_use(
                "call with spaces",
                "search",
                json!({ "query": "x" }),
            )]),
            Message::user(vec![Block::tool_result(
                "call with spaces",
                json!({ "ok": true }),
                false,
            )]),
        ]);
        for target in [ProviderFormat::OpenAi, ProviderFormat::Anthropic] {
            let translated = translate(&spaced, ProviderFormat::Gemini, target).expect("translate");
            assert_eq!(translated.report.remapped_ids.len(), 1);
            let new_id = translated
                .report
                .mapped_id("call with spaces")
                .expect("the non-portable id is remapped")
                .to_owned();
            assert!(new_id.starts_with("call_"), "{new_id}");
            assert!(new_id.len() <= target.id_max(), "{new_id}");
            assert_eq!(
                tool_pairs(&translated.transcript),
                vec![(new_id.clone(), "search".to_owned())]
            );
            assert_eq!(tool_result_ids(&translated.transcript), vec![new_id]);
            assert_pairing(&translated.transcript);
        }

        let long_id = "x".repeat(50);
        let long = transcript(vec![
            Message::assistant(vec![Block::tool_use(
                long_id.clone(),
                "read",
                json!({}),
            )]),
            Message::user(vec![Block::tool_result(
                long_id.clone(),
                json!({ "ok": true }),
                false,
            )]),
        ]);
        let openai = translate(&long, ProviderFormat::Anthropic, ProviderFormat::OpenAi)
            .expect("translate");
        let new_id = openai
            .report
            .mapped_id(&long_id)
            .expect("50 chars exceeds the OpenAI bound")
            .to_owned();
        assert!(new_id.len() <= OPENAI_TOOL_ID_MAX);
        assert_pairing(&openai.transcript);

        let anthropic = translate(&long, ProviderFormat::OpenAi, ProviderFormat::Anthropic)
            .expect("translate");
        assert!(anthropic.report.remapped_ids.is_empty());
        assert_eq!(
            tool_pairs(&anthropic.transcript),
            vec![(long_id, "read".to_owned())]
        );
    }

    #[test]
    fn gemini_remaps_ids_consistently_even_for_repeated_function_names() {
        let input = transcript(vec![
            Message::assistant(vec![
                Block::tool_use("first", "read", json!({ "path": "a" })),
                Block::tool_use("second", "read", json!({ "path": "b" })),
            ]),
            Message::user(vec![
                Block::tool_result("first", json!({ "content": "A" }), false),
                Block::tool_result("second", json!({ "content": "B" }), false),
            ]),
        ]);

        let translated =
            translate(&input, ProviderFormat::Anthropic, ProviderFormat::Gemini).expect("translate");
        assert_eq!(translated.report.remapped_ids.len(), 2);
        assert_eq!(
            translated.report.mapped_id("first"),
            Some("read__1")
        );
        assert_eq!(
            translated.report.mapped_id("second"),
            Some("read__2")
        );
        assert_eq!(tool_pairs(&translated.transcript), vec![
            ("read__1".to_owned(), "read".to_owned()),
            ("read__2".to_owned(), "read".to_owned())
        ]);
        assert_eq!(
            tool_result_ids(&translated.transcript),
            vec!["read__1".to_owned(), "read__2".to_owned()]
        );
        assert_pairing(&translated.transcript);
        assert!(
            translated
                .report
                .notes
                .iter()
                .any(|note| note.contains("repeated calls")),
            "{:?}",
            translated.report.notes
        );
    }

    #[test]
    fn round_trip_reports_lossy_first_leg_and_preserves_text_roles_and_pairing() {
        let input = rich(true);

        let first = translate(&input, ProviderFormat::Anthropic, ProviderFormat::OpenAi)
            .expect("first leg");
        assert_eq!(first.report.dropped.len(), 1);
        assert_eq!(first.report.dropped[0].kind, "thinking");

        let second = translate(&first.transcript, ProviderFormat::OpenAi, ProviderFormat::Anthropic)
            .expect("second leg");
        assert!(second.report.dropped.is_empty(), "{:?}", second.report.dropped);
        assert_pairing(&second.transcript);
        assert_eq!(non_system_roles(&second.transcript), non_system_roles(&first.transcript));
        assert_eq!(texts(&second.transcript), texts(&first.transcript));
        assert_eq!(
            second.transcript.system_text(),
            first.transcript.system_text()
        );
        assert_eq!(tool_pairs(&second.transcript), tool_pairs(&first.transcript));
        assert_eq!(tool_result_ids(&second.transcript), tool_result_ids(&first.transcript));
    }

    #[test]
    fn round_trip_through_gemini_keeps_pairing_and_ordering() {
        let input = rich(false);
        let first = translate(&input, ProviderFormat::Anthropic, ProviderFormat::Gemini)
            .expect("to gemini");
        assert_eq!(first.report.remapped_ids.len(), 1);

        let second = translate(&first.transcript, ProviderFormat::Gemini, ProviderFormat::Anthropic)
            .expect("back to anthropic");
        assert!(second.report.remapped_ids.is_empty(), "{:?}", second.report.remapped_ids);
        assert_pairing(&second.transcript);
        assert_eq!(non_system_roles(&second.transcript), non_system_roles(&input));
        assert_eq!(texts(&second.transcript), texts(&input));
        assert_eq!(
            tool_pairs(&second.transcript),
            tool_pairs(&first.transcript)
        );
        assert_eq!(
            tool_result_ids(&second.transcript),
            tool_result_ids(&first.transcript)
        );
    }

    #[test]
    fn escalation_mid_task_keeps_paired_tool_ids_valid() {
        let input = transcript(vec![
            Message::assistant(vec![
                Block::text("Checking."),
                Block::tool_use("call_1", "search", json!({ "query": "x" })),
            ]),
            Message::user(vec![Block::tool_result(
                "call_1",
                json!({ "ok": true }),
                false,
            )]),
        ]);

        let same_ids = translate_for_escalation(
            &input,
            ProviderFormat::Anthropic,
            ProviderFormat::OpenAi,
        )
        .expect("escalate");
        assert_pairing(&same_ids.transcript);
        assert_eq!(same_ids.transcript.tool_ids, input.tool_ids);
        assert!(
            same_ids
                .report
                .notes
                .iter()
                .any(|note| note.starts_with("escalation:") && note.contains("preserved")),
            "{:?}",
            same_ids.report.notes
        );

        let remapped = translate_for_escalation(
            &input,
            ProviderFormat::Anthropic,
            ProviderFormat::Gemini,
        )
        .expect("escalate to gemini");
        assert_pairing(&remapped.transcript);
        let new_id = remapped
            .report
            .mapped_id("call_1")
            .expect("gemini remaps the id")
            .to_owned();
        assert_eq!(remapped.transcript.tool_ids, BTreeSet::from([new_id.clone()]));
        assert_eq!(tool_result_ids(&remapped.transcript), vec![new_id]);

        let back = translate_for_escalation(
            &remapped.transcript,
            ProviderFormat::Gemini,
            ProviderFormat::Anthropic,
        )
        .expect("escalate back");
        assert_pairing(&back.transcript);
        assert_eq!(tool_result_ids(&back.transcript), tool_result_ids(&remapped.transcript));
    }

    #[test]
    fn escalation_with_a_pending_tool_call_keeps_the_future_result_pairable() {
        let pending = transcript(vec![Message::assistant(vec![Block::tool_use(
            "call_1",
            "search",
            json!({ "query": "x" }),
        )])]);

        let translated = translate_for_escalation(
            &pending,
            ProviderFormat::Anthropic,
            ProviderFormat::Gemini,
        )
        .expect("escalate while a call is in flight");
        assert_pairing(&translated.transcript);
        let new_id = translated
            .report
            .mapped_id("call_1")
            .expect("the pending call is remapped")
            .to_owned();
        assert_eq!(tool_result_ids(&translated.transcript), Vec::<String>::new());

        let mut messages = translated.transcript.messages.clone();
        messages.push(Message::user(vec![Block::tool_result(
            new_id,
            json!({ "ok": true }),
            false,
        )]));
        let completed = Transcript::new(messages).expect("the future result pairs");
        assert_pairing(&completed);

        let back = translate_for_escalation(
            &translated.transcript,
            ProviderFormat::Gemini,
            ProviderFormat::Anthropic,
        )
        .expect("escalate back with the call still pending");
        assert_pairing(&back.transcript);
        assert_eq!(back.transcript.tool_ids, translated.transcript.tool_ids);
    }

    #[test]
    fn invalid_pairing_and_duplicate_ids_are_typed_errors() {
        let secret = Block::text(SECRET);
        let orphan = Transcript::new(vec![
            Message::user(vec![secret.clone()]),
            Message::user(vec![Block::tool_result("missing", json!("x"), false)]),
        ])
        .expect_err("orphan result");
        assert_eq!(orphan.code(), ErrorCode::ProviderProtocol);
        assert!(!orphan.message().contains(SECRET));

        let duplicate = Transcript::new(vec![Message::assistant(vec![
            Block::tool_use("same", "read", json!({})),
            Block::tool_use("same", "read", json!({})),
        ])])
        .expect_err("duplicate id");
        assert_eq!(duplicate.code(), ErrorCode::ProviderProtocol);

        let repeated = Transcript::new(vec![
            Message::assistant(vec![Block::tool_use("call_1", "read", json!({}))]),
            Message::user(vec![
                Block::tool_result("call_1", json!("one"), false),
                Block::tool_result("call_1", json!("two"), false),
            ]),
        ])
        .expect_err("repeated result");
        assert_eq!(repeated.code(), ErrorCode::ProviderProtocol);

        let wrong_use_role = Transcript::new(vec![Message::user(vec![Block::tool_use(
            "call_1",
            "read",
            json!({}),
        )])])
        .expect_err("tool_use in a user message");
        assert_eq!(wrong_use_role.code(), ErrorCode::ProviderProtocol);

        let wrong_result_role = Transcript::new(vec![Message::assistant(vec![
            Block::tool_use("call_1", "read", json!({})),
            Block::tool_result("call_1", json!("x"), false),
        ])])
        .expect_err("tool_result in an assistant message");
        assert_eq!(wrong_result_role.code(), ErrorCode::ProviderProtocol);

        let mut mismatched = rich(false);
        mismatched.tool_ids.insert("not-a-real-id".to_owned());
        let mismatch = mismatched.validate().expect_err("index mismatch");
        assert_eq!(mismatch.code(), ErrorCode::InvalidInput);
    }

    #[test]
    fn oversized_and_malformed_blocks_are_rejected_without_prompt_text() {
        let oversized_text = Transcript::new(vec![Message::user(vec![Block::text(format!(
            "{SECRET}{}",
            "x".repeat(MAX_TEXT_BYTES)
        ))])])
        .expect_err("oversized text");
        assert_eq!(oversized_text.code(), ErrorCode::LimitExceeded);
        assert!(!oversized_text.message().contains(SECRET));

        let oversized_image = Transcript::new(vec![Message::user(vec![Block::image(
            "image/png",
            "A".repeat(MAX_IMAGE_B64_BYTES + 1),
        )])])
        .expect_err("oversized image");
        assert_eq!(oversized_image.code(), ErrorCode::LimitExceeded);

        let bad_base64 = Transcript::new(vec![Message::user(vec![Block::image(
            "image/png",
            "not base64!",
        )])])
        .expect_err("bad base64");
        assert_eq!(bad_base64.code(), ErrorCode::InvalidInput);

        let empty_media = Transcript::new(vec![Message::user(vec![Block::image("", "AAAA")])])
            .expect_err("empty media type");
        assert_eq!(empty_media.code(), ErrorCode::InvalidInput);

        let not_image = Transcript::new(vec![Message::user(vec![Block::image(
            "application/pdf",
            "AAAA",
        )])])
        .expect_err("not an image");
        assert_eq!(not_image.code(), ErrorCode::InvalidInput);

        let empty_id = Transcript::new(vec![Message::assistant(vec![Block::tool_use(
            "",
            "read",
            json!({}),
        )])])
        .expect_err("empty id");
        assert_eq!(empty_id.code(), ErrorCode::InvalidInput);

        let control_id = Transcript::new(vec![Message::assistant(vec![Block::tool_use(
            "call\n1",
            "read",
            json!({}),
        )])])
        .expect_err("control char in id");
        assert_eq!(control_id.code(), ErrorCode::InvalidInput);

        let oversized_name = Transcript::new(vec![Message::assistant(vec![Block::tool_use(
            "call_1",
            "x".repeat(MAX_TOOL_NAME_BYTES + 1),
            json!({}),
        )])])
        .expect_err("oversized name");
        assert_eq!(oversized_name.code(), ErrorCode::LimitExceeded);

        let oversized_arguments = Transcript::new(vec![Message::assistant(vec![
            Block::tool_use(
                "call_1",
                "read",
                json!({ "blob": "x".repeat(MAX_TOOL_ARGUMENT_BYTES + 1) }),
            ),
        ])])
        .expect_err("oversized arguments");
        assert_eq!(oversized_arguments.code(), ErrorCode::LimitExceeded);
    }

    #[test]
    fn render_refuses_non_portable_blocks_instead_of_losing_them() {
        let input = transcript(vec![
            Message::assistant(vec![Block::thinking(SECRET)]),
            Message::user(vec![Block::text("hello")]),
        ]);
        let error = input
            .render(ProviderFormat::OpenAi)
            .expect_err("thinking is not portable to openai");
        assert_eq!(error.code(), ErrorCode::ProviderProtocol);
        assert!(!error.message().contains(SECRET));

        let image = transcript(vec![Message::user(vec![Block::image(
            "image/svg+xml",
            "PHN2Zy8+",
        )])]);
        let error = image
            .render(ProviderFormat::OpenAi)
            .expect_err("svg is not portable to openai");
        assert_eq!(error.code(), ErrorCode::ProviderProtocol);
        assert!(error.message().contains("image/svg+xml"));
    }

    #[test]
    fn translation_is_deterministic() {
        let input = rich(true);
        let first = translate(&input, ProviderFormat::Anthropic, ProviderFormat::Gemini)
            .expect("first");
        let second = translate(&input, ProviderFormat::Anthropic, ProviderFormat::Gemini)
            .expect("second");
        assert_eq!(first, second);

        let first_escalation =
            translate_for_escalation(&input, ProviderFormat::Anthropic, ProviderFormat::OpenAi)
                .expect("first escalation");
        let second_escalation =
            translate_for_escalation(&input, ProviderFormat::Anthropic, ProviderFormat::OpenAi)
                .expect("second escalation");
        assert_eq!(first_escalation, second_escalation);
    }

    #[test]
    fn empty_transcripts_translate_and_render() {
        let empty = Transcript::empty();
        for to in ProviderFormat::ALL {
            let translated = translate(&empty, ProviderFormat::OpenAi, to).expect("translate");
            assert!(translated.transcript.messages.is_empty());
            assert!(translated.transcript.tool_ids.is_empty());
            assert!(translated.report.dropped.is_empty());
        }
        assert_eq!(
            empty.render(ProviderFormat::OpenAi).expect("openai"),
            json!({ "messages": [] })
        );
        assert_eq!(
            empty.render(ProviderFormat::Anthropic).expect("anthropic"),
            json!({ "messages": [] })
        );
        assert_eq!(
            empty.render(ProviderFormat::Gemini).expect("gemini"),
            json!({ "contents": [] })
        );
    }

    #[test]
    fn formats_use_stable_wire_labels() {
        assert_eq!(ProviderFormat::OpenAi.as_str(), "openai");
        assert_eq!(
            serde_json::to_value(ProviderFormat::OpenAi).expect("serde"),
            json!("openai")
        );
        assert_eq!(
            ProviderFormat::parse(" Google "),
            Some(ProviderFormat::Gemini)
        );
        assert_eq!(
            ProviderFormat::parse("OPEN_AI"),
            Some(ProviderFormat::OpenAi)
        );
        assert_eq!(ProviderFormat::parse("unknown"), None);

        let block = Block::tool_use("call_1", "read", json!({ "path": "a" }));
        let value = serde_json::to_value(&block).expect("block serde");
        assert_eq!(value["type"], "tool_use");
        assert_eq!(value["id"], "call_1");
        assert_eq!(value["name"], "read");
    }
}
