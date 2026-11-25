//! T-MM-06 local CPU model consent and capability gate.
//!
//! A local model is described by one validated [`LocalModelRequest`]. The
//! request carries the licence, the disk and memory it needs, and the exact
//! purpose, and it is rendered into a deterministic [`ConsentPrompt`] before
//! anything else happens. [`authorize`] turns the user's [`ConsentDecision`]
//! into a capability: a decline leaves the modality unavailable with an
//! explanation, and a grant makes exactly one model available for exactly one
//! modality. [`CapabilityRegistry`] holds those per-modality states and is what
//! callers use to find the consented model or to refuse the work.
//!
//! This module performs no download, no installation, and no network or
//! filesystem access. [`authorize`] returns a capability plus a
//! [`DownloadPlan`] that a later task may act on only after verifying a
//! checksum. Local models are CPU-capable by construction: [`LocalModality`] is
//! restricted to the inputs those models consume, and there is no accelerator
//! path (MM-06, MM-13, MM-14).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, Result, ZeroError};

/// Maximum characters in a local model id.
pub const MAX_MODEL_ID_CHARS: usize = 128;
/// Maximum characters in a local model display name.
pub const MAX_MODEL_NAME_CHARS: usize = 128;
/// Maximum characters in a licence string (an SPDX id or `name + URL`).
pub const MAX_LICENCE_CHARS: usize = 256;
/// Maximum characters in the declared purpose.
pub const MAX_PURPOSE_CHARS: usize = 512;
/// Maximum characters in the model source (URL or local path).
pub const MAX_SOURCE_CHARS: usize = 512;
/// Maximum characters in an optional decline reason.
pub const MAX_DECLINE_REASON_CHARS: usize = 256;
/// Documented maximum disk requirement: 32 GiB.
pub const MAX_LOCAL_MODEL_DISK_BYTES: u64 = 32 * 1024 * 1024 * 1024;
/// Documented maximum memory requirement: 16 GiB.
pub const MAX_LOCAL_MODEL_MEMORY_BYTES: u64 = 16 * 1024 * 1024 * 1024;

const MIB: u128 = 1024 * 1024;
const GIB: u128 = 1024 * MIB;

/// The modalities a CPU-capable local model can serve.
///
/// This is deliberately separate from [`crate::Modality`]: an embedding model
/// consumes text and produces vectors, so it is not an input attachment kind.
/// The set is closed on purpose: a modality that is not listed here has no
/// local CPU path and must be routed to a hosted provider or reported
/// unavailable (MM-13, MM-14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LocalModality {
    #[serde(rename = "image")]
    Image,
    #[serde(rename = "audio")]
    Audio,
    #[serde(rename = "video")]
    Video,
    #[serde(rename = "text-embedding")]
    TextEmbedding,
}

impl LocalModality {
    /// Every local-capable modality in deterministic order.
    pub const ALL: [LocalModality; 4] = [
        LocalModality::Image,
        LocalModality::Audio,
        LocalModality::Video,
        LocalModality::TextEmbedding,
    ];

    /// Parse the canonical lowercase name. Anything else is unknown and is
    /// rejected by the caller.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "image" => Some(LocalModality::Image),
            "audio" => Some(LocalModality::Audio),
            "video" => Some(LocalModality::Video),
            "text-embedding" => Some(LocalModality::TextEmbedding),
            _ => None,
        }
    }

    /// Map an input attachment modality to a local model modality.
    ///
    /// `Text` and `Document` return `None`: this slice has no local model for
    /// them, so a router must use a hosted provider or report the modality
    /// unavailable (MM-14).
    pub fn from_input(modality: crate::Modality) -> Option<Self> {
        match modality {
            crate::Modality::Image => Some(LocalModality::Image),
            crate::Modality::Audio => Some(LocalModality::Audio),
            crate::Modality::Video => Some(LocalModality::Video),
            crate::Modality::Text | crate::Modality::Document => None,
        }
    }

    /// Stable lowercase name used in prompts, JSON, and error messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            LocalModality::Image => "image",
            LocalModality::Audio => "audio",
            LocalModality::Video => "video",
            LocalModality::TextEmbedding => "text-embedding",
        }
    }
}

impl fmt::Display for LocalModality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One local CPU model that needs explicit consent before it can be used.
///
/// `licence` is either an SPDX identifier (`MIT`, `Apache-2.0`) or a licence
/// name followed by a URL (`Llama 3.2 Community License, https://...`).
/// `source` is where a later task would download the model from; this module
/// never fetches it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalModelRequest {
    pub id: String,
    pub name: String,
    pub modality: LocalModality,
    pub licence: String,
    pub disk_bytes: u64,
    pub memory_bytes: u64,
    pub purpose: String,
    pub source: String,
}

impl LocalModelRequest {
    /// Validate every field before it can be shown or authorized.
    pub fn validate(&self) -> Result<()> {
        validate_model_id(&self.id)?;
        validate_text(&self.name, "model name", MAX_MODEL_NAME_CHARS)?;
        validate_text(&self.licence, "licence", MAX_LICENCE_CHARS)?;
        licence_parts(&self.licence)?;
        if self.disk_bytes == 0 {
            return Err(invalid("disk requirement must be greater than zero"));
        }
        if self.disk_bytes > MAX_LOCAL_MODEL_DISK_BYTES {
            return Err(limit(format!(
                "disk requirement {} exceeds the documented maximum of {MAX_LOCAL_MODEL_DISK_BYTES} bytes",
                self.disk_bytes
            )));
        }
        if self.memory_bytes == 0 {
            return Err(invalid("memory requirement must be greater than zero"));
        }
        if self.memory_bytes > MAX_LOCAL_MODEL_MEMORY_BYTES {
            return Err(limit(format!(
                "memory requirement {} exceeds the documented maximum of {MAX_LOCAL_MODEL_MEMORY_BYTES} bytes",
                self.memory_bytes
            )));
        }
        validate_text(&self.purpose, "purpose", MAX_PURPOSE_CHARS)?;
        validate_text(&self.source, "source", MAX_SOURCE_CHARS)?;
        Ok(())
    }
}

/// A deterministic consent prompt for one validated request.
///
/// `lines` is built once from the request, so rendering the same request twice
/// produces byte-identical text. The prompt names the model, its modality, its
/// licence (with the URL when one is present), the disk and memory it needs,
/// and the exact purpose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentPrompt {
    pub request: LocalModelRequest,
    pub lines: Vec<String>,
}

impl ConsentPrompt {
    /// Validate the request and build the prompt lines.
    pub fn new(request: LocalModelRequest) -> Result<Self> {
        request.validate()?;
        let (licence_name, licence_url) = licence_parts(&request.licence)?;
        let modality = request.modality;
        let licence_line = match licence_url {
            Some(url) => format!("licence: {licence_name} ({url})"),
            None => format!("licence: {licence_name}"),
        };

        let mut lines = Vec::with_capacity(12);
        lines.push("Local model consent request".to_string());
        lines.push(format!("model: {}", request.name));
        lines.push(format!("id: {}", request.id));
        lines.push(format!("modality: {}", modality.as_str()));
        lines.push(licence_line);
        lines.push(format!(
            "disk required: {}",
            describe_bytes(request.disk_bytes)
        ));
        lines.push(format!(
            "memory required: {}",
            describe_bytes(request.memory_bytes)
        ));
        lines.push(format!("purpose: {}", request.purpose));
        lines.push(format!("source: {}", request.source));
        lines.push(format!(
            "consent: accepting records consent and makes this model available for the {} modality only.",
            modality.as_str()
        ));
        lines.push(format!(
            "decline: declining leaves the {} modality unavailable and no download occurs.",
            modality.as_str()
        ));
        lines.push(
            "download: a later task performs any download and must verify a checksum first."
                .to_string(),
        );

        Ok(Self { request, lines })
    }

    /// Join the prompt lines with `\n`. No trailing newline is appended.
    pub fn render(&self) -> String {
        self.lines.join("\n")
    }
}

impl fmt::Display for ConsentPrompt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

/// What the user decided about one local model request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum ConsentDecision {
    /// The user accepted at `at_ms`. The time is part of the durable record.
    Granted { at_ms: u64 },
    /// The user declined, optionally with a reason shown in the explanation.
    Declined { reason: Option<String> },
}

impl ConsentDecision {
    /// Validate the optional decline reason. A blank reason is rejected so the
    /// explanation never ends in a dangling separator.
    pub fn validate(&self) -> Result<()> {
        if let ConsentDecision::Declined {
            reason: Some(reason),
        } = self
        {
            if reason.trim().is_empty() {
                return Err(invalid("a decline reason cannot be empty; omit it instead"));
            }
            if reason.chars().count() > MAX_DECLINE_REASON_CHARS {
                return Err(limit(format!(
                    "a decline reason is longer than {MAX_DECLINE_REASON_CHARS} characters"
                )));
            }
            if reason.chars().any(char::is_control) {
                return Err(invalid("a decline reason contains a control character"));
            }
        }
        Ok(())
    }
}

/// The state of one modality in the capability registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CapabilityState {
    /// No consented model serves this modality.
    Unavailable { explanation: String },
    /// Exactly one consented model serves this modality.
    Available { model_id: String },
}

/// A modality and its current state.
///
/// `Available` means consent is on record for that model; it does not mean the
/// weights are present. The later download task still has to run and verify a
/// checksum before the model can be loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalCapability {
    pub modality: LocalModality,
    pub state: CapabilityState,
}

impl LocalCapability {
    /// Whether a consented model serves this modality.
    pub fn is_available(&self) -> bool {
        matches!(&self.state, CapabilityState::Available { .. })
    }

    /// The model id when the modality is available.
    pub fn model_id(&self) -> Option<&str> {
        match &self.state {
            CapabilityState::Available { model_id } => Some(model_id.as_str()),
            CapabilityState::Unavailable { .. } => None,
        }
    }

    /// The explanation when the modality is unavailable.
    pub fn explanation(&self) -> Option<&str> {
        match &self.state {
            CapabilityState::Unavailable { explanation } => Some(explanation.as_str()),
            CapabilityState::Available { .. } => None,
        }
    }
}

/// A plan for a later task. It is data only: no socket is opened and no file is
/// written here. The download task MUST verify a published checksum before the
/// model is loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadPlan {
    pub model_id: String,
    pub modality: LocalModality,
    pub source: String,
    pub disk_bytes: u64,
    pub memory_bytes: u64,
    pub authorized_at_ms: u64,
}

/// The result of applying one consent decision to one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "authorization", rename_all = "snake_case")]
pub enum Authorization {
    /// The model is available for exactly the request's modality.
    Granted {
        capability: LocalCapability,
        plan: DownloadPlan,
    },
    /// The modality stays unavailable; the capability carries the explanation.
    Declined { capability: LocalCapability },
}

impl Authorization {
    /// The capability produced by this decision.
    pub fn capability(&self) -> &LocalCapability {
        match self {
            Authorization::Granted { capability, .. } | Authorization::Declined { capability } => {
                capability
            }
        }
    }

    /// The download plan, when the decision was a grant.
    pub fn plan(&self) -> Option<&DownloadPlan> {
        match self {
            Authorization::Granted { plan, .. } => Some(plan),
            Authorization::Declined { .. } => None,
        }
    }
}

/// Apply one consent decision. Nothing is downloaded or installed.
///
/// A grant marks exactly the request's modality available for exactly the
/// request's model id. A decline leaves the modality unavailable with an
/// explanation that names the model and states that no download occurred.
/// `now_ms` is the authorization time; a grant recorded after it is rejected as
/// a clock error.
pub fn authorize(
    request: &LocalModelRequest,
    decision: &ConsentDecision,
    now_ms: u64,
) -> Result<Authorization> {
    request.validate()?;
    decision.validate()?;

    match decision {
        ConsentDecision::Granted { at_ms } => {
            if *at_ms > now_ms {
                return Err(invalid(format!(
                    "consent timestamp {at_ms} is later than the authorization time {now_ms}"
                )));
            }
            let capability = LocalCapability {
                modality: request.modality,
                state: CapabilityState::Available {
                    model_id: request.id.clone(),
                },
            };
            let plan = DownloadPlan {
                model_id: request.id.clone(),
                modality: request.modality,
                source: request.source.clone(),
                disk_bytes: request.disk_bytes,
                memory_bytes: request.memory_bytes,
                authorized_at_ms: now_ms,
            };
            Ok(Authorization::Granted { capability, plan })
        }
        ConsentDecision::Declined { reason } => {
            let capability = LocalCapability {
                modality: request.modality,
                state: CapabilityState::Unavailable {
                    explanation: decline_explanation(request, reason.as_deref()),
                },
            };
            Ok(Authorization::Declined { capability })
        }
    }
}

/// Per-modality local model availability.
///
/// A modality with no entry is unavailable with a default explanation. Applying
/// an authorization replaces that modality's state, so a re-consent (grant or
/// decline) is effective immediately and never touches another modality.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityRegistry {
    #[serde(default)]
    states: BTreeMap<LocalModality, CapabilityState>,
}

impl CapabilityRegistry {
    /// An empty registry: every modality is unavailable.
    pub fn new() -> Self {
        Self::default()
    }

    /// The current capability for one modality. A missing entry becomes an
    /// unavailable state with the default explanation.
    pub fn capability(&self, modality: LocalModality) -> LocalCapability {
        let state =
            self.states
                .get(&modality)
                .cloned()
                .unwrap_or_else(|| CapabilityState::Unavailable {
                    explanation: default_explanation(modality),
                });
        LocalCapability { modality, state }
    }

    /// Whether a consented model serves this modality.
    pub fn is_available(&self, modality: LocalModality) -> bool {
        matches!(
            self.states.get(&modality),
            Some(CapabilityState::Available { .. })
        )
    }

    /// Require a consented model for this modality.
    ///
    /// Returns the model id, or `zero.fnd.unavailable` with the stored
    /// explanation (or the default one when nothing was ever consented).
    pub fn require(&self, modality: LocalModality) -> Result<&str> {
        match self.states.get(&modality) {
            Some(CapabilityState::Available { model_id }) => Ok(model_id.as_str()),
            Some(CapabilityState::Unavailable { explanation }) => Err(unavailable(format!(
                "{} modality is unavailable: {explanation}",
                modality.as_str()
            ))),
            None => Err(unavailable(format!(
                "{} modality is unavailable: {}",
                modality.as_str(),
                default_explanation(modality)
            ))),
        }
    }

    /// Apply an authorization, replacing only that modality's state.
    pub fn apply(&mut self, authorization: &Authorization) {
        let capability = authorization.capability();
        self.states
            .insert(capability.modality, capability.state.clone());
    }

    /// Authorize a request and apply the result in one step.
    pub fn authorize(
        &mut self,
        request: &LocalModelRequest,
        decision: &ConsentDecision,
        now_ms: u64,
    ) -> Result<Authorization> {
        let authorization = crate::consent::authorize(request, decision, now_ms)?;
        self.apply(&authorization);
        Ok(authorization)
    }
}

/// The explanation attached to a decline. It always names the model and says
/// that no download occurred, which is the T-MM-06 done condition.
fn decline_explanation(request: &LocalModelRequest, reason: Option<&str>) -> String {
    let mut text = format!(
        "local model `{}` ({}) was declined; the {} modality stays unavailable and no download occurred",
        request.name,
        request.id,
        request.modality.as_str()
    );
    if let Some(reason) = reason {
        let reason = reason.trim();
        if !reason.is_empty() {
            text.push_str(&format!(": {reason}"));
        }
    }
    text
}

fn default_explanation(modality: LocalModality) -> String {
    format!("no local {} model has been consented to", modality.as_str())
}

/// Parse a licence string into a display name and an optional URL.
///
/// Accepted forms:
/// - an SPDX identifier: one token of ASCII letters, digits, `.`, `+`, or `-`;
/// - a licence name followed by an `http(s)` URL, separated by a comma,
///   whitespace, or parentheses, for example
///   `Some Model License, https://example.com/licence`.
fn licence_parts(licence: &str) -> Result<(String, Option<String>)> {
    let trimmed = licence.trim();
    if let Some(index) = find_url(trimmed) {
        let raw_name = trimmed[..index].trim_end();
        let parenthesized = raw_name.ends_with('(');
        let name = raw_name
            .trim_end_matches(|character: char| {
                character.is_whitespace() || matches!(character, ',' | ';' | ':' | '-' | '(')
            })
            .trim();
        if name.is_empty() {
            return Err(invalid("a licence with a URL needs a name before the URL"));
        }
        let mut url = trimmed[index..].trim();
        if parenthesized {
            if let Some(stripped) = url.strip_suffix(')') {
                url = stripped.trim_end();
            }
        }
        if url.chars().any(char::is_whitespace) {
            return Err(invalid("a licence URL cannot contain whitespace"));
        }
        validate_licence_url(url)?;
        return Ok((name.to_string(), Some(url.to_string())));
    }

    if !is_spdx_like(trimmed) {
        return Err(invalid(
            "licence must be an SPDX identifier or `name, https://...`",
        ));
    }
    Ok((trimmed.to_string(), None))
}

fn find_url(text: &str) -> Option<usize> {
    [text.find("https://"), text.find("http://")]
        .into_iter()
        .flatten()
        .min()
}

fn validate_licence_url(url: &str) -> Result<()> {
    let Some((scheme, rest)) = url.split_once("://") else {
        return Err(invalid(format!("licence URL `{url}` is missing a scheme")));
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(invalid(format!(
            "licence URL `{url}` uses `{scheme}`; only http and https are allowed"
        )));
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err(invalid(format!("licence URL `{url}` has no host")));
    }
    if authority.contains('@') {
        return Err(invalid(format!(
            "licence URL `{url}` carries userinfo; credentials in a URL are not allowed"
        )));
    }
    if authority.contains('\\') {
        return Err(invalid(format!("licence URL `{url}` has an invalid host")));
    }
    let host = if let Some(remainder) = authority.strip_prefix('[') {
        remainder.split(']').next().unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    };
    if host.is_empty() {
        return Err(invalid(format!("licence URL `{url}` has no host")));
    }
    Ok(())
}

fn is_spdx_like(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .any(|character| character.is_ascii_alphabetic())
        && text.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '+' | '-')
        })
}

fn validate_model_id(id: &str) -> Result<()> {
    if id.trim().is_empty() {
        return Err(invalid("model id cannot be empty"));
    }
    if id.chars().count() > MAX_MODEL_ID_CHARS {
        return Err(limit(format!(
            "model id is longer than {MAX_MODEL_ID_CHARS} characters"
        )));
    }
    if id
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(invalid(
            "model id contains a control character or whitespace",
        ));
    }
    Ok(())
}

fn validate_text(value: &str, label: &str, cap: usize) -> Result<()> {
    if value.trim().is_empty() {
        return Err(invalid(format!("{label} cannot be empty")));
    }
    if value.chars().count() > cap {
        return Err(limit(format!("{label} is longer than {cap} characters")));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid(format!("{label} contains a control character")));
    }
    Ok(())
}

/// Render bytes as a deterministic human-readable size plus the exact count.
fn describe_bytes(bytes: u64) -> String {
    let bytes = u128::from(bytes);
    if bytes >= GIB {
        let tenths = bytes * 10 / GIB;
        format!("{}.{} GiB ({} bytes)", tenths / 10, tenths % 10, bytes)
    } else if bytes >= MIB {
        let tenths = bytes * 10 / MIB;
        format!("{}.{} MiB ({} bytes)", tenths / 10, tenths % 10, bytes)
    } else {
        format!("{bytes} bytes")
    }
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn limit(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

fn unavailable(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Unavailable, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    fn request_for(id: &str, name: &str, modality: LocalModality) -> LocalModelRequest {
        LocalModelRequest {
            id: id.to_string(),
            name: name.to_string(),
            modality,
            licence: "Llama 3.2 Community License, https://example.com/licence".to_string(),
            disk_bytes: 6 * GIB,
            memory_bytes: 8 * GIB,
            purpose: "Read screenshots and describe UI elements.".to_string(),
            source: "https://example.com/models/llama-3.2-vision".to_string(),
        }
    }

    fn vision_request() -> LocalModelRequest {
        request_for(
            "llama-3.2-vision-11b",
            "Llama 3.2 Vision",
            LocalModality::Image,
        )
    }

    fn granted(at_ms: u64) -> ConsentDecision {
        ConsentDecision::Granted { at_ms }
    }

    #[test]
    fn prompt_shows_every_required_field() {
        let request = vision_request();
        let prompt = ConsentPrompt::new(request.clone()).expect("valid request");
        assert_eq!(prompt.request, request);
        let text = prompt.render();
        for needle in [
            "model: Llama 3.2 Vision",
            "id: llama-3.2-vision-11b",
            "modality: image",
            "licence: Llama 3.2 Community License (https://example.com/licence)",
            "disk required: 6.0 GiB (6442450944 bytes)",
            "memory required: 8.0 GiB (8589934592 bytes)",
            "purpose: Read screenshots and describe UI elements.",
            "source: https://example.com/models/llama-3.2-vision",
        ] {
            assert!(
                text.contains(needle),
                "prompt must contain `{needle}`:\n{text}"
            );
        }

        let mut mit = request_for("whisper-small", "Whisper Small", LocalModality::Audio);
        mit.licence = "MIT".to_string();
        let prompt = ConsentPrompt::new(mit).expect("an SPDX licence renders");
        assert!(prompt.render().contains("licence: MIT\n"));

        let mut parenthesized = vision_request();
        parenthesized.licence =
            "Llama 3.2 Community License (https://example.com/licence)".to_string();
        let prompt = ConsentPrompt::new(parenthesized).expect("a parenthesized licence renders");
        assert!(prompt
            .render()
            .contains("licence: Llama 3.2 Community License (https://example.com/licence)\n"));
    }

    #[test]
    fn declining_leaves_the_modality_unavailable_with_an_explanation() {
        let request = vision_request();
        let decision = ConsentDecision::Declined {
            reason: Some("not on this machine".to_string()),
        };
        let authorization = authorize(&request, &decision, 10).expect("decline is valid");
        assert!(matches!(authorization, Authorization::Declined { .. }));

        let capability = authorization.capability();
        assert_eq!(capability.modality, LocalModality::Image);
        assert!(!capability.is_available());
        let explanation = capability
            .explanation()
            .expect("an unavailable capability has an explanation");
        assert!(explanation.contains("Llama 3.2 Vision"));
        assert!(explanation.contains("llama-3.2-vision-11b"));
        assert!(explanation.contains("no download occurred"));
        assert!(explanation.contains("not on this machine"));

        let mut registry = CapabilityRegistry::new();
        registry.apply(&authorization);
        let error = registry
            .require(LocalModality::Image)
            .expect_err("a declined modality is unavailable");
        assert_eq!(error.code(), ErrorCode::Unavailable);
        assert_eq!(error.code().as_str(), "zero.fnd.unavailable");
        assert!(error.message().contains("no download occurred"));
        assert!(error.message().contains("Llama 3.2 Vision"));
        assert!(registry.require(LocalModality::Audio).is_err());
    }

    #[test]
    fn granting_enables_only_that_model_and_modality() {
        let mut registry = CapabilityRegistry::new();
        let audio = request_for("whisper-small", "Whisper Small", LocalModality::Audio);
        registry
            .authorize(&audio, &granted(1), 1)
            .expect("grant audio");

        let vision = vision_request();
        let authorization = registry
            .authorize(&vision, &granted(2), 2)
            .expect("grant vision");

        assert_eq!(
            registry
                .require(LocalModality::Image)
                .expect("image is available"),
            "llama-3.2-vision-11b"
        );
        assert_eq!(
            registry
                .require(LocalModality::Audio)
                .expect("audio is unchanged"),
            "whisper-small"
        );
        assert_eq!(
            registry
                .require(LocalModality::Video)
                .expect_err("video was never granted")
                .code(),
            ErrorCode::Unavailable
        );
        assert_eq!(
            registry
                .require(LocalModality::TextEmbedding)
                .expect_err("embeddings were never granted")
                .code(),
            ErrorCode::Unavailable
        );

        let plan = authorization
            .plan()
            .expect("a grant carries a download plan");
        assert_eq!(plan.model_id, "llama-3.2-vision-11b");
        assert_eq!(plan.modality, LocalModality::Image);
        assert_eq!(plan.source, "https://example.com/models/llama-3.2-vision");
        assert_eq!(plan.disk_bytes, 6 * GIB);
        assert_eq!(plan.memory_bytes, 8 * GIB);
        assert_eq!(plan.authorized_at_ms, 2);
        assert!(authorization.capability().is_available());
    }

    #[test]
    fn re_consent_replaces_the_registry_state() {
        let mut registry = CapabilityRegistry::new();

        let first = request_for("vision-a", "Vision A", LocalModality::Image);
        registry
            .authorize(&first, &granted(1), 1)
            .expect("first grant");
        assert_eq!(
            registry
                .require(LocalModality::Image)
                .expect("first is available"),
            "vision-a"
        );

        let second = request_for("vision-b", "Vision B", LocalModality::Image);
        registry
            .authorize(&second, &granted(2), 2)
            .expect("second grant");
        assert_eq!(
            registry
                .require(LocalModality::Image)
                .expect("second is available"),
            "vision-b"
        );

        let decline = ConsentDecision::Declined { reason: None };
        registry
            .authorize(&second, &decline, 3)
            .expect("a decline is valid");
        let error = registry
            .require(LocalModality::Image)
            .expect_err("the decline revokes the modality");
        assert_eq!(error.code(), ErrorCode::Unavailable);
        assert!(error.message().contains("Vision B"));
    }

    #[test]
    fn invalid_requests_are_rejected() {
        let base = vision_request();
        let cases: Vec<(&str, LocalModelRequest)> = vec![
            (
                "empty id",
                LocalModelRequest {
                    id: String::new(),
                    ..base.clone()
                },
            ),
            (
                "id with whitespace",
                LocalModelRequest {
                    id: "llama vision".to_string(),
                    ..base.clone()
                },
            ),
            (
                "empty name",
                LocalModelRequest {
                    name: String::new(),
                    ..base.clone()
                },
            ),
            (
                "oversize name",
                LocalModelRequest {
                    name: "n".repeat(MAX_MODEL_NAME_CHARS + 1),
                    ..base.clone()
                },
            ),
            (
                "empty licence",
                LocalModelRequest {
                    licence: String::new(),
                    ..base.clone()
                },
            ),
            (
                "oversize licence",
                LocalModelRequest {
                    licence: "l".repeat(MAX_LICENCE_CHARS + 1),
                    ..base.clone()
                },
            ),
            (
                "licence without a URL and with spaces",
                LocalModelRequest {
                    licence: "see the website".to_string(),
                    ..base.clone()
                },
            ),
            (
                "licence URL without a name",
                LocalModelRequest {
                    licence: "https://example.com/licence".to_string(),
                    ..base.clone()
                },
            ),
            (
                "numeric licence token",
                LocalModelRequest {
                    licence: "123".to_string(),
                    ..base.clone()
                },
            ),
            (
                "zero disk",
                LocalModelRequest {
                    disk_bytes: 0,
                    ..base.clone()
                },
            ),
            (
                "oversize disk",
                LocalModelRequest {
                    disk_bytes: MAX_LOCAL_MODEL_DISK_BYTES + 1,
                    ..base.clone()
                },
            ),
            (
                "zero memory",
                LocalModelRequest {
                    memory_bytes: 0,
                    ..base.clone()
                },
            ),
            (
                "oversize memory",
                LocalModelRequest {
                    memory_bytes: MAX_LOCAL_MODEL_MEMORY_BYTES + 1,
                    ..base.clone()
                },
            ),
            (
                "empty purpose",
                LocalModelRequest {
                    purpose: String::new(),
                    ..base.clone()
                },
            ),
            (
                "oversize purpose",
                LocalModelRequest {
                    purpose: "p".repeat(MAX_PURPOSE_CHARS + 1),
                    ..base.clone()
                },
            ),
            (
                "empty source",
                LocalModelRequest {
                    source: String::new(),
                    ..base.clone()
                },
            ),
            (
                "oversize source",
                LocalModelRequest {
                    source: "s".repeat(MAX_SOURCE_CHARS + 1),
                    ..base.clone()
                },
            ),
        ];

        for (label, request) in cases {
            assert!(
                request.validate().is_err(),
                "{label} must be rejected by validate"
            );
            assert!(
                ConsentPrompt::new(request.clone()).is_err(),
                "{label} must not render a prompt"
            );
            assert!(
                authorize(&request, &granted(1), 1).is_err(),
                "{label} must not be authorized"
            );
        }

        let oversized = LocalModelRequest {
            disk_bytes: MAX_LOCAL_MODEL_DISK_BYTES + 1,
            ..base.clone()
        };
        assert_eq!(
            oversized.validate().expect_err("oversize disk").code(),
            ErrorCode::LimitExceeded
        );
        let blank = LocalModelRequest {
            name: "   ".to_string(),
            ..base.clone()
        };
        assert_eq!(
            blank.validate().expect_err("blank name").code(),
            ErrorCode::InvalidInput
        );

        assert!(
            ConsentDecision::Declined {
                reason: Some("  ".to_string())
            }
            .validate()
            .is_err(),
            "a blank decline reason is rejected"
        );
        assert!(
            ConsentDecision::Declined {
                reason: Some("r".repeat(MAX_DECLINE_REASON_CHARS + 1))
            }
            .validate()
            .is_err(),
            "an oversize decline reason is rejected"
        );
    }

    #[test]
    fn unknown_modalities_are_rejected() {
        for modality in LocalModality::ALL {
            assert_eq!(LocalModality::from_name(modality.as_str()), Some(modality));
            let json = serde_json::to_string(&modality).expect("serialize modality");
            assert_eq!(
                serde_json::from_str::<LocalModality>(&json).expect("deserialize modality"),
                modality
            );
        }
        assert!(LocalModality::from_name("hologram").is_none());
        assert!(LocalModality::from_name("IMAGE").is_none());
        assert!(serde_json::from_str::<LocalModality>("\"hologram\"").is_err());
        assert!(serde_json::from_str::<LocalModality>("\"text_embedding\"").is_err());

        assert_eq!(
            LocalModality::from_input(crate::Modality::Image),
            Some(LocalModality::Image)
        );
        assert_eq!(
            LocalModality::from_input(crate::Modality::Audio),
            Some(LocalModality::Audio)
        );
        assert_eq!(
            LocalModality::from_input(crate::Modality::Video),
            Some(LocalModality::Video)
        );
        assert_eq!(LocalModality::from_input(crate::Modality::Text), None);
        assert_eq!(LocalModality::from_input(crate::Modality::Document), None);
    }

    #[test]
    fn prompt_text_is_deterministic() {
        let first = ConsentPrompt::new(vision_request()).expect("valid request");
        let second = ConsentPrompt::new(vision_request()).expect("valid request");
        assert_eq!(first.lines, second.lines);
        let expected = "\
Local model consent request
model: Llama 3.2 Vision
id: llama-3.2-vision-11b
modality: image
licence: Llama 3.2 Community License (https://example.com/licence)
disk required: 6.0 GiB (6442450944 bytes)
memory required: 8.0 GiB (8589934592 bytes)
purpose: Read screenshots and describe UI elements.
source: https://example.com/models/llama-3.2-vision
consent: accepting records consent and makes this model available for the image modality only.
decline: declining leaves the image modality unavailable and no download occurs.
download: a later task performs any download and must verify a checksum first.";
        assert_eq!(first.render(), expected);
    }

    #[test]
    fn no_network_or_install_code_path_exists() {
        let source = include_str!("consent.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("consent.rs has a production half");
        for needle in [
            "std::net",
            "std::fs",
            "std::process",
            "TcpStream",
            "UdpSocket",
            "reqwest",
            "hyper",
            "ureq",
            "isahc",
            "File::create",
            "OpenOptions",
            "Command::new",
            "fn download",
            "fn install",
        ] {
            assert!(
                !production.contains(needle),
                "`{needle}` must not appear in the consent module; consent only plans, it never downloads or installs"
            );
        }
    }

    #[test]
    fn the_registry_round_trips_through_serde() {
        let mut registry = CapabilityRegistry::new();
        registry
            .authorize(&vision_request(), &granted(1), 1)
            .expect("grant vision");
        let audio = request_for("whisper-small", "Whisper Small", LocalModality::Audio);
        registry
            .authorize(
                &audio,
                &ConsentDecision::Declined {
                    reason: Some("not needed".to_string()),
                },
                2,
            )
            .expect("decline audio");

        let json = serde_json::to_string(&registry).expect("serialize registry");
        let restored: CapabilityRegistry =
            serde_json::from_str(&json).expect("deserialize registry");
        assert_eq!(restored, registry);
        assert_eq!(
            restored
                .require(LocalModality::Image)
                .expect("image survives"),
            "llama-3.2-vision-11b"
        );
        assert_eq!(
            restored
                .require(LocalModality::Audio)
                .expect_err("audio stays declined")
                .code(),
            ErrorCode::Unavailable
        );
        assert_eq!(
            serde_json::to_string(&restored).expect("re-serialize"),
            json,
            "the registry JSON is deterministic"
        );
    }

    #[test]
    fn a_consent_from_the_future_is_rejected() {
        let error = authorize(&vision_request(), &granted(11), 10)
            .expect_err("a future consent is a clock error");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(
            authorize(&vision_request(), &granted(10), 10).is_ok(),
            "a consent at the current time is accepted"
        );
    }
}
