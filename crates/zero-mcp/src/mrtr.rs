//! MRTR and elicitation (T-MCP-03, MCP-03, MCP-07, MCP-08).
//!
//! The `2026-07-28` core replaces server-initiated requests with multi
//! round-trip requests: a server answers `tools/call` with
//! `resultType: "input_required"`, an `inputRequests` map, and an optional
//! opaque `requestState`; the client gathers the requested input and retries
//! the same call once with `inputResponses` and the echoed `requestState`. No
//! stream is held open between the two requests.
//!
//! This module models the wire types Zero accepts and the responses it is
//! willing to construct. Form mode is refused for credential-like fields; URL
//! mode is always returned to the host for explicit approval and is never
//! opened, followed, or submitted by this crate.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::jsonrpc::protocol_error;

/// The only input request method implemented by this client.
pub const METHOD_ELICITATION_CREATE: &str = "elicitation/create";

/// How an elicitation request asks for input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InputMode {
    /// In-band structured input described by `requestedSchema`.
    Form,
    /// Out-of-band interaction at a URL the host must approve.
    Url,
}

/// Sensitivity classification for one input request (MCP-08).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputSensitivity {
    /// A form whose fields are not credential-like.
    NonSensitive,
    /// URL mode, which exists precisely for sensitive interactions.
    Sensitive,
}

/// One validated `elicitation/create` request from an `inputRequests` map.
///
/// `id` is the server-assigned key in that map. Unknown server fields are
/// ignored; the message, schema, and URL are untrusted server data and are
/// payload, never instructions.
#[derive(Debug, Clone, PartialEq)]
pub struct InputRequest {
    /// Server-assigned key in `inputRequests`, echoed as the `inputResponses` key.
    pub id: String,
    /// Form or URL mode.
    pub mode: InputMode,
    /// Human-readable reason shown to the user.
    pub message: String,
    /// `requestedSchema` for form mode; `None` for URL mode.
    pub requested_schema: Option<Value>,
    /// Top-level form field names in schema order; empty for URL mode.
    pub fields: Vec<String>,
    /// Target URL for URL mode; `None` for form mode.
    pub url: Option<String>,
    /// Sensitivity classification. Every accepted form is non-sensitive;
    /// URL mode is sensitive by definition.
    pub sensitivity: InputSensitivity,
}

impl InputRequest {
    /// Whether the host must approve this request before it can be accepted.
    pub fn requires_host_approval(&self) -> bool {
        self.mode == InputMode::Url
    }

    /// A host-facing approval action naming the URL, for URL-mode requests.
    ///
    /// The action carries no executable behaviour: this crate never opens or
    /// follows the URL. It only proves that the host produced the action from
    /// an actual URL request, which [`InputResponses::approve_url`] requires.
    pub fn host_action(&self) -> Option<HostAction> {
        self.url.as_ref().map(|url| HostAction {
            request_id: self.id.clone(),
            url: url.clone(),
            message: self.message.clone(),
        })
    }
}

/// A host-facing action that must be approved outside the agent.
///
/// Fields are private and there is no public constructor: the only way to
/// obtain one is [`InputRequest::host_action`] or
/// [`ToolCallOutcome::host_actions`]. That ties approval to the URL request the
/// host actually saw rather than a free-form value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAction {
    request_id: String,
    url: String,
    message: String,
}

impl HostAction {
    /// Key of the URL-mode request this action approves.
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// The exact URL the host must display to the user.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The server's reason for the interaction.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// The classified `tools/call` result (MCP-03).
#[derive(Debug, Clone, PartialEq)]
pub enum ToolCallOutcome {
    /// Final content, retained as raw untrusted data.
    Complete {
        /// `content` array, passed through.
        content: Value,
        /// `structuredContent` when present.
        structured: Option<Value>,
    },
    /// The server needs input before it can finish the call.
    InputRequired {
        /// Parsed elicitation requests, in server map order.
        requests: Vec<InputRequest>,
        /// Opaque `requestState` to echo verbatim on the retry.
        state: Option<Value>,
    },
    /// A `resultType` this client does not know, passed through unchanged.
    Other(String),
}

impl ToolCallOutcome {
    /// Whether the call finished.
    pub fn is_complete(&self) -> bool {
        matches!(self, ToolCallOutcome::Complete { .. })
    }

    /// Whether the server asked for input.
    pub fn is_input_required(&self) -> bool {
        matches!(self, ToolCallOutcome::InputRequired { .. })
    }

    /// The parsed requests, or an empty slice for other outcomes.
    pub fn requests(&self) -> &[InputRequest] {
        match self {
            ToolCallOutcome::InputRequired { requests, .. } => requests,
            _ => &[],
        }
    }

    /// Host-facing approval actions for every URL-mode request.
    ///
    /// Returning these does not open or submit anything; the host decides
    /// whether to show the URL and, if the user consents, call
    /// [`InputResponses::approve_url`].
    pub fn host_actions(&self) -> Vec<HostAction> {
        self.requests()
            .iter()
            .filter_map(InputRequest::host_action)
            .collect()
    }
}

/// The three elicitation outcomes from the specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ElicitationAction {
    /// The user approved and submitted data (form mode) or consented (URL mode).
    Accept,
    /// The user explicitly declined.
    Decline,
    /// The user dismissed the request without choosing.
    Cancel,
}

/// The typed client result sent for one `elicitation/create` request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ElicitationResult {
    /// What the user did.
    pub action: ElicitationAction,
    /// Submitted form data. Present only for form-mode acceptance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
}

impl ElicitationResult {
    /// Accept a form with the submitted content.
    pub fn accept(content: Value) -> Self {
        Self {
            action: ElicitationAction::Accept,
            content: Some(content),
        }
    }

    /// Decline explicitly.
    pub fn decline() -> Self {
        Self {
            action: ElicitationAction::Decline,
            content: None,
        }
    }

    /// Dismiss without a choice.
    pub fn cancel() -> Self {
        Self {
            action: ElicitationAction::Cancel,
            content: None,
        }
    }
}

/// The `inputResponses` map sent on an MRTR retry.
///
/// Responses are constructed through typed helpers, not free-form values. A
/// URL-mode acceptance additionally requires the [`HostAction`] produced by
/// the outcome, so a caller cannot silently accept a URL on the agent's behalf.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct InputResponses {
    responses: BTreeMap<String, Value>,
    approved_urls: BTreeMap<String, String>,
}

impl InputResponses {
    /// An empty response map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether no responses have been recorded.
    pub fn is_empty(&self) -> bool {
        self.responses.is_empty()
    }

    /// Number of recorded responses.
    pub fn len(&self) -> usize {
        self.responses.len()
    }

    /// Accept a non-sensitive form request with `content`.
    pub fn accept_form(&mut self, id: impl Into<String>, content: Value) -> &mut Self {
        self.insert(id.into(), ElicitationResult::accept(content));
        self
    }

    /// Decline a request explicitly.
    pub fn decline(&mut self, id: impl Into<String>) -> &mut Self {
        self.insert(id.into(), ElicitationResult::decline());
        self
    }

    /// Cancel a request.
    pub fn cancel(&mut self, id: impl Into<String>) -> &mut Self {
        self.insert(id.into(), ElicitationResult::cancel());
        self
    }

    /// Record host approval for a URL-mode request.
    ///
    /// `action` must come from [`ToolCallOutcome::host_actions`] or
    /// [`InputRequest::host_action`]. Approval both records the consent and
    /// inserts the URL-mode `{"action": "accept"}` response.
    pub fn approve_url(&mut self, action: &HostAction) -> &mut Self {
        self.approved_urls
            .insert(action.request_id.clone(), action.url.clone());
        self.responses
            .insert(action.request_id.clone(), json!({"action": "accept"}));
        self
    }

    /// The wire `inputResponses` object.
    pub(crate) fn as_value(&self) -> Value {
        Value::Object(
            self.responses
                .iter()
                .map(|(id, response)| (id.clone(), response.clone()))
                .collect(),
        )
    }

    /// Check that every pending request has a response and that URL acceptance
    /// was approved by the host for the matching URL.
    pub(crate) fn validate_for(&self, requests: &[InputRequest]) -> Result<()> {
        for request in requests {
            let Some(response) = self.responses.get(&request.id) else {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "missing response for input request `{}`; accept, decline, or cancel it",
                        request.id
                    ),
                ));
            };
            let action = response.get("action").and_then(Value::as_str);
            if !matches!(action, Some("accept" | "decline" | "cancel")) {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "input response for `{}` must be an elicitation action",
                        request.id
                    ),
                ));
            }
            if request.mode == InputMode::Url && action == Some("accept") {
                let approved = self.approved_urls.get(&request.id);
                if approved.map(String::as_str) != request.url.as_deref() {
                    return Err(ZeroError::new(
                        ErrorCode::PolicyDenied,
                        format!(
                            "URL-mode elicitation `{}` requires explicit host approval before acceptance",
                            request.id
                        ),
                    ));
                }
            }
        }
        for id in self.responses.keys() {
            if !requests.iter().any(|request| &request.id == id) {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!("input response `{id}` does not match any pending input request"),
                ));
            }
        }
        Ok(())
    }

    fn insert(&mut self, id: String, result: ElicitationResult) {
        let value =
            serde_json::to_value(result).expect("an elicitation result must serialize to JSON");
        self.responses.insert(id, value);
    }
}

/// Parse an `inputRequests` map into validated elicitation requests.
pub(crate) fn parse_input_requests(value: &Value) -> Result<Vec<InputRequest>> {
    let object = value.as_object().ok_or_else(|| {
        protocol_error("`inputRequests` must be a JSON object keyed by request id")
    })?;
    let mut requests = Vec::with_capacity(object.len());
    for (id, request) in object {
        requests.push(parse_input_request(id, request)?);
    }
    Ok(requests)
}

fn parse_input_request(id: &str, value: &Value) -> Result<InputRequest> {
    if id.is_empty() {
        return Err(protocol_error("`inputRequests` keys must not be empty"));
    }
    let object = value
        .as_object()
        .ok_or_else(|| protocol_error(format!("input request `{id}` must be a JSON object")))?;
    let method = match object.get("method") {
        Some(Value::String(method)) => method.as_str(),
        Some(other) => {
            return Err(protocol_error(format!(
                "input request `{id}` method must be a string, got {other}"
            )))
        }
        None => {
            return Err(protocol_error(format!(
                "input request `{id}` is missing `method`"
            )))
        }
    };
    if method != METHOD_ELICITATION_CREATE {
        return Err(protocol_error(format!(
            "input request `{id}` uses unsupported method `{method}`; only `{METHOD_ELICITATION_CREATE}` is implemented"
        )));
    }
    let params = object
        .get("params")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            protocol_error(format!(
                "input request `{id}` must carry an elicitation `params` object"
            ))
        })?;
    let message = match params.get("message") {
        Some(Value::String(message)) if !message.trim().is_empty() => message.clone(),
        Some(Value::String(_)) => {
            return Err(protocol_error(format!(
                "input request `{id}` message must not be empty"
            )))
        }
        Some(other) => {
            return Err(protocol_error(format!(
                "input request `{id}` message must be a string, got {other}"
            )))
        }
        None => {
            return Err(protocol_error(format!(
                "input request `{id}` is missing `message`"
            )))
        }
    };
    let mode = match params.get("mode") {
        None | Some(Value::Null) => InputMode::Form,
        Some(Value::String(mode)) if mode == "form" => InputMode::Form,
        Some(Value::String(mode)) if mode == "url" => InputMode::Url,
        Some(Value::String(other)) => {
            return Err(protocol_error(format!(
                "input request `{id}` has unknown elicitation mode `{other}`"
            )))
        }
        Some(other) => {
            return Err(protocol_error(format!(
                "input request `{id}` mode must be a string, got {other}"
            )))
        }
    };

    match mode {
        InputMode::Form => parse_form_request(id, message, params),
        InputMode::Url => parse_url_request(id, message, params),
    }
}

fn parse_form_request(
    id: &str,
    message: String,
    params: &Map<String, Value>,
) -> Result<InputRequest> {
    if params.get("url").is_some_and(|value| !value.is_null()) {
        return Err(protocol_error(format!(
            "form-mode input request `{id}` must not carry `url`"
        )));
    }
    let schema = params.get("requestedSchema").ok_or_else(|| {
        protocol_error(format!(
            "form-mode input request `{id}` is missing `requestedSchema`"
        ))
    })?;
    let schema_object = schema.as_object().ok_or_else(|| {
        protocol_error(format!(
            "form-mode input request `{id}` requestedSchema must be a JSON object"
        ))
    })?;
    match schema_object.get("type") {
        Some(Value::String(kind)) if kind == "object" => {}
        Some(other) => {
            return Err(protocol_error(format!(
                "form-mode input request `{id}` requestedSchema type must be `object`, got {other}"
            )))
        }
        None => {
            return Err(protocol_error(format!(
                "form-mode input request `{id}` requestedSchema must declare type `object`"
            )))
        }
    }
    let properties = schema_object
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            protocol_error(format!(
                "form-mode input request `{id}` requestedSchema must carry a `properties` object"
            ))
        })?;
    let mut fields = Vec::with_capacity(properties.len());
    for (name, property) in properties {
        let property_object = property.as_object().ok_or_else(|| {
            protocol_error(format!(
                "form-mode input request `{id}` field `{name}` must be a schema object"
            ))
        })?;
        if credential_field(name, property_object).is_some() {
            return Err(ZeroError::new(
                ErrorCode::PolicyDenied,
                format!(
                    "form-mode elicitation `{id}` asks for credential field `{name}`; sensitive input must use URL mode"
                ),
            ));
        }
        fields.push(name.clone());
    }
    if let Some(required) = schema_object.get("required") {
        let entries = required.as_array().ok_or_else(|| {
            protocol_error(format!(
                "form-mode input request `{id}` requestedSchema `required` must be an array"
            ))
        })?;
        for entry in entries {
            if !entry.is_string() {
                return Err(protocol_error(format!(
                    "form-mode input request `{id}` requestedSchema `required` entries must be strings"
                )));
            }
        }
    }

    Ok(InputRequest {
        id: id.to_string(),
        mode: InputMode::Form,
        message,
        requested_schema: Some(schema.clone()),
        fields,
        url: None,
        sensitivity: InputSensitivity::NonSensitive,
    })
}

fn parse_url_request(
    id: &str,
    message: String,
    params: &Map<String, Value>,
) -> Result<InputRequest> {
    if params
        .get("requestedSchema")
        .is_some_and(|value| !value.is_null())
    {
        return Err(protocol_error(format!(
            "URL-mode input request `{id}` must not carry `requestedSchema`"
        )));
    }
    let url = match params.get("url") {
        Some(Value::String(url)) => url.clone(),
        Some(other) => {
            return Err(protocol_error(format!(
                "URL-mode input request `{id}` url must be a string, got {other}"
            )))
        }
        None => {
            return Err(protocol_error(format!(
                "URL-mode input request `{id}` is missing `url`"
            )))
        }
    };
    if !is_http_url(&url) {
        return Err(protocol_error(format!(
            "URL-mode input request `{id}` must carry an absolute http(s) URL without whitespace or control characters"
        )));
    }

    Ok(InputRequest {
        id: id.to_string(),
        mode: InputMode::Url,
        message,
        requested_schema: None,
        fields: Vec::new(),
        url: Some(url),
        sensitivity: InputSensitivity::Sensitive,
    })
}

/// Words that mark a form field as credential-bearing. Matching is
/// intentionally conservative: a false refusal is safe, a false acceptance is
/// not.
const CREDENTIAL_MARKERS: &[&str] = &[
    "password",
    "passphrase",
    "passwd",
    "token",
    "apikey",
    "api key",
    "secret",
    "privatekey",
    "private key",
    "cookie",
    "session",
    "credential",
    "otp",
    "one time",
    "pin code",
    "passcode",
    "seed phrase",
    "mnemonic",
    "recovery code",
    "cvv",
];

fn credential_field(name: &str, property: &Map<String, Value>) -> Option<String> {
    if contains_credential_marker(name) {
        return Some(name.to_string());
    }
    for key in ["title", "description", "format"] {
        if let Some(Value::String(value)) = property.get(key) {
            if contains_credential_marker(value) {
                return Some(name.to_string());
            }
        }
    }
    if property.get("writeOnly").and_then(Value::as_bool) == Some(true) {
        return Some(name.to_string());
    }
    None
}

fn contains_credential_marker(value: &str) -> bool {
    let normalised = normalise_label(value);
    CREDENTIAL_MARKERS
        .iter()
        .any(|marker| normalised.contains(marker))
}

/// Lower-case a label and reduce separators to single spaces so `api_key`,
/// `api-key`, and `API Key` all match the same marker.
fn normalise_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut pending_space = false;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            if pending_space && !out.is_empty() {
                out.push(' ');
            }
            out.push(character.to_ascii_lowercase());
            pending_space = false;
        } else {
            pending_space = true;
        }
    }
    out
}

/// Whether `value` is an absolute `http`/`https` URL with an authority.
///
/// This deliberately does not require HTTPS (development servers commonly use
/// HTTP) and does not fetch anything. The host displays the URL verbatim; a
/// non-HTTP scheme is refused because it cannot be safely shown as a link.
fn is_http_url(value: &str) -> bool {
    if value.is_empty()
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return false;
    }
    let Some((scheme, rest)) = value.split_once("://") else {
        return false;
    };
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    !authority.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_markers_cover_names_and_descriptions() {
        assert!(contains_credential_marker("password"));
        assert!(contains_credential_marker("API_KEY"));
        assert!(contains_credential_marker("accessToken"));
        assert!(contains_credential_marker("private-key"));
        assert!(contains_credential_marker("session_id"));
        assert!(contains_credential_marker("Your client secret"));
        assert!(contains_credential_marker("one-time code"));
        assert!(contains_credential_marker("card CVV"));
        assert!(contains_credential_marker("seed phrase"));
        assert!(!contains_credential_marker("shipping address"));
        assert!(!contains_credential_marker("display name"));
        assert!(!contains_credential_marker("email"));
        assert!(!contains_credential_marker("favourite colour"));
    }

    #[test]
    fn only_absolute_http_urls_are_accepted() {
        assert!(is_http_url("https://mcp.example.com/ui/set_api_key"));
        assert!(is_http_url("http://127.0.0.1:8080/consent"));
        assert!(!is_http_url("javascript:alert(1)"));
        assert!(!is_http_url("file:///etc/passwd"));
        assert!(!is_http_url("https://"));
        assert!(!is_http_url("https://mcp.example.com/a b"));
    }

    #[test]
    fn elicitation_results_have_the_specification_shape() {
        assert_eq!(
            serde_json::to_value(ElicitationResult::accept(json!({"name": "octocat"}))).unwrap(),
            json!({"action": "accept", "content": {"name": "octocat"}})
        );
        assert_eq!(
            serde_json::to_value(ElicitationResult::decline()).unwrap(),
            json!({"action": "decline"})
        );
        assert_eq!(
            serde_json::to_value(ElicitationResult::cancel()).unwrap(),
            json!({"action": "cancel"})
        );
    }
}
