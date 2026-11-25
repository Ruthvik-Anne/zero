//! Conformance fixtures for both supported revisions (T-MCP-11, MCP-19).
//!
//! A fixture is declarative JSON: one revision, a name, and an ordered list of
//! exchanges. Each exchange names the JSON-RPC request and response and the
//! parsed outcome the real client types must produce. [`run`] validates the
//! fixture, replays every response through a scripted [`Transport`], drives the
//! actual [`Client`], and reports a pass or a typed failure per exchange.
//!
//! Fixtures contain no code and no Rust expressions. Adding an exchange never
//! requires changing the runner unless it uses a method the runner does not
//! drive yet.
//!
//! The checked-in fixtures live under `tests/fixtures/conformance/` and are
//! exercised by `crates/zero-mcp/tests/conformance.rs`, so the suite runs under
//! `cargo test -p zero-mcp` and therefore in CI.

use std::cell::{Cell, RefCell};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use zero_types::error::{Result as ZeroResult, ZeroError};

use crate::client::{
    Client, ToolCatalog, Transport, METHOD_INITIALIZE, METHOD_TOOLS_CALL, METHOD_TOOLS_LIST,
};
use crate::jsonrpc::{protocol_error, RequestId};
use crate::mrtr::{InputMode, InputResponses, ToolCallOutcome};
use crate::resources::{
    PromptCatalog, ResourceCatalog, METHOD_PROMPTS_LIST, METHOD_RESOURCES_LIST,
};
use crate::revision::McpRevision;
use crate::tasks::{TaskId, METHOD_TASKS_GET};

/// Fixture schema version understood by this runner.
pub const CONFORMANCE_SCHEMA_VERSION: u32 = 1;

/// Methods the runner can replay. A fixture that names another method is a
/// structural error rather than a silently skipped exchange.
pub const SUPPORTED_METHODS: &[&str] = &[
    METHOD_INITIALIZE,
    METHOD_TOOLS_LIST,
    METHOD_TOOLS_CALL,
    METHOD_RESOURCES_LIST,
    METHOD_PROMPTS_LIST,
    METHOD_TASKS_GET,
];

/// A versioned conformance fixture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceFixture {
    /// Fixture format version; must equal [`CONFORMANCE_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The revision this whole fixture exercises, as a wire string.
    pub revision: String,
    /// Human-readable fixture name, also used as the scripted server name.
    pub name: String,
    /// Ordered exchanges; responses are returned in this exact order.
    pub exchanges: Vec<Exchange>,
}

/// One request/response pair and the outcome it must produce.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exchange {
    /// Exchange name used in pass/fail reports.
    pub name: String,
    /// The expected JSON-RPC request. `id` and `method` are checked on the
    /// wire; `params` drive the call for `tools/call` and `tasks/get`.
    pub request: Value,
    /// The JSON-RPC response envelope to return in order.
    pub response: Value,
    /// The parsed outcome the real client must produce.
    pub expected: Expected,
}

/// Declarative expectations for one exchange.
///
/// Every field is optional; at least one must be present. Only the fields a
/// fixture declares are compared, so an exchange does not need to restate the
/// whole result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expected {
    /// Revision selected by `initialize`; must match the fixture revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub negotiated_revision: Option<String>,
    /// Tool names in server order, parsed from `tools/list`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_names: Option<Vec<String>>,
    /// Stable `ToolCatalog::schema_hash`, as 16 lower-case hex digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_catalog_hash: Option<String>,
    /// Tool names whose parsed `annotations.readOnlyHint` is `true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_tools: Option<Vec<String>>,
    /// Classified `resultType`: `complete`, `input_required`, `task`, or a
    /// value this client passes through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_type: Option<String>,
    /// `tools/call` content blocks on a complete result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Vec<Value>>,
    /// `tools/call` `structuredContent` on a complete result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_content: Option<Value>,
    /// Task state from a `task` result or `tasks/get`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_state: Option<String>,
    /// Number of parsed elicitation requests in an `input_required` result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_request_count: Option<usize>,
    /// Resource names parsed from `resources/list`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_names: Option<Vec<String>>,
    /// Prompt names parsed from `prompts/list`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_names: Option<Vec<String>>,
    /// JSON-RPC error code the response must carry and the client must surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<i64>,
}

impl Expected {
    fn is_empty(&self) -> bool {
        self.negotiated_revision.is_none()
            && self.tool_names.is_none()
            && self.tool_catalog_hash.is_none()
            && self.read_only_tools.is_none()
            && self.result_type.is_none()
            && self.content.is_none()
            && self.structured_content.is_none()
            && self.task_state.is_none()
            && self.input_request_count.is_none()
            && self.resource_names.is_none()
            && self.prompt_names.is_none()
            && self.error_code.is_none()
    }
}

/// A structural fixture problem. These are returned from [`run`] before or
/// during replay; they never panic.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConformanceError {
    /// The fixture was written for a newer runner.
    #[error("fixture `{fixture}` uses unsupported schema_version {version}; expected {expected}")]
    UnsupportedSchemaVersion {
        /// Fixture name.
        fixture: String,
        /// Version found in the fixture.
        version: u32,
        /// Version this runner understands.
        expected: u32,
    },
    /// A fixture with nothing to replay cannot prove anything.
    #[error("fixture `{fixture}` has no exchanges")]
    NoExchanges {
        /// Fixture name.
        fixture: String,
    },
    /// The fixture names a revision this client does not speak.
    #[error("fixture `{fixture}` revision `{revision}` is unsupported: {detail}")]
    UnsupportedRevision {
        /// Fixture name.
        fixture: String,
        /// Revision as written in the fixture.
        revision: String,
        /// Why the revision was rejected.
        detail: String,
    },
    /// The fixture or an exchange field is malformed.
    #[error("fixture `{fixture}` exchange `{exchange}` is invalid: {detail}")]
    InvalidExchange {
        /// Fixture name.
        fixture: String,
        /// Exchange name.
        exchange: String,
        /// What is wrong.
        detail: String,
    },
    /// The client did not follow the scripted exchange order.
    #[error("fixture `{fixture}` failed while replaying exchange `{exchange}`: {detail}")]
    Replay {
        /// Fixture name.
        fixture: String,
        /// Exchange name.
        exchange: String,
        /// Transport or request-order problem.
        detail: String,
    },
    /// A fixture file could not be read.
    #[error("could not read fixture `{path}`: {detail}")]
    Read {
        /// Path that was attempted.
        path: String,
        /// Underlying I/O problem.
        detail: String,
    },
    /// A fixture file is not valid JSON for the declared format.
    #[error("could not parse conformance fixture: {detail}")]
    Parse {
        /// Serde parse error.
        detail: String,
    },
}

/// Result type used by fixture loading and replay.
pub type ConformanceResult<T> = std::result::Result<T, ConformanceError>;

impl ConformanceFixture {
    /// Load and validate a fixture file.
    pub fn load(path: impl AsRef<Path>) -> ConformanceResult<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|error| ConformanceError::Read {
            path: path.display().to_string(),
            detail: error.to_string(),
        })?;
        Self::from_json(&text)
    }

    /// Parse and validate fixture JSON.
    pub fn from_json(text: &str) -> ConformanceResult<Self> {
        let fixture: Self =
            serde_json::from_str(text).map_err(|error| ConformanceError::Parse {
                detail: error.to_string(),
            })?;
        fixture.validate()?;
        Ok(fixture)
    }

    /// Validate the shape, revision, and exchange order before replay.
    pub fn validate(&self) -> ConformanceResult<McpRevision> {
        if self.schema_version != CONFORMANCE_SCHEMA_VERSION {
            return Err(ConformanceError::UnsupportedSchemaVersion {
                fixture: self.name.clone(),
                version: self.schema_version,
                expected: CONFORMANCE_SCHEMA_VERSION,
            });
        }
        if self.name.trim().is_empty() {
            return Err(ConformanceError::InvalidExchange {
                fixture: self.name.clone(),
                exchange: "<fixture>".to_string(),
                detail: "fixture name must not be empty".to_string(),
            });
        }
        let revision = McpRevision::parse(&self.revision).map_err(|error| {
            ConformanceError::UnsupportedRevision {
                fixture: self.name.clone(),
                revision: self.revision.clone(),
                detail: error.message().to_string(),
            }
        })?;
        if self.exchanges.is_empty() {
            return Err(ConformanceError::NoExchanges {
                fixture: self.name.clone(),
            });
        }
        for (index, exchange) in self.exchanges.iter().enumerate() {
            exchange.validate(index, revision, &self.name)?;
        }
        Ok(revision)
    }
}

impl Exchange {
    fn validate(
        &self,
        index: usize,
        revision: McpRevision,
        fixture: &str,
    ) -> ConformanceResult<()> {
        let invalid = |detail: String| ConformanceError::InvalidExchange {
            fixture: fixture.to_string(),
            exchange: self.name.clone(),
            detail,
        };
        if self.name.trim().is_empty() {
            return Err(invalid("exchange name must not be empty".to_string()));
        }

        let request = self
            .request
            .as_object()
            .ok_or_else(|| invalid("`request` must be a JSON object".to_string()))?;
        if request.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(invalid("`request.jsonrpc` must be \"2.0\"".to_string()));
        }
        let request_id = parse_request_id(request.get("id"))
            .ok_or_else(|| invalid("`request.id` must be a non-negative integer".to_string()))?;
        let expected_id = RequestId::Number(index as u64 + 1);
        if request_id != expected_id {
            return Err(invalid(format!(
                "`request.id` is {request_id} but exchange {index} must use id {expected_id} so responses replay in order"
            )));
        }
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("`request.method` must be a string".to_string()))?;
        if !SUPPORTED_METHODS.contains(&method) {
            return Err(invalid(format!(
                "unsupported request method `{method}`; the runner drives {SUPPORTED_METHODS:?}"
            )));
        }
        self.validate_request_params(request, method, revision, &invalid)?;

        let response = self
            .response
            .as_object()
            .ok_or_else(|| invalid("`response` must be a JSON object".to_string()))?;
        if response.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(invalid("`response.jsonrpc` must be \"2.0\"".to_string()));
        }
        let response_id = parse_request_id(response.get("id"))
            .ok_or_else(|| invalid("`response.id` must be a non-negative integer".to_string()))?;
        if response_id != request_id {
            return Err(invalid(format!(
                "`response.id` is {response_id} but the request id is {request_id}"
            )));
        }

        let has_result = response.get("result").is_some();
        let error = response.get("error").filter(|value| !value.is_null());
        if has_result && error.is_some() {
            return Err(invalid(
                "`response` must contain either `result` or `error`, not both".to_string(),
            ));
        }
        if !has_result && error.is_none() {
            return Err(invalid(
                "`response` must contain either `result` or `error`".to_string(),
            ));
        }

        if let Some(error) = error {
            let code = response_error_code(error)
                .ok_or_else(|| invalid("`response.error.code` must be an integer".to_string()))?;
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("`response.error.message` must be a string".to_string()))?;
            if message.is_empty() {
                return Err(invalid(
                    "`response.error.message` must not be empty".to_string(),
                ));
            }
            if self.expected.error_code != Some(code) {
                return Err(invalid(format!(
                    "error response code {code} must be declared as `expected.error_code`"
                )));
            }
            if !self.expected_only_error_code() {
                return Err(invalid(
                    "an error exchange may declare only `expected.error_code`".to_string(),
                ));
            }
            return Ok(());
        }

        if self.expected.error_code.is_some() {
            return Err(invalid(
                "`expected.error_code` requires an `error` response".to_string(),
            ));
        }
        let result = response
            .get("result")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("`response.result` must be a JSON object".to_string()))?;
        if let Some(version) = result.get("protocolVersion") {
            let version = version.as_str().ok_or_else(|| {
                invalid("`response.result.protocolVersion` must be a string".to_string())
            })?;
            if version != revision.as_str() {
                return Err(invalid(format!(
                    "response revision `{version}` does not match fixture revision `{revision}`"
                )));
            }
        }
        if let Some(version) = result
            .get("_meta")
            .and_then(Value::as_object)
            .and_then(|meta| meta.get("protocolVersion"))
            .and_then(Value::as_str)
        {
            if version != revision.as_str() {
                return Err(invalid(format!(
                    "response `_meta.protocolVersion` `{version}` does not match fixture revision `{revision}`"
                )));
            }
        }
        if method == METHOD_INITIALIZE && !result.contains_key("protocolVersion") {
            return Err(invalid(
                "`initialize` result is missing `protocolVersion`".to_string(),
            ));
        }
        if let Some(result_type) = result.get("resultType") {
            if !result_type.is_string() {
                return Err(invalid(
                    "`response.result.resultType` must be a string".to_string(),
                ));
            }
        }

        if self.expected.is_empty() {
            return Err(invalid(
                "`expected` must declare at least one outcome".to_string(),
            ));
        }
        if let Some(version) = &self.expected.negotiated_revision {
            if version != revision.as_str() {
                return Err(invalid(format!(
                    "`expected.negotiated_revision` `{version}` does not match fixture revision `{revision}`"
                )));
            }
        }
        if let Some(hash) = &self.expected.tool_catalog_hash {
            if hash.len() != 16 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(invalid(
                    "`expected.tool_catalog_hash` must be 16 hex digits".to_string(),
                ));
            }
            if u64::from_str_radix(hash, 16).is_err() {
                return Err(invalid(
                    "`expected.tool_catalog_hash` must be 16 hex digits".to_string(),
                ));
            }
        }
        if let Some(result_type) = &self.expected.result_type {
            if result_type.is_empty() {
                return Err(invalid(
                    "`expected.result_type` must not be empty".to_string(),
                ));
            }
        }
        if let Some(state) = &self.expected.task_state {
            if state.is_empty() {
                return Err(invalid(
                    "`expected.task_state` must not be empty".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn validate_request_params(
        &self,
        request: &Map<String, Value>,
        method: &str,
        revision: McpRevision,
        invalid: &impl Fn(String) -> ConformanceError,
    ) -> ConformanceResult<()> {
        let params = request.get("params");
        match method {
            METHOD_INITIALIZE => {
                let params = params.and_then(Value::as_object).ok_or_else(|| {
                    invalid("`initialize` requires a `request.params` object".to_string())
                })?;
                let version = params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        invalid(
                            "`initialize` `request.params.protocolVersion` must be a string"
                                .to_string(),
                        )
                    })?;
                if version != revision.as_str() {
                    return Err(invalid(format!(
                        "`initialize` requests `{version}` but the fixture revision is `{revision}`"
                    )));
                }
            }
            METHOD_TOOLS_CALL => {
                let params = params.and_then(Value::as_object).ok_or_else(|| {
                    invalid("`tools/call` requires a `request.params` object".to_string())
                })?;
                if params.get("name").and_then(Value::as_str).is_none() {
                    return Err(invalid(
                        "`tools/call` `request.params.name` must be a string".to_string(),
                    ));
                }
                if let Some(responses) = params.get("inputResponses") {
                    if !responses.is_object() {
                        return Err(invalid(
                            "`tools/call` `request.params.inputResponses` must be an object"
                                .to_string(),
                        ));
                    }
                }
            }
            METHOD_TASKS_GET => {
                let params = params.and_then(Value::as_object).ok_or_else(|| {
                    invalid("`tasks/get` requires a `request.params` object".to_string())
                })?;
                if params.get("taskId").and_then(Value::as_str).is_none() {
                    return Err(invalid(
                        "`tasks/get` `request.params.taskId` must be a string".to_string(),
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn expected_only_error_code(&self) -> bool {
        let mut only_error = self.expected.clone();
        only_error.error_code = None;
        only_error.is_empty()
    }
}

/// One exchange's pass/fail result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeReport {
    /// Exchange name from the fixture.
    pub name: String,
    /// `None` on a pass.
    pub failure: Option<ConformanceFailure>,
}

/// A typed expectation failure. Never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceFailure {
    /// What class of mismatch was found.
    pub kind: ConformanceFailureKind,
    /// Human-readable detail listing every mismatch.
    pub detail: String,
}

/// Why an exchange failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConformanceFailureKind {
    /// A declared expectation did not match the parsed outcome.
    ExpectationMismatch,
    /// The fixture expected an error but the client accepted the result.
    UnexpectedSuccess,
    /// The client returned an error the fixture did not expect.
    UnexpectedError,
    /// The parsed `tools/list` catalogue was not cached as required.
    CacheMiss,
}

/// Counts, per-exchange outcomes, and the failure list for one fixture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceReport {
    /// Fixture name.
    pub fixture: String,
    /// Revision the fixture exercised.
    pub revision: McpRevision,
    /// One report per exchange, in fixture order.
    pub exchanges: Vec<ExchangeReport>,
}

impl ConformanceReport {
    /// Number of exchanges that passed.
    pub fn passed(&self) -> usize {
        self.exchanges
            .iter()
            .filter(|exchange| exchange.failure.is_none())
            .count()
    }

    /// Number of exchanges that failed.
    pub fn failed(&self) -> usize {
        self.exchanges.len() - self.passed()
    }

    /// Whether every exchange passed.
    pub fn is_success(&self) -> bool {
        self.failed() == 0
    }

    /// The non-empty failure list, in fixture order.
    pub fn failures(&self) -> Vec<&ConformanceFailure> {
        self.exchanges
            .iter()
            .filter_map(|exchange| exchange.failure.as_ref())
            .collect()
    }
}

/// Replay a validated fixture through the real client types.
///
/// Structural problems return [`ConformanceError`]. An expectation mismatch is
/// recorded in the returned report so every exchange is attempted and reported.
pub fn run(fixture: &ConformanceFixture) -> ConformanceResult<ConformanceReport> {
    let revision = fixture.validate()?;
    let transport = ScriptedTransport::new(&fixture.exchanges);
    let mut client = Client::new(fixture.name.clone(), &transport).with_revision(revision);
    let mut pending: Option<ToolCallOutcome> = None;
    let mut exchanges = Vec::with_capacity(fixture.exchanges.len());

    for (index, exchange) in fixture.exchanges.iter().enumerate() {
        let method = exchange
            .request
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let call = dispatch(&mut client, exchange, &mut pending, &fixture.name)?;

        if let Some(detail) = transport.take_fault() {
            return Err(ConformanceError::Replay {
                fixture: fixture.name.clone(),
                exchange: exchange.name.clone(),
                detail,
            });
        }
        let sent = transport.position();
        if sent != index + 1 {
            return Err(ConformanceError::Replay {
                fixture: fixture.name.clone(),
                exchange: exchange.name.clone(),
                detail: format!(
                    "exchange sent {} request(s); a fixture exchange must send exactly one",
                    sent.saturating_sub(index)
                ),
            });
        }

        let expected_error = exchange.expected.error_code;
        let failure = match call {
            ObservedCall::Parsed(observed) => {
                if let Some(code) = expected_error {
                    Some(ConformanceFailure {
                        kind: ConformanceFailureKind::UnexpectedSuccess,
                        detail: format!(
                            "expected JSON-RPC error {code}, but the client accepted the result"
                        ),
                    })
                } else {
                    let mut mismatches = evaluate(&exchange.expected, &observed);
                    if method == METHOD_TOOLS_LIST {
                        mismatches.extend(check_cache(&client, exchange, &observed));
                    }
                    report_failure(mismatches)
                }
            }
            ObservedCall::ClientError(error) => match expected_error {
                Some(code) => {
                    let observed = Observed {
                        error_code: exchange.response.get("error").and_then(response_error_code),
                        ..Observed::default()
                    };
                    let mut mismatches = evaluate(&exchange.expected, &observed);
                    if !error.message().contains(&code.to_string()) {
                        mismatches.push(format!(
                            "the client error did not surface JSON-RPC code {code}: {}",
                            error.message()
                        ));
                    }
                    report_failure(mismatches)
                }
                None => Some(ConformanceFailure {
                    kind: ConformanceFailureKind::UnexpectedError,
                    detail: error.to_string(),
                }),
            },
        };

        exchanges.push(ExchangeReport {
            name: exchange.name.clone(),
            failure,
        });
    }

    Ok(ConformanceReport {
        fixture: fixture.name.clone(),
        revision,
        exchanges,
    })
}

fn report_failure(mismatches: Vec<String>) -> Option<ConformanceFailure> {
    if mismatches.is_empty() {
        None
    } else {
        Some(ConformanceFailure {
            kind: ConformanceFailureKind::ExpectationMismatch,
            detail: mismatches.join("; "),
        })
    }
}

/// What the real client produced for one exchange.
enum ObservedCall {
    Parsed(Box<Observed>),
    ClientError(ZeroError),
}

/// Normalised parsed outcome, so expectations compare uniformly.
#[derive(Debug, Clone, Default, PartialEq)]
struct Observed {
    negotiated_revision: Option<String>,
    tool_names: Option<Vec<String>>,
    tool_catalog_hash: Option<String>,
    read_only_tools: Option<Vec<String>>,
    result_type: Option<String>,
    content: Option<Vec<Value>>,
    structured_content: Option<Value>,
    task_state: Option<String>,
    input_request_count: Option<usize>,
    resource_names: Option<Vec<String>>,
    prompt_names: Option<Vec<String>>,
    error_code: Option<i64>,
}

impl Observed {
    fn from_initialize(result: &crate::client::InitializeResult) -> Self {
        Self {
            negotiated_revision: Some(result.protocol_version.as_str().to_string()),
            result_type: Some(result.result_type.as_str().to_string()),
            ..Self::default()
        }
    }

    fn from_catalog(catalog: &ToolCatalog) -> Self {
        Self {
            tool_names: Some(catalog.tools.iter().map(|tool| tool.name.clone()).collect()),
            tool_catalog_hash: Some(format!("{:016x}", catalog.schema_hash())),
            read_only_tools: Some(
                catalog
                    .tools
                    .iter()
                    .filter(|tool| {
                        tool.annotations
                            .as_ref()
                            .and_then(|annotations| annotations.read_only_hint)
                            == Some(true)
                    })
                    .map(|tool| tool.name.clone())
                    .collect(),
            ),
            result_type: Some(catalog.result_type.as_str().to_string()),
            ..Self::default()
        }
    }

    fn from_outcome(outcome: &ToolCallOutcome) -> Self {
        match outcome {
            ToolCallOutcome::Complete {
                content,
                structured,
            } => Self {
                result_type: Some("complete".to_string()),
                content: content.as_array().cloned(),
                structured_content: structured.clone(),
                ..Self::default()
            },
            ToolCallOutcome::InputRequired { requests, .. } => Self {
                result_type: Some("input_required".to_string()),
                input_request_count: Some(requests.len()),
                ..Self::default()
            },
            ToolCallOutcome::Task(task) => Self {
                result_type: Some("task".to_string()),
                task_state: Some(task.state.as_str().to_string()),
                ..Self::default()
            },
            ToolCallOutcome::Other(value) => Self {
                result_type: Some(value.clone()),
                ..Self::default()
            },
        }
    }

    fn from_task(task: &crate::tasks::Task) -> Self {
        Self {
            result_type: Some("complete".to_string()),
            task_state: Some(task.state.as_str().to_string()),
            ..Self::default()
        }
    }

    fn from_resources(catalog: &ResourceCatalog) -> Self {
        Self {
            resource_names: Some(
                catalog
                    .resources
                    .iter()
                    .map(|resource| resource.name.clone())
                    .collect(),
            ),
            ..Self::default()
        }
    }

    fn from_prompts(catalog: &PromptCatalog) -> Self {
        Self {
            prompt_names: Some(
                catalog
                    .prompts
                    .iter()
                    .map(|prompt| prompt.name.clone())
                    .collect(),
            ),
            ..Self::default()
        }
    }
}

fn dispatch<T: Transport>(
    client: &mut Client<T>,
    exchange: &Exchange,
    pending: &mut Option<ToolCallOutcome>,
    fixture: &str,
) -> ConformanceResult<ObservedCall> {
    let method = exchange
        .request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let invalid = |detail: String| ConformanceError::InvalidExchange {
        fixture: fixture.to_string(),
        exchange: exchange.name.clone(),
        detail,
    };

    match method {
        METHOD_INITIALIZE => Ok(match client.initialize() {
            Ok(result) => ObservedCall::Parsed(Box::new(Observed::from_initialize(&result))),
            Err(error) => ObservedCall::ClientError(error),
        }),
        METHOD_TOOLS_LIST => Ok(match client.tools_list() {
            Ok(catalog) => ObservedCall::Parsed(Box::new(Observed::from_catalog(&catalog))),
            Err(error) => ObservedCall::ClientError(error),
        }),
        METHOD_TOOLS_CALL => dispatch_tools_call(client, exchange, pending, fixture),
        METHOD_RESOURCES_LIST => {
            let result = client.exchange(METHOD_RESOURCES_LIST, Some(json!({})));
            Ok(match result {
                Ok(value) => match ResourceCatalog::from_resources_list("conformance", &value) {
                    Ok(catalog) => {
                        ObservedCall::Parsed(Box::new(Observed::from_resources(&catalog)))
                    }
                    Err(error) => ObservedCall::ClientError(error),
                },
                Err(error) => ObservedCall::ClientError(error),
            })
        }
        METHOD_PROMPTS_LIST => {
            let result = client.exchange(METHOD_PROMPTS_LIST, Some(json!({})));
            Ok(match result {
                Ok(value) => match PromptCatalog::parse("conformance", &value) {
                    Ok(catalog) => ObservedCall::Parsed(Box::new(Observed::from_prompts(&catalog))),
                    Err(error) => ObservedCall::ClientError(error),
                },
                Err(error) => ObservedCall::ClientError(error),
            })
        }
        METHOD_TASKS_GET => {
            let params = exchange
                .request
                .get("params")
                .and_then(Value::as_object)
                .ok_or_else(|| invalid("`tasks/get` needs params".to_string()))?;
            let task_id = params
                .get("taskId")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("`tasks/get` needs `taskId`".to_string()))?;
            Ok(match client.tasks_get(&TaskId::new(task_id)) {
                Ok(task) => ObservedCall::Parsed(Box::new(Observed::from_task(&task))),
                Err(error) => ObservedCall::ClientError(error),
            })
        }
        other => Err(invalid(format!("unsupported method `{other}`"))),
    }
}

fn dispatch_tools_call<T: Transport>(
    client: &mut Client<T>,
    exchange: &Exchange,
    pending: &mut Option<ToolCallOutcome>,
    fixture: &str,
) -> ConformanceResult<ObservedCall> {
    let invalid = |detail: String| ConformanceError::InvalidExchange {
        fixture: fixture.to_string(),
        exchange: exchange.name.clone(),
        detail,
    };
    let params = exchange
        .request
        .get("params")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("`tools/call` needs `request.params`".to_string()))?;

    if let Some(raw_responses) = params.get("inputResponses") {
        let previous = pending.take().ok_or_else(|| {
            invalid(
                "a retry exchange must follow an `input_required` exchange in the same fixture"
                    .to_string(),
            )
        })?;
        let responses =
            build_input_responses(raw_responses, previous.requests()).map_err(invalid)?;
        return Ok(match client.retry_with_inputs(responses) {
            Ok(outcome) => ObservedCall::Parsed(Box::new(Observed::from_outcome(&outcome))),
            Err(error) => ObservedCall::ClientError(error),
        });
    }

    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("`tools/call` needs `request.params.name`".to_string()))?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    Ok(match client.tools_call_outcome(name, arguments) {
        Ok(outcome) => {
            *pending = match &outcome {
                ToolCallOutcome::InputRequired { .. } => Some(outcome.clone()),
                _ => None,
            };
            ObservedCall::Parsed(Box::new(Observed::from_outcome(&outcome)))
        }
        Err(error) => ObservedCall::ClientError(error),
    })
}

fn build_input_responses(
    raw: &Value,
    requests: &[crate::mrtr::InputRequest],
) -> std::result::Result<InputResponses, String> {
    let object = raw
        .as_object()
        .ok_or_else(|| "`inputResponses` must be a JSON object".to_string())?;
    for key in object.keys() {
        if !requests.iter().any(|request| &request.id == key) {
            return Err(format!(
                "input response `{key}` does not match any pending request"
            ));
        }
    }

    let mut responses = InputResponses::new();
    for request in requests {
        let value = object
            .get(&request.id)
            .ok_or_else(|| format!("missing input response for `{}`", request.id))?;
        let response = value
            .as_object()
            .ok_or_else(|| format!("input response for `{}` must be an object", request.id))?;
        let action = response
            .get("action")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!(
                    "input response for `{}` must carry a string `action`",
                    request.id
                )
            })?;
        match action {
            "accept" => match request.mode {
                InputMode::Form => {
                    let content = response
                        .get("content")
                        .cloned()
                        .unwrap_or_else(|| json!({}));
                    responses.accept_form(request.id.clone(), content);
                }
                InputMode::Url => {
                    let host_action = request.host_action().ok_or_else(|| {
                        format!("URL-mode request `{}` carries no URL", request.id)
                    })?;
                    responses.approve_url(&host_action);
                }
            },
            "decline" => {
                responses.decline(request.id.clone());
            }
            "cancel" => {
                responses.cancel(request.id.clone());
            }
            other => {
                return Err(format!(
                    "input response for `{}` has unknown action `{other}`",
                    request.id
                ))
            }
        }
    }
    Ok(responses)
}

fn evaluate(expected: &Expected, observed: &Observed) -> Vec<String> {
    let mut mismatches = Vec::new();
    compare(
        "negotiated_revision",
        &expected.negotiated_revision,
        &observed.negotiated_revision,
        &mut mismatches,
    );
    compare(
        "tool_names",
        &expected.tool_names,
        &observed.tool_names,
        &mut mismatches,
    );
    compare(
        "tool_catalog_hash",
        &expected.tool_catalog_hash,
        &observed.tool_catalog_hash,
        &mut mismatches,
    );
    compare(
        "read_only_tools",
        &expected.read_only_tools,
        &observed.read_only_tools,
        &mut mismatches,
    );
    compare(
        "result_type",
        &expected.result_type,
        &observed.result_type,
        &mut mismatches,
    );
    compare(
        "content",
        &expected.content,
        &observed.content,
        &mut mismatches,
    );
    compare(
        "structured_content",
        &expected.structured_content,
        &observed.structured_content,
        &mut mismatches,
    );
    compare(
        "task_state",
        &expected.task_state,
        &observed.task_state,
        &mut mismatches,
    );
    compare(
        "input_request_count",
        &expected.input_request_count,
        &observed.input_request_count,
        &mut mismatches,
    );
    compare(
        "resource_names",
        &expected.resource_names,
        &observed.resource_names,
        &mut mismatches,
    );
    compare(
        "prompt_names",
        &expected.prompt_names,
        &observed.prompt_names,
        &mut mismatches,
    );
    compare(
        "error_code",
        &expected.error_code,
        &observed.error_code,
        &mut mismatches,
    );
    mismatches
}

fn compare<T: PartialEq + std::fmt::Debug>(
    field: &str,
    expected: &Option<T>,
    observed: &Option<T>,
    mismatches: &mut Vec<String>,
) {
    let Some(expected) = expected else {
        return;
    };
    match observed {
        Some(actual) if actual == expected => {}
        Some(actual) => mismatches.push(format!(
            "`{field}` expected {expected:?}, observed {actual:?}"
        )),
        None => mismatches.push(format!(
            "`{field}` expected {expected:?}, but the exchange produced no value"
        )),
    }
}

/// Verify the parsed `tools/list` catalogue is cached (unless `ttlMs` is `0`).
fn check_cache<T: Transport>(
    client: &Client<T>,
    exchange: &Exchange,
    observed: &Observed,
) -> Vec<String> {
    let ttl = exchange
        .response
        .pointer("/result/ttlMs")
        .and_then(Value::as_u64);
    let cached = client.cached_tools();
    if ttl == Some(0) {
        return if cached.is_some() {
            vec!["`ttlMs: 0` must not be served from the catalogue cache".to_string()]
        } else {
            Vec::new()
        };
    }

    match cached {
        None => vec!["the parsed `tools/list` catalogue was not cached".to_string()],
        Some(catalog) => {
            let cached = Observed::from_catalog(catalog);
            let mut mismatches = Vec::new();
            compare(
                "cached tool_names",
                &observed.tool_names,
                &cached.tool_names,
                &mut mismatches,
            );
            compare(
                "cached tool_catalog_hash",
                &observed.tool_catalog_hash,
                &cached.tool_catalog_hash,
                &mut mismatches,
            );
            mismatches
        }
    }
}

fn parse_request_id(value: Option<&Value>) -> Option<RequestId> {
    let value = value?;
    serde_json::from_value::<RequestId>(value.clone()).ok()
}

fn response_error_code(error: &Value) -> Option<i64> {
    error.get("code").and_then(Value::as_i64)
}

// ---------------------------------------------------------------------------
// Scripted transport
// ---------------------------------------------------------------------------

struct ScriptedExpectation {
    id: RequestId,
    method: String,
    response: Value,
}

struct ScriptedTransport {
    expectations: Vec<ScriptedExpectation>,
    cursor: Cell<usize>,
    fault: RefCell<Option<String>>,
}

impl ScriptedTransport {
    fn new(exchanges: &[Exchange]) -> Self {
        let expectations = exchanges
            .iter()
            .filter_map(|exchange| {
                let request = exchange.request.as_object()?;
                Some(ScriptedExpectation {
                    id: parse_request_id(request.get("id"))?,
                    method: request.get("method")?.as_str()?.to_string(),
                    response: exchange.response.clone(),
                })
            })
            .collect();
        Self {
            expectations,
            cursor: Cell::new(0),
            fault: RefCell::new(None),
        }
    }

    fn position(&self) -> usize {
        self.cursor.get()
    }

    fn take_fault(&self) -> Option<String> {
        self.fault.borrow_mut().take()
    }

    fn fail(&self, detail: String) -> ZeroResult<Value> {
        *self.fault.borrow_mut() = Some(detail.clone());
        Err(protocol_error(detail))
    }
}

impl Transport for ScriptedTransport {
    fn exchange(&self, request: &Value) -> ZeroResult<Value> {
        let index = self.cursor.get();
        let Some(expected) = self.expectations.get(index) else {
            return self
                .fail("the client sent a request after the last fixture exchange".to_string());
        };

        if request.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return self.fail("the client sent a request without `jsonrpc: \"2.0\"`".to_string());
        }
        let id = match parse_request_id(request.get("id")) {
            Some(id) => id,
            None => return self.fail("the client sent a request without a numeric id".to_string()),
        };
        if id != expected.id {
            return self.fail(format!(
                "request id {id} arrived out of order; the fixture expects {}",
                expected.id
            ));
        }
        if request.get("method").and_then(Value::as_str) != Some(expected.method.as_str()) {
            return self.fail(format!(
                "request method arrived out of order; the fixture expects `{}`",
                expected.method
            ));
        }
        self.cursor.set(index + 1);
        Ok(expected.response.clone())
    }
}
