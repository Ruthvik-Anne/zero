//! Stateless MCP core client (MCP-01..MCP-05).
//!
//! The client speaks JSON-RPC 2.0 over an in-memory [`Transport`]. There is no
//! protocol session, no `Mcp-Session-Id`, and no required handshake: callers may
//! use the [`Client::current_revision`] default before `initialize`, or
//! negotiate a revision with [`Client::initialize`] and keep it for later calls.
//!
//! The stdio and Streamable HTTP transports live in [`crate::transport`] (T-MCP-02)
//! and implement the [`Transport`] seam; the legacy HTTP+SSE shim is off by
//! default.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use zero_types::clock::{Clock, SystemClock, Timestamp};
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::headers::{Headers, HEADER_METHOD, HEADER_NAME, HEADER_PROTOCOL_VERSION};
use crate::jsonrpc::{expect_object, expect_result, protocol_error, Request, RequestId};
use crate::mrtr::{parse_input_requests, InputRequest, InputResponses, ToolCallOutcome};
use crate::revision::McpRevision;
use crate::schema::{hash_bytes, hash_start, schema_hash, SchemaLimits};

/// `initialize` method name.
pub const METHOD_INITIALIZE: &str = "initialize";
/// `tools/list` method name.
pub const METHOD_TOOLS_LIST: &str = "tools/list";
/// `tools/call` method name.
pub const METHOD_TOOLS_CALL: &str = "tools/call";

/// Client name reported in `initialize.clientInfo`.
pub const CLIENT_NAME: &str = "zero";

/// `resultType` classification (MCP-03).
///
/// Revisions before `2026-07-28` do not define `resultType`; their results are
/// treated as [`ResultType::Complete`]. The `2026-07-28` core defines
/// `complete` and `input_required`; an unrecognised string is preserved as
/// [`ResultType::Other`] so a newer server does not break the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultType {
    /// The result is final.
    Complete,
    /// The server needs more input; retrying with `inputResponses` is T-MCP-03.
    InputRequired,
    /// A `resultType` this client does not know, passed through unchanged.
    Other(String),
}

impl ResultType {
    /// Read `resultType` from a result object under a negotiated revision.
    ///
    /// A missing (or null) field is treated as `complete`, which keeps older
    /// servers and tolerant servers working; this is documented in
    /// `docs/mcp.md`. A non-string value is a protocol error.
    pub fn from_result(revision: McpRevision, result: &Map<String, Value>) -> Result<Self> {
        if !revision.supports_result_type() {
            return Ok(ResultType::Complete);
        }
        match result.get("resultType") {
            None | Some(Value::Null) => Ok(ResultType::Complete),
            Some(Value::String(value)) if value == "complete" => Ok(ResultType::Complete),
            Some(Value::String(value)) if value == "input_required" => {
                Ok(ResultType::InputRequired)
            }
            Some(Value::String(value)) => Ok(ResultType::Other(value.clone())),
            Some(other) => Err(protocol_error(format!(
                "`resultType` must be a string, got {other}"
            ))),
        }
    }

    /// Whether the result is final.
    pub fn is_complete(&self) -> bool {
        matches!(self, ResultType::Complete)
    }

    /// Whether the server asked for more input.
    pub fn is_input_required(&self) -> bool {
        matches!(self, ResultType::InputRequired)
    }

    /// Wire spelling.
    pub fn as_str(&self) -> &str {
        match self {
            ResultType::Complete => "complete",
            ResultType::InputRequired => "input_required",
            ResultType::Other(value) => value,
        }
    }
}

/// One tool advertised by `tools/list`.
///
/// Unknown tool fields are ignored. Descriptions, titles, and annotations are
/// untrusted server data; they are payload here, never instructions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Tool {
    /// Tool name used in `tools/call`.
    pub name: String,
    /// Optional display title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema 2020-12 input schema.
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    /// Optional JSON Schema 2020-12 output schema.
    #[serde(
        default,
        rename = "outputSchema",
        skip_serializing_if = "Option::is_none"
    )]
    pub output_schema: Option<Value>,
}

impl Tool {
    /// Stable hash of this tool's input and output schemas.
    ///
    /// Descriptions and titles are excluded: only a definition change counts as
    /// a schema change for cache invalidation and, later, schema pinning.
    pub fn schema_hash(&self) -> u64 {
        let mut hash = hash_start();
        hash_bytes(&mut hash, b"input:");
        hash_bytes(&mut hash, &schema_hash(&self.input_schema).to_be_bytes());
        match &self.output_schema {
            Some(output) => {
                hash_bytes(&mut hash, b"output:");
                hash_bytes(&mut hash, &schema_hash(output).to_be_bytes());
            }
            None => hash_bytes(&mut hash, b"no-output"),
        }
        hash
    }

    /// Validate the name and both schemas against the configured bounds.
    pub fn validate(&self, limits: SchemaLimits) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                "MCP tool name must not be empty",
            ));
        }
        crate::schema::validate_schema_with(&self.input_schema, limits)
            .map_err(|error| annotate(error, &self.name, "inputSchema"))?;
        if let Some(output) = &self.output_schema {
            crate::schema::validate_schema_with(output, limits)
                .map_err(|error| annotate(error, &self.name, "outputSchema"))?;
        }
        Ok(())
    }
}

fn annotate(error: ZeroError, tool: &str, field: &str) -> ZeroError {
    ZeroError::new(
        error.code(),
        format!("tool `{tool}` {field}: {}", error.message()),
    )
}

/// A validated `tools/list` catalogue.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCatalog {
    /// Tools in server order.
    pub tools: Vec<Tool>,
    /// Opaque pagination cursor for the next page, when the server paginates.
    pub next_cursor: Option<String>,
    /// Server cache lifetime hint in milliseconds (MCP-04). `None` means no hint.
    pub ttl_ms: Option<u64>,
    /// Server cache scope hint (MCP-04), passed through.
    pub cache_scope: Option<String>,
    /// `resultType` under the negotiated revision (MCP-03).
    pub result_type: ResultType,
}

impl ToolCatalog {
    /// Stable hash of the tool names and their schema hashes.
    ///
    /// The hash covers the whole ordered catalogue, so adding, removing,
    /// renaming, or redefining a tool changes it. It is used to detect a schema
    /// change on refresh, not as a cryptographic signature.
    pub fn schema_hash(&self) -> u64 {
        let mut hash = hash_start();
        hash_bytes(&mut hash, &(self.tools.len() as u64).to_be_bytes());
        for tool in &self.tools {
            hash_bytes(&mut hash, tool.name.as_bytes());
            hash_bytes(&mut hash, &tool.schema_hash().to_be_bytes());
        }
        hash
    }

    /// Find a tool by exact name.
    pub fn tool(&self, name: &str) -> Option<&Tool> {
        self.tools.iter().find(|tool| tool.name == name)
    }
}

/// What a catalogue refresh found.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolsRefresh {
    /// The freshly fetched catalogue.
    pub catalog: ToolCatalog,
    /// Whether a previously cached catalogue had a different schema hash.
    pub schema_changed: bool,
    /// The replaced catalogue's hash, when one was cached.
    pub previous_schema_hash: Option<u64>,
}

/// The parsed `initialize` result.
#[derive(Debug, Clone, PartialEq)]
pub struct InitializeResult {
    /// Revision the server selected; used for all later calls.
    pub protocol_version: McpRevision,
    /// `resultType` under the selected revision.
    pub result_type: ResultType,
    /// Server capabilities, passed through as untrusted data.
    pub capabilities: Value,
    /// Optional server identity.
    pub server_info: Option<ServerInfo>,
    /// Optional instructions; untrusted server data.
    pub instructions: Option<String>,
}

/// Server identity from `initialize`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInfo {
    /// Server name.
    pub name: String,
    /// Server version.
    pub version: String,
    /// Optional display title.
    #[serde(default)]
    pub title: Option<String>,
}

/// The parsed `tools/call` result.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCallResult {
    /// `resultType` under the negotiated revision (MCP-03).
    pub result_type: ResultType,
    /// Content blocks, passed through as untrusted data.
    pub content: Vec<Value>,
    /// Optional structured content, passed through.
    pub structured_content: Option<Value>,
    /// `inputRequests` when the result is `input_required`; MRTR is T-MCP-03.
    pub input_requests: Option<Value>,
    /// Whether the server reported a tool-level error (`isError`).
    pub is_error: bool,
}

/// Cache key for `tools/list`: one server at one negotiated revision.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ToolsCacheKey {
    /// Configured server name.
    pub server: String,
    /// Revision used for the request.
    pub revision: McpRevision,
}

#[derive(Debug, Clone)]
struct CachedCatalog {
    key: ToolsCacheKey,
    schema_hash: u64,
    catalog: ToolCatalog,
    stored_at: Timestamp,
}

/// The tool call kept between an `input_required` result and its one retry.
///
/// No transport stream is kept open: the retry is a fresh JSON-RPC request
/// with the same tool name and arguments, a new id, and `inputResponses`.
#[derive(Debug, Clone)]
struct PendingToolCall {
    name: String,
    arguments: Value,
    requests: Vec<InputRequest>,
    state: Option<Value>,
}

/// A JSON-RPC exchange with a server.
///
/// Implementations take a complete request value and return a complete
/// response value. They must not add headers or sessions on their own; a future
/// transport uses [`Client::request_headers`] for routing metadata. Production
/// transports are later tasks; tests use an in-memory script.
pub trait Transport {
    /// Send one request and return the raw response envelope.
    fn exchange(&self, request: &Value) -> Result<Value>;
}

impl<T: Transport + ?Sized> Transport for &T {
    fn exchange(&self, request: &Value) -> Result<Value> {
        (**self).exchange(request)
    }
}

impl<T: Transport + ?Sized> Transport for Box<T> {
    fn exchange(&self, request: &Value) -> Result<Value> {
        (**self).exchange(request)
    }
}

/// A stateless MCP client for one configured server.
///
/// Request ids are sequential per client. The `tools/list` catalogue is cached
/// under [`ToolsCacheKey`] and reused until it expires, is invalidated, or a
/// refresh observes a different schema hash.
pub struct Client<T: Transport> {
    server_name: String,
    transport: T,
    requested_revision: McpRevision,
    negotiated_revision: Option<McpRevision>,
    headers: Headers,
    next_id: u64,
    cache: Option<CachedCatalog>,
    pending_input: Option<PendingToolCall>,
    clock: Arc<dyn Clock>,
    schema_limits: SchemaLimits,
}

impl<T: Transport> Client<T> {
    /// Create a client for `server_name` requesting the latest revision.
    pub fn new(server_name: impl Into<String>, transport: T) -> Self {
        let requested_revision = McpRevision::LATEST;
        let mut headers = Headers::new();
        headers.insert(HEADER_PROTOCOL_VERSION, requested_revision.as_str());
        Self {
            server_name: server_name.into(),
            transport,
            requested_revision,
            negotiated_revision: None,
            headers,
            next_id: 0,
            cache: None,
            pending_input: None,
            clock: Arc::new(SystemClock),
            schema_limits: SchemaLimits::default(),
        }
    }

    /// Choose the revision sent in `initialize`. Clears negotiation and cache.
    pub fn with_revision(mut self, revision: McpRevision) -> Self {
        self.requested_revision = revision;
        self.negotiated_revision = None;
        self.cache = None;
        self.pending_input = None;
        self.headers
            .insert(HEADER_PROTOCOL_VERSION, revision.as_str());
        self
    }

    /// Use an injected clock for `ttlMs` expiry.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Replace the bounds applied to tool schemas.
    pub fn with_schema_limits(mut self, limits: SchemaLimits) -> Self {
        self.schema_limits = limits;
        self
    }

    /// Configured server name.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// The underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// The revision this client asks for in `initialize`.
    pub fn requested_revision(&self) -> McpRevision {
        self.requested_revision
    }

    /// The revision the server selected, when `initialize` has run.
    pub fn negotiated_revision(&self) -> Option<McpRevision> {
        self.negotiated_revision
    }

    /// The revision used for the next request.
    ///
    /// Before `initialize` this is the requested revision; the stateless core
    /// does not require a handshake, so calls may proceed.
    pub fn current_revision(&self) -> McpRevision {
        self.negotiated_revision.unwrap_or(self.requested_revision)
    }

    /// Headers stored by the client (protocol version, plus caller additions).
    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    /// Mutable access to the stored headers.
    ///
    /// `initialize` overwrites `MCP-Protocol-Version` with the negotiated
    /// revision; other entries are preserved. Authorization is not modelled in
    /// this task.
    pub fn headers_mut(&mut self) -> &mut Headers {
        &mut self.headers
    }

    /// Headers for one request, for a future transport to put on the wire.
    ///
    /// Includes the stored headers, the negotiated protocol version, and the
    /// `Mcp-Method`/`Mcp-Name` routing headers (MCP-02).
    pub fn request_headers(&self, method: &str, name: Option<&str>) -> Headers {
        let mut headers = self.headers.clone();
        headers.insert(HEADER_PROTOCOL_VERSION, self.current_revision().as_str());
        headers.insert(HEADER_METHOD, method);
        if let Some(name) = name {
            headers.insert(HEADER_NAME, name);
        }
        headers
    }

    /// The cache key used for `tools/list`.
    pub fn cache_key(&self) -> ToolsCacheKey {
        ToolsCacheKey {
            server: self.server_name.clone(),
            revision: self.current_revision(),
        }
    }

    /// The cached catalogue, if it is present, current, and unexpired.
    pub fn cached_tools(&self) -> Option<&ToolCatalog> {
        self.cache
            .as_ref()
            .filter(|entry| self.cache_is_fresh(entry))
            .map(|entry| &entry.catalog)
    }

    /// Drop the cached catalogue.
    pub fn invalidate_tools(&mut self) {
        self.cache = None;
    }

    /// Negotiate a revision and keep it for later calls.
    ///
    /// Sends `initialize` with this client's requested revision, then stores the
    /// server-selected revision. An unknown revision is
    /// [`ErrorCode::Unsupported`]; a malformed result is
    /// [`ErrorCode::ProviderProtocol`].
    pub fn initialize(&mut self) -> Result<InitializeResult> {
        let params = json!({
            "protocolVersion": self.requested_revision.as_str(),
            "capabilities": {},
            "clientInfo": {
                "name": CLIENT_NAME,
                "version": env!("CARGO_PKG_VERSION"),
            },
        });
        let result = self.exchange(METHOD_INITIALIZE, Some(params))?;
        let object = expect_object(result, METHOD_INITIALIZE)?;

        let protocol_version = match object.get("protocolVersion") {
            Some(Value::String(value)) => McpRevision::parse(value)?,
            Some(other) => {
                return Err(protocol_error(format!(
                    "`initialize` protocolVersion must be a string, got {other}"
                )))
            }
            None => {
                return Err(protocol_error(
                    "`initialize` result is missing `protocolVersion`",
                ))
            }
        };
        let result_type = ResultType::from_result(protocol_version, &object)?;
        let capabilities = object
            .get("capabilities")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let server_info = match object.get("serverInfo") {
            None | Some(Value::Null) => None,
            Some(value) => Some(serde_json::from_value(value.clone()).map_err(|cause| {
                protocol_error(format!("malformed `initialize` serverInfo: {cause}"))
            })?),
        };
        let instructions = optional_string(&object, "instructions", METHOD_INITIALIZE)?;

        self.negotiated_revision = Some(protocol_version);
        self.pending_input = None;
        self.headers
            .insert(HEADER_PROTOCOL_VERSION, protocol_version.as_str());
        if self
            .cache
            .as_ref()
            .is_some_and(|entry| entry.key.revision != protocol_version)
        {
            self.cache = None;
        }

        Ok(InitializeResult {
            protocol_version,
            result_type,
            capabilities,
            server_info,
            instructions,
        })
    }

    /// List tools, using the cached catalogue when it is fresh.
    ///
    /// The first call exchanges one `tools/list` request; an identical call
    /// before expiry returns the cached catalogue without touching the
    /// transport.
    pub fn tools_list(&mut self) -> Result<ToolCatalog> {
        if let Some(catalog) = self.cached_tools() {
            return Ok(catalog.clone());
        }
        self.fetch_tools()
    }

    /// Fetch tools regardless of cache and report whether the schema changed.
    ///
    /// A changed hash replaces the cached catalogue and sets `schema_changed`,
    /// which is the invalidation signal for callers that pin schemas.
    pub fn refresh_tools(&mut self) -> Result<ToolsRefresh> {
        let key = self.cache_key();
        let previous_schema_hash = self
            .cache
            .as_ref()
            .filter(|entry| entry.key == key)
            .map(|entry| entry.schema_hash);
        let catalog = self.fetch_tools()?;
        let hash = catalog.schema_hash();
        let schema_changed = previous_schema_hash.is_some_and(|previous| previous != hash);
        Ok(ToolsRefresh {
            catalog,
            schema_changed,
            previous_schema_hash,
        })
    }

    /// Call one tool with a JSON `arguments` value.
    ///
    /// A JSON-RPC error becomes a typed error; a tool-level failure is returned
    /// as [`ToolCallResult::is_error`] instead. `input_required` results are
    /// surfaced as [`ResultType::InputRequired`] and are not retried here
    /// (T-MCP-03).
    pub fn tools_call(&mut self, name: &str, arguments: Value) -> Result<ToolCallResult> {
        if name.trim().is_empty() {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                "MCP tool name must not be empty",
            ));
        }
        let params = json!({"name": name, "arguments": arguments});
        let result = self.exchange(METHOD_TOOLS_CALL, Some(params))?;
        let object = expect_object(result, METHOD_TOOLS_CALL)?;
        let result_type = ResultType::from_result(self.current_revision(), &object)?;

        let content = match object.get("content") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => items.clone(),
            Some(other) => {
                return Err(protocol_error(format!(
                    "`tools/call` content must be an array, got {other}"
                )))
            }
        };
        let is_error = match object.get("isError") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(value)) => *value,
            Some(other) => {
                return Err(protocol_error(format!(
                    "`tools/call` isError must be a boolean, got {other}"
                )))
            }
        };

        Ok(ToolCallResult {
            result_type,
            content,
            structured_content: object
                .get("structuredContent")
                .filter(|value| !value.is_null())
                .cloned(),
            input_requests: object
                .get("inputRequests")
                .filter(|value| !value.is_null())
                .cloned(),
            is_error,
        })
    }

    /// Call one tool and classify the result for MRTR (MCP-03, MCP-07, MCP-08).
    ///
    /// A `complete` result is returned as [`ToolCallOutcome::Complete`] with the
    /// raw `content` array. An `input_required` result is validated and parsed
    /// into [`ToolCallOutcome::InputRequired`]; the pending call is kept so
    /// [`Self::retry_with_inputs`] can send exactly one retry. An unknown
    /// `resultType` is passed through as [`ToolCallOutcome::Other`].
    ///
    /// Form-mode requests that ask for a credential field are refused with
    /// `zero.pol.denied` before any pending call is recorded. On `2025-11-25`,
    /// every result is `complete`; an `input_required` payload is never
    /// produced for an older revision.
    pub fn tools_call_outcome(&mut self, name: &str, arguments: Value) -> Result<ToolCallOutcome> {
        if name.trim().is_empty() {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                "MCP tool name must not be empty",
            ));
        }
        if self.pending_input.is_some() {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                "a tool call is already awaiting input; call `retry_with_inputs` first",
            ));
        }
        let params = json!({"name": name, "arguments": arguments.clone()});
        let result = self.exchange(METHOD_TOOLS_CALL, Some(params))?;
        let outcome = self.parse_tool_call_outcome(result)?;
        if let ToolCallOutcome::InputRequired { requests, state } = &outcome {
            self.pending_input = Some(PendingToolCall {
                name: name.to_string(),
                arguments,
                requests: requests.clone(),
                state: state.clone(),
            });
        }
        Ok(outcome)
    }

    /// Retry the pending tool call once with `inputResponses`.
    ///
    /// The retry sends the same tool name and arguments with a new JSON-RPC id,
    /// the `inputResponses` map, and the exact `requestState` the server sent.
    /// It never loops: a second `input_required` is returned to the caller and
    /// no further request is sent. The pending call is consumed even when the
    /// retry fails so a caller cannot accidentally retry more than once.
    ///
    /// Accepting a URL-mode request requires an [`InputResponses`] built with
    /// the [`HostAction`] from the outcome; the client never opens, follows, or
    /// submits a URL on its own.
    pub fn retry_with_inputs(&mut self, responses: InputResponses) -> Result<ToolCallOutcome> {
        let pending = self.pending_input.as_ref().ok_or_else(|| {
            ZeroError::new(
                ErrorCode::InvalidInput,
                "no tool call is awaiting input; call `tools_call_outcome` first",
            )
        })?;
        responses.validate_for(&pending.requests)?;
        let pending = self
            .pending_input
            .take()
            .expect("pending input was checked above");

        let mut params = Map::new();
        params.insert("name".to_string(), Value::String(pending.name));
        params.insert("arguments".to_string(), pending.arguments);
        if !responses.is_empty() {
            params.insert("inputResponses".to_string(), responses.as_value());
        }
        if let Some(state) = pending.state {
            params.insert("requestState".to_string(), state);
        }

        let result = self.exchange(METHOD_TOOLS_CALL, Some(Value::Object(params)))?;
        self.parse_tool_call_outcome(result)
    }

    /// Whether an `input_required` result is waiting for a retry.
    pub fn has_pending_input(&self) -> bool {
        self.pending_input.is_some()
    }

    /// Requests carried by the pending tool call, or an empty slice.
    pub fn pending_input_requests(&self) -> &[InputRequest] {
        self.pending_input
            .as_ref()
            .map_or(&[], |pending| pending.requests.as_slice())
    }

    fn parse_tool_call_outcome(&self, result: Value) -> Result<ToolCallOutcome> {
        let object = expect_object(result, METHOD_TOOLS_CALL)?;
        if !self.current_revision().supports_result_type() {
            return Ok(ToolCallOutcome::Complete {
                content: tool_call_content(&object)?,
                structured: structured_content(&object),
            });
        }

        match ResultType::from_result(self.current_revision(), &object)? {
            ResultType::Complete => {
                if has_non_null(&object, "inputRequests") || has_non_null(&object, "requestState") {
                    return Err(protocol_error(
                        "`tools/call` result mixes `complete` with `inputRequests`/`requestState`",
                    ));
                }
                Ok(ToolCallOutcome::Complete {
                    content: tool_call_content(&object)?,
                    structured: structured_content(&object),
                })
            }
            ResultType::InputRequired => {
                if has_non_null(&object, "content")
                    || has_non_null(&object, "structuredContent")
                    || has_non_null(&object, "isError")
                {
                    return Err(protocol_error(
                        "`tools/call` result mixes `input_required` with complete content",
                    ));
                }
                let requests = match object.get("inputRequests") {
                    None | Some(Value::Null) => Vec::new(),
                    Some(value) => parse_input_requests(value)?,
                };
                let state = match object.get("requestState") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(_)) => object.get("requestState").cloned(),
                    Some(other) => {
                        return Err(protocol_error(format!(
                            "`tools/call` requestState must be a string, got {other}"
                        )))
                    }
                };
                if requests.is_empty() && state.is_none() {
                    return Err(protocol_error(
                        "`tools/call` input_required result carries neither `inputRequests` nor `requestState`",
                    ));
                }
                Ok(ToolCallOutcome::InputRequired { requests, state })
            }
            ResultType::Other(value) => Ok(ToolCallOutcome::Other(value)),
        }
    }

    fn exchange(&mut self, method: &str, params: Option<Value>) -> Result<Value> {
        self.next_id = self.next_id.saturating_add(1);
        let id = RequestId::Number(self.next_id);
        let request = Request::new(id.clone(), method, params);
        let request = serde_json::to_value(&request)?;
        let response = self.transport.exchange(&request)?;
        expect_result(response, &id)
    }

    fn fetch_tools(&mut self) -> Result<ToolCatalog> {
        let result = self.exchange(METHOD_TOOLS_LIST, Some(json!({})))?;
        let object = expect_object(result, METHOD_TOOLS_LIST)?;
        let result_type = ResultType::from_result(self.current_revision(), &object)?;

        let tools_value = object
            .get("tools")
            .ok_or_else(|| protocol_error("`tools/list` result is missing `tools`"))?;
        let tools: Vec<Tool> = serde_json::from_value(tools_value.clone()).map_err(|cause| {
            protocol_error(format!("malformed `tools/list` tools array: {cause}"))
        })?;
        for tool in &tools {
            tool.validate(self.schema_limits)?;
        }

        let catalog = ToolCatalog {
            tools,
            next_cursor: optional_string(&object, "nextCursor", METHOD_TOOLS_LIST)?,
            ttl_ms: optional_u64(&object, "ttlMs", METHOD_TOOLS_LIST)?,
            cache_scope: optional_string(&object, "cacheScope", METHOD_TOOLS_LIST)?,
            result_type,
        };

        self.cache = Some(CachedCatalog {
            key: self.cache_key(),
            schema_hash: catalog.schema_hash(),
            catalog: catalog.clone(),
            stored_at: self.clock.now(),
        });
        Ok(catalog)
    }

    fn cache_is_fresh(&self, entry: &CachedCatalog) -> bool {
        if entry.key != self.cache_key() {
            return false;
        }
        let Some(ttl_ms) = entry.catalog.ttl_ms else {
            return true;
        };
        if ttl_ms == 0 {
            return false;
        }
        let elapsed = self.clock.now().0.saturating_sub(entry.stored_at.0).max(0) as u64;
        elapsed < ttl_ms
    }
}

fn has_non_null(object: &Map<String, Value>, key: &str) -> bool {
    object.get(key).is_some_and(|value| !value.is_null())
}

fn tool_call_content(object: &Map<String, Value>) -> Result<Value> {
    match object.get("content") {
        None | Some(Value::Null) => Ok(json!([])),
        Some(value @ Value::Array(_)) => Ok(value.clone()),
        Some(other) => Err(protocol_error(format!(
            "`tools/call` content must be an array, got {other}"
        ))),
    }
}

fn structured_content(object: &Map<String, Value>) -> Option<Value> {
    object
        .get("structuredContent")
        .filter(|value| !value.is_null())
        .cloned()
}

fn optional_string(object: &Map<String, Value>, key: &str, method: &str) -> Result<Option<String>> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(other) => Err(protocol_error(format!(
            "`{method}` {key} must be a string, got {other}"
        ))),
    }
}

fn optional_u64(object: &Map<String, Value>, key: &str, method: &str) -> Result<Option<u64>> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => number.as_u64().map(Some).ok_or_else(|| {
            protocol_error(format!("`{method}` {key} must be a non-negative integer"))
        }),
        Some(other) => Err(protocol_error(format!(
            "`{method}` {key} must be a number, got {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn older_revisions_treat_every_result_as_complete() {
        let result = object(json!({"resultType": "input_required"}));
        assert_eq!(
            ResultType::from_result(McpRevision::V2025_11_25, &result).unwrap(),
            ResultType::Complete
        );
    }

    #[test]
    fn newer_revisions_classify_known_values_and_pass_unknown_ones_through() {
        let complete = object(json!({"resultType": "complete"}));
        assert_eq!(
            ResultType::from_result(McpRevision::V2026_07_28, &complete).unwrap(),
            ResultType::Complete
        );

        let input = object(json!({"resultType": "input_required"}));
        assert_eq!(
            ResultType::from_result(McpRevision::V2026_07_28, &input).unwrap(),
            ResultType::InputRequired
        );

        let future = object(json!({"resultType": "deferred"}));
        assert_eq!(
            ResultType::from_result(McpRevision::V2026_07_28, &future).unwrap(),
            ResultType::Other("deferred".to_string())
        );

        let missing = object(json!({}));
        assert_eq!(
            ResultType::from_result(McpRevision::V2026_07_28, &missing).unwrap(),
            ResultType::Complete
        );

        let invalid = object(json!({"resultType": 7}));
        assert_eq!(
            ResultType::from_result(McpRevision::V2026_07_28, &invalid)
                .unwrap_err()
                .code(),
            ErrorCode::ProviderProtocol
        );
    }
}
