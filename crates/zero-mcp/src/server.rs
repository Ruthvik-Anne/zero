//! MCP server mode (T-MCP-10, MCP-10 and MCP-15).
//!
//! MCP-15 is a MAY: Zero may expose its tools, sessions, and events over MCP,
//! **disabled by default**. This module implements the protocol-facing half of
//! that optional server: a [`ServerConfig`] gate, two injectable host seams
//! ([`SessionHost`] and [`ToolHost`]), and a [`McpServer`] that turns one
//! JSON-RPC request at a time into one JSON-RPC response envelope.
//!
//! The module is deliberately transport-free. `handle` takes an already-parsed
//! [`serde_json::Value`] and `handle_line` takes one NDJSON line; the stdio and
//! Streamable HTTP wiring that a future task adds is a thin loop around these
//! two methods. Tests drive scripted hosts, so they need no socket, child
//! process, or provider credential. The server never reads provider
//! credentials, model configuration, or the workspace directly: every effect
//! goes through the host traits.
//!
//! Three rules shape the design:
//!
//! - **Off means off.** A default [`ServerConfig`] serves nothing. While
//!   `enabled` is false, `handle` and `handle_line` answer every request with
//!   `zero.fnd.unsupported`; an enabled server with one flag off answers only
//!   that capability's methods with `Unsupported`.
//! - **The wire is bounded.** The request line, argument bytes, argument
//!   nesting, host catalogue sizes, and every returned value have fixed caps.
//!   Oversize live data is rejected, never truncated.
//! - **Errors are envelopes, not panics and not payloads.** Every failure is a
//!   JSON-RPC error object carrying a generic message, the stable Zero code in
//!   `data.zeroCode`, and the code's static remediation line. A host error
//!   message is never copied onto the wire, so a payload or secret inside one
//!   cannot leak to the editor.
//!
//! Only tools, sessions, and events are exposed. `resources/list`,
//! `resources/read`, and `prompts/list` are intentionally omitted because the
//! host seams here do not back them; a later task that adds resource and prompt
//! host methods can advertise them (see `docs/mcp.md`).

use std::io::Write;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::client::{
    Tool, ToolAnnotations, METHOD_INITIALIZE, METHOD_TOOLS_CALL, METHOD_TOOLS_LIST,
};
use crate::events::{EventBatch, EventCursor};
use crate::jsonrpc::JSONRPC_VERSION;
use crate::revision::McpRevision;
use crate::schema::SchemaLimits;

/// `sessions/list` method name and the matching tool name.
pub const METHOD_SESSIONS_LIST: &str = "sessions/list";
/// `sessions/prompt` method name and the matching tool name.
pub const METHOD_SESSIONS_PROMPT: &str = "sessions/prompt";
/// `sessions/events` method name and the matching tool name.
pub const METHOD_SESSIONS_EVENTS: &str = "sessions/events";

/// Largest accepted request (one `handle` value or one NDJSON line), in bytes.
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;
/// Largest accepted `tools/call` arguments value, in compact JSON bytes.
pub const MAX_ARGUMENT_BYTES: usize = 64 * 1024;
/// Largest accepted `tools/call` arguments nesting depth. The root is depth 0.
pub const MAX_ARGUMENT_DEPTH: usize = 32;
/// Largest returned result value, in compact JSON bytes.
pub const MAX_RESULT_BYTES: usize = 1024 * 1024;
/// Largest catalogue returned by `tools/list`, including session tools.
pub const MAX_TOOLS: usize = 512;
/// Largest catalogue returned by `sessions/list`.
pub const MAX_SESSIONS: usize = 1024;
/// Largest batch returned by `sessions/events`.
pub const MAX_EVENTS: usize = 256;

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const INTERNAL_ERROR: i64 = -32603;

// ---------------------------------------------------------------------------
// Configuration and gate
// ---------------------------------------------------------------------------

/// Server-mode configuration. [`ServerConfig::disabled`] is the default.
///
/// `enabled` is the master switch: construction does not touch a host, and
/// while this is false every request is refused with
/// `zero.fnd.unsupported`. The three `expose_*` flags select individual
/// capabilities. `expose_events` only has an effect together with
/// `expose_sessions`, because events are delivered for a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    /// Master switch. `false` refuses every request.
    pub enabled: bool,
    /// Expose the host's tools through `tools/list` and `tools/call`.
    pub expose_tools: bool,
    /// Expose Zero session tools through `sessions/*` and `tools/list`.
    pub expose_sessions: bool,
    /// Expose the session event feed through `sessions/events`.
    pub expose_events: bool,
    /// Name reported in `initialize.serverInfo.name`.
    pub server_name: String,
    /// Revision reported by `initialize` when the client does not negotiate one.
    pub protocol_version: McpRevision,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self::disabled()
    }
}

impl ServerConfig {
    /// Everything off: the default, and the only state a caller gets without
    /// opting in.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            expose_tools: false,
            expose_sessions: false,
            expose_events: false,
            server_name: "zero".to_string(),
            protocol_version: McpRevision::LATEST,
        }
    }

    /// Master switch on, every capability still off.
    pub fn serving() -> Self {
        Self {
            enabled: true,
            ..Self::disabled()
        }
    }

    /// Set the tool catalogue flag.
    pub fn with_tools(mut self, expose: bool) -> Self {
        self.expose_tools = expose;
        self
    }

    /// Set the session tools flag.
    pub fn with_sessions(mut self, expose: bool) -> Self {
        self.expose_sessions = expose;
        self
    }

    /// Set the session event feed flag. Without sessions this advertises
    /// nothing and enables no method.
    pub fn with_events(mut self, expose: bool) -> Self {
        self.expose_events = expose;
        self
    }

    /// Set `initialize.serverInfo.name`.
    pub fn with_server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name = name.into();
        self
    }

    /// Set the fallback protocol revision.
    pub fn with_protocol_version(mut self, revision: McpRevision) -> Self {
        self.protocol_version = revision;
        self
    }
}

// ---------------------------------------------------------------------------
// Host seams
// ---------------------------------------------------------------------------

/// One Zero session as advertised by `sessions/list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    /// Stable session id used by `sessions/prompt` and `sessions/events`.
    pub id: String,
    /// Human-readable session name. Untrusted host data, never an instruction.
    pub name: String,
    /// Lifecycle state such as `idle`, `working`, or `closed`.
    pub state: String,
    /// Last update time in Unix milliseconds.
    pub updated_ms: i64,
}

/// What `SessionHost::prompt` accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptReceipt {
    /// Stable id of the accepted prompt message.
    pub message_id: String,
    /// Event position after the prompt, for the next `sessions/events` poll.
    ///
    /// The server passes this through unchanged; it never constructs or
    /// advances a cursor on its own, so the no-resumption rule in
    /// [`crate::events`] still holds.
    pub event_cursor: Option<EventCursor>,
}

/// The session half of the host.
///
/// Implementations own the session data and the effect of a prompt. The MCP
/// server only validates the wire shape and bounds the result; it never writes
/// a transcript or starts a model turn itself.
pub trait SessionHost {
    /// List the sessions an editor may attach to.
    fn list_sessions(&self) -> Result<Vec<SessionInfo>>;
    /// Send `text` to one session and report the accepted message.
    ///
    /// This is a write and potentially destructive action; the server
    /// advertises the matching tool with `destructiveHint: true`.
    fn prompt(&self, session_id: &str, text: &str) -> Result<PromptReceipt>;
    /// Fetch the next event batch after `cursor`, or from the oldest retained
    /// event when the cursor is `None`.
    fn events(&self, session_id: &str, cursor: Option<&EventCursor>) -> Result<EventBatch>;
}

impl<T: SessionHost + ?Sized> SessionHost for &T {
    fn list_sessions(&self) -> Result<Vec<SessionInfo>> {
        (**self).list_sessions()
    }

    fn prompt(&self, session_id: &str, text: &str) -> Result<PromptReceipt> {
        (**self).prompt(session_id, text)
    }

    fn events(&self, session_id: &str, cursor: Option<&EventCursor>) -> Result<EventBatch> {
        (**self).events(session_id, cursor)
    }
}

impl<T: SessionHost + ?Sized> SessionHost for Box<T> {
    fn list_sessions(&self) -> Result<Vec<SessionInfo>> {
        (**self).list_sessions()
    }

    fn prompt(&self, session_id: &str, text: &str) -> Result<PromptReceipt> {
        (**self).prompt(session_id, text)
    }

    fn events(&self, session_id: &str, cursor: Option<&EventCursor>) -> Result<EventBatch> {
        (**self).events(session_id, cursor)
    }
}

/// The tool half of the host.
///
/// `call_tool` returns the structured result value; the server wraps it in a
/// `tools/call` result whose single text block is its compact JSON and whose
/// `structuredContent` is the value itself. A host error becomes a JSON-RPC
/// error object with a stable code, never a tool-level `isError` payload.
pub trait ToolHost {
    /// List the tools this host wants an editor to see.
    fn list_tools(&self) -> Result<Vec<Tool>>;
    /// Run one tool with already shape-checked JSON arguments.
    fn call_tool(&self, name: &str, arguments: Value) -> Result<Value>;
}

impl<T: ToolHost + ?Sized> ToolHost for &T {
    fn list_tools(&self) -> Result<Vec<Tool>> {
        (**self).list_tools()
    }

    fn call_tool(&self, name: &str, arguments: Value) -> Result<Value> {
        (**self).call_tool(name, arguments)
    }
}

impl<T: ToolHost + ?Sized> ToolHost for Box<T> {
    fn list_tools(&self) -> Result<Vec<Tool>> {
        (**self).list_tools()
    }

    fn call_tool(&self, name: &str, arguments: Value) -> Result<Value> {
        (**self).call_tool(name, arguments)
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// An MCP server-mode endpoint for one host.
///
/// One instance handles one request at a time (`handle`), so no protocol
/// session or request multiplexing is modelled. Construction is infallible and
/// does not call the host; the capability gate is checked per request, which
/// lets a caller build the object from configuration before deciding to serve.
pub struct McpServer<H> {
    config: ServerConfig,
    host: H,
}

impl<H> McpServer<H> {
    /// Build a server for `config` and `host`. Nothing is served until
    /// [`Self::check_enabled`] passes.
    pub fn new(config: ServerConfig, host: H) -> Self {
        Self { config, host }
    }

    /// The configuration in use.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// The injected host.
    pub fn host(&self) -> &H {
        &self.host
    }

    /// Whether the master switch is on.
    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    /// The server gate. A disabled server refuses to serve.
    ///
    /// A future transport calls this before accepting a connection; `handle`
    /// and `handle_line` also call it so an accidental direct call cannot
    /// bypass the switch.
    pub fn check_enabled(&self) -> Result<()> {
        if self.config.enabled {
            Ok(())
        } else {
            Err(ZeroError::new(
                ErrorCode::Unsupported,
                "MCP server mode is disabled",
            ))
        }
    }
}

impl<H: SessionHost + ToolHost> McpServer<H> {
    /// Handle one parsed JSON-RPC request value.
    ///
    /// The returned [`Value`] is a complete response envelope with exactly one
    /// of `result` or `error`. Protocol-shape failures are envelopes too, so
    /// this method does not panic and does not use `Err` for them; `Err` is
    /// reserved for a failure to serialise a response (which a [`Value`] cannot
    /// cause in practice). Notifications are not supported: a request without
    /// an id is an invalid request.
    pub fn handle(&self, request: &Value) -> Result<Value> {
        let id = request.as_object().map_or(Value::Null, request_id);
        if let Err(error) = self.check_enabled() {
            return Ok(zero_error_response(id, &error));
        }
        if json_len(request, MAX_REQUEST_BYTES).is_none() {
            return Ok(error_response(
                Value::Null,
                INVALID_REQUEST,
                ErrorCode::LimitExceeded,
            ));
        }

        let Some(object) = request.as_object() else {
            return Ok(invalid_request(Value::Null));
        };
        if !matches!(object.get("jsonrpc"), Some(Value::String(version)) if version == JSONRPC_VERSION)
        {
            return Ok(invalid_request(id));
        }
        let id = match object.get("id") {
            Some(value @ (Value::Number(_) | Value::String(_))) => value.clone(),
            _ => return Ok(invalid_request(Value::Null)),
        };
        let method = match object.get("method") {
            Some(Value::String(method)) if !method.trim().is_empty() => method.as_str(),
            _ => return Ok(invalid_request(id)),
        };

        let params = object.get("params");
        let result = match method {
            METHOD_INITIALIZE => self.initialize(params),
            METHOD_TOOLS_LIST => self.tools_list(params),
            METHOD_TOOLS_CALL => self.tools_call(params),
            METHOD_SESSIONS_LIST => self.sessions_list(params),
            METHOD_SESSIONS_PROMPT => self.sessions_prompt(params),
            METHOD_SESSIONS_EVENTS => self.sessions_events(params),
            _ => Err(unsupported(format!("unknown MCP server method `{method}`"))),
        };
        Ok(match result {
            Ok(result) => success_response(id, result),
            Err(error) => zero_error_response(id, &error),
        })
    }

    /// Handle one NDJSON line and return one response line.
    ///
    /// Invalid JSON is a `-32700` parse-error envelope. An oversize line is
    /// rejected before parsing so a hostile client cannot force a large
    /// allocation. The returned string contains no newline.
    pub fn handle_line(&self, line: &str) -> Result<String> {
        if line.len() > MAX_REQUEST_BYTES {
            return Ok(serde_json::to_string(&error_response(
                Value::Null,
                INVALID_REQUEST,
                ErrorCode::LimitExceeded,
            ))?);
        }
        let request: Value = match serde_json::from_str(line) {
            Ok(request) => request,
            Err(_) => {
                return Ok(serde_json::to_string(&error_response(
                    Value::Null,
                    PARSE_ERROR,
                    ErrorCode::InvalidInput,
                ))?)
            }
        };
        let response = self.handle(&request)?;
        Ok(serde_json::to_string(&response)?)
    }

    // -- initialize ---------------------------------------------------------

    fn initialize(&self, params: Option<&Value>) -> Result<Value> {
        let object = params_object(params)?;
        let revision = match object.and_then(|object| object.get("protocolVersion")) {
            None | Some(Value::Null) => self.config.protocol_version,
            Some(Value::String(requested)) => {
                McpRevision::parse(requested).unwrap_or(self.config.protocol_version)
            }
            Some(_) => return Err(invalid("`initialize` `protocolVersion` must be a string")),
        };
        let result = json!({
            "protocolVersion": revision.as_str(),
            "serverInfo": {
                "name": self.config.server_name,
                "version": env!("CARGO_PKG_VERSION"),
            },
            "capabilities": self.capabilities(),
        });
        Ok(with_result_type(result, revision))
    }

    /// Capabilities reflect the enabled flags and nothing else.
    fn capabilities(&self) -> Value {
        let mut capabilities = Map::new();
        if self.config.expose_tools {
            capabilities.insert("tools".to_string(), json!({"listChanged": false}));
        }
        let mut experimental = Map::new();
        if self.config.expose_sessions {
            experimental.insert(
                "zero.sessions".to_string(),
                json!({"list": true, "prompt": true, "promptDestructive": true}),
            );
        }
        if self.config.expose_sessions && self.config.expose_events {
            experimental.insert("zero.events".to_string(), json!({"poll": true}));
        }
        if !experimental.is_empty() {
            capabilities.insert("experimental".to_string(), Value::Object(experimental));
        }
        Value::Object(capabilities)
    }

    // -- tools --------------------------------------------------------------

    fn tools_list(&self, params: Option<&Value>) -> Result<Value> {
        params_object(params)?;
        if !self.config.expose_tools && !self.config.expose_sessions {
            return Err(unsupported("MCP tools are not exposed"));
        }

        let mut tools = if self.config.expose_sessions {
            self.session_tools()
        } else {
            Vec::new()
        };
        if self.config.expose_tools {
            for tool in self.host.list_tools()? {
                tool.validate(SchemaLimits::default())
                    .map_err(host_data_error)?;
                // Reserved session tools win so the destructive prompt is
                // always advertised with its annotation.
                if tools.iter().any(|existing| existing.name == tool.name) {
                    continue;
                }
                tools.push(tool);
            }
        }
        if tools.len() > MAX_TOOLS {
            return Err(limit("tool count", tools.len(), MAX_TOOLS));
        }

        let result = with_result_type(json!({"tools": tools}), self.config.protocol_version);
        check_result_len(&result)?;
        Ok(result)
    }

    fn tools_call(&self, params: Option<&Value>) -> Result<Value> {
        let object = require_params(params)?;
        let name = required_string(object, "name")?;
        let arguments = match object.get("arguments") {
            None | Some(Value::Null) => json!({}),
            Some(value @ Value::Object(_)) => value.clone(),
            Some(_) => return Err(invalid("`tools/call` `arguments` must be an object")),
        };
        check_arguments(&arguments)?;

        if self.config.expose_sessions && is_session_tool(&name) {
            let data = self.session_tool_data(&name, &arguments)?;
            return self.tool_result(data);
        }
        if !self.config.expose_tools {
            return Err(unsupported("MCP tools are not exposed"));
        }

        let value = self.host.call_tool(&name, arguments)?;
        self.tool_result(value)
    }

    fn tool_result(&self, value: Value) -> Result<Value> {
        check_result_len(&value)?;
        let text = serde_json::to_string(&value)?;
        let result = json!({
            "content": [{"type": "text", "text": text}],
            "structuredContent": value,
            "isError": false,
        });
        let result = with_result_type(result, self.config.protocol_version);
        check_result_len(&result)?;
        Ok(result)
    }

    fn session_tool_data(&self, name: &str, arguments: &Value) -> Result<Value> {
        let object = require_params(Some(arguments))?;
        match name {
            METHOD_SESSIONS_LIST => self.sessions_data(),
            METHOD_SESSIONS_PROMPT => self.prompt_data(object),
            METHOD_SESSIONS_EVENTS => self.events_data(object),
            _ => Err(unsupported(format!("unknown session tool `{name}`"))),
        }
    }

    /// The zero session tools advertised next to the host's tools.
    ///
    /// `sessions/prompt` is a write and potentially destructive action, so it
    /// carries `destructiveHint: true` and `readOnlyHint: false`. A client
    /// applying [`crate::security::decide`] in the default manual mode then
    /// asks the user before the prompt is sent.
    fn session_tools(&self) -> Vec<Tool> {
        let mut tools = vec![
            Tool {
                name: METHOD_SESSIONS_LIST.to_string(),
                title: Some("List Zero sessions".to_string()),
                description: Some(
                    "Read-only: list the Zero sessions an editor can attach to.".to_string(),
                ),
                input_schema: json!({
                    "type": "object",
                    "properties": {},
                    "additionalProperties": false
                }),
                output_schema: None,
                annotations: Some(ToolAnnotations {
                    read_only_hint: Some(true),
                    destructive_hint: Some(false),
                    idempotent_hint: Some(true),
                    open_world_hint: None,
                }),
            },
            Tool {
                name: METHOD_SESSIONS_PROMPT.to_string(),
                title: Some("Prompt a Zero session".to_string()),
                description: Some(
                    "Write: send a prompt to a Zero session; the session may change the workspace."
                        .to_string(),
                ),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "sessionId": {"type": "string"},
                        "text": {"type": "string"}
                    },
                    "required": ["sessionId", "text"],
                    "additionalProperties": false
                }),
                output_schema: None,
                annotations: Some(ToolAnnotations {
                    read_only_hint: Some(false),
                    destructive_hint: Some(true),
                    idempotent_hint: Some(false),
                    open_world_hint: None,
                }),
            },
        ];
        if self.config.expose_events {
            tools.push(Tool {
                name: METHOD_SESSIONS_EVENTS.to_string(),
                title: Some("Read Zero session events".to_string()),
                description: Some(
                    "Read-only: poll session events after an opaque cursor.".to_string(),
                ),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "sessionId": {"type": "string"},
                        "cursor": {"type": "string"}
                    },
                    "required": ["sessionId"],
                    "additionalProperties": false
                }),
                output_schema: None,
                annotations: Some(ToolAnnotations {
                    read_only_hint: Some(true),
                    destructive_hint: Some(false),
                    idempotent_hint: Some(true),
                    open_world_hint: None,
                }),
            });
        }
        tools
    }

    // -- sessions -----------------------------------------------------------

    fn sessions_list(&self, params: Option<&Value>) -> Result<Value> {
        params_object(params)?;
        self.require_sessions()?;
        let result = with_result_type(self.sessions_data()?, self.config.protocol_version);
        check_result_len(&result)?;
        Ok(result)
    }

    fn sessions_prompt(&self, params: Option<&Value>) -> Result<Value> {
        let object = require_params(params)?;
        let result = with_result_type(self.prompt_data(object)?, self.config.protocol_version);
        check_result_len(&result)?;
        Ok(result)
    }

    fn sessions_events(&self, params: Option<&Value>) -> Result<Value> {
        let object = require_params(params)?;
        let result = with_result_type(self.events_data(object)?, self.config.protocol_version);
        check_result_len(&result)?;
        Ok(result)
    }

    fn require_sessions(&self) -> Result<()> {
        if self.config.expose_sessions {
            Ok(())
        } else {
            Err(unsupported("MCP sessions are not exposed"))
        }
    }

    fn require_events(&self) -> Result<()> {
        if self.config.expose_sessions && self.config.expose_events {
            Ok(())
        } else {
            Err(unsupported("MCP session events are not exposed"))
        }
    }

    fn sessions_data(&self) -> Result<Value> {
        self.require_sessions()?;
        let sessions = self.host.list_sessions()?;
        if sessions.len() > MAX_SESSIONS {
            return Err(limit("session count", sessions.len(), MAX_SESSIONS));
        }
        for session in &sessions {
            if session.id.trim().is_empty() {
                return Err(provider("MCP session id must not be empty"));
            }
        }
        Ok(json!({"sessions": sessions}))
    }

    fn prompt_data(&self, params: &Map<String, Value>) -> Result<Value> {
        self.require_sessions()?;
        let session_id = required_string(params, "sessionId")?;
        let text = required_string(params, "text")?;
        if text.len() > MAX_ARGUMENT_BYTES {
            return Err(invalid(format!(
                "MCP prompt text is {} bytes; limit is {MAX_ARGUMENT_BYTES}",
                text.len()
            )));
        }
        let receipt = self.host.prompt(&session_id, &text)?;
        if receipt.message_id.trim().is_empty() {
            return Err(provider("MCP prompt receipt message id must not be empty"));
        }
        let mut data = json!({"messageId": receipt.message_id});
        if let Some(cursor) = receipt.event_cursor {
            data["eventCursor"] = Value::String(cursor.as_str().to_string());
        }
        Ok(data)
    }

    fn events_data(&self, params: &Map<String, Value>) -> Result<Value> {
        self.require_events()?;
        let session_id = required_string(params, "sessionId")?;
        let cursor = optional_string(params, "cursor")?.map(EventCursor::new);
        let batch = self.host.events(&session_id, cursor.as_ref())?;

        if batch.events.len() > MAX_EVENTS {
            return Err(limit("event count", batch.events.len(), MAX_EVENTS));
        }
        let mut total = 0usize;
        let mut events = Vec::with_capacity(batch.events.len());
        for event in &batch.events {
            event.validate()?;
            let size = json_len(&event.payload, MAX_RESULT_BYTES).ok_or_else(|| {
                limit(
                    "event payload bytes",
                    MAX_RESULT_BYTES + 1,
                    MAX_RESULT_BYTES,
                )
            })?;
            total = total.saturating_add(size);
            if total > MAX_RESULT_BYTES {
                return Err(limit("event payload bytes", total, MAX_RESULT_BYTES));
            }
            events.push(json!({
                "id": event.id,
                "kind": event.kind,
                "payload": event.payload,
                "deliveredMs": event.delivered_at_ms,
            }));
        }

        let mut data = json!({"events": events});
        if let Some(next) = batch.next_cursor {
            data["nextCursor"] = Value::String(next.as_str().to_string());
        }
        if let Some(ttl_ms) = batch.ttl_ms {
            data["ttlMs"] = json!(ttl_ms);
        }
        Ok(data)
    }
}

fn is_session_tool(name: &str) -> bool {
    matches!(
        name,
        METHOD_SESSIONS_LIST | METHOD_SESSIONS_PROMPT | METHOD_SESSIONS_EVENTS
    )
}

// ---------------------------------------------------------------------------
// Envelopes and wire errors
// ---------------------------------------------------------------------------

fn success_response(id: Value, result: Value) -> Value {
    json!({"jsonrpc": JSONRPC_VERSION, "id": id, "result": result})
}

fn invalid_request(id: Value) -> Value {
    error_response(id, INVALID_REQUEST, ErrorCode::InvalidInput)
}

fn zero_error_response(id: Value, error: &ZeroError) -> Value {
    error_response(id, rpc_code(error.code()), error.code())
}

/// Build a JSON-RPC error envelope.
///
/// `message` is one of five fixed strings. The host error's own message is
/// never used, so a payload or credential embedded in it cannot reach the
/// editor; `data.zeroCode` carries the stable Zero taxonomy instead.
fn error_response(id: Value, code: i64, zero_code: ErrorCode) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": id,
        "error": {
            "code": code,
            "message": rpc_message(code),
            "data": {
                "zeroCode": zero_code.as_str(),
                "remediation": zero_code.remediation(),
            }
        }
    })
}

fn rpc_code(code: ErrorCode) -> i64 {
    match code {
        ErrorCode::Unsupported => METHOD_NOT_FOUND,
        ErrorCode::InvalidInput | ErrorCode::NotFound | ErrorCode::SessionNotFound => {
            INVALID_PARAMS
        }
        _ => INTERNAL_ERROR,
    }
}

fn rpc_message(code: i64) -> &'static str {
    match code {
        PARSE_ERROR => "Parse error",
        INVALID_REQUEST => "Invalid Request",
        METHOD_NOT_FOUND => "Method not found",
        INVALID_PARAMS => "Invalid params",
        _ => "Internal error",
    }
}

fn request_id(object: &Map<String, Value>) -> Value {
    match object.get("id") {
        Some(value @ (Value::Number(_) | Value::String(_))) => value.clone(),
        _ => Value::Null,
    }
}

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

/// A writer that refuses to accept more than `limit` bytes.
struct LimitWriter {
    written: usize,
    limit: usize,
}

impl Write for LimitWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let next = self.written.saturating_add(buffer.len());
        if next > self.limit {
            return Err(std::io::Error::other(
                "MCP server value exceeds the configured bound",
            ));
        }
        self.written = next;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Compact-JSON length of `value`, or `None` when it exceeds `limit`.
///
/// Serialisation streams into [`LimitWriter`], so an oversize host value is
/// rejected without first materialising its full JSON text.
fn json_len(value: &Value, limit: usize) -> Option<usize> {
    let mut writer = LimitWriter { written: 0, limit };
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => Some(writer.written),
        Err(_) => None,
    }
}

fn check_result_len(value: &Value) -> Result<()> {
    if json_len(value, MAX_RESULT_BYTES).is_none() {
        return Err(limit(
            "result bytes",
            MAX_RESULT_BYTES + 1,
            MAX_RESULT_BYTES,
        ));
    }
    Ok(())
}

fn check_arguments(arguments: &Value) -> Result<()> {
    if json_len(arguments, MAX_ARGUMENT_BYTES).is_none() {
        return Err(invalid(format!(
            "MCP `arguments` exceeds {MAX_ARGUMENT_BYTES} bytes"
        )));
    }
    if exceeds_depth(arguments, MAX_ARGUMENT_DEPTH) {
        return Err(invalid(format!(
            "MCP `arguments` nests deeper than {MAX_ARGUMENT_DEPTH} levels"
        )));
    }
    Ok(())
}

fn exceeds_depth(value: &Value, limit: usize) -> bool {
    fn walk(value: &Value, depth: usize, limit: usize) -> bool {
        if depth > limit {
            return true;
        }
        match value {
            Value::Array(items) => items.iter().any(|item| walk(item, depth + 1, limit)),
            Value::Object(map) => map.values().any(|item| walk(item, depth + 1, limit)),
            _ => false,
        }
    }
    walk(value, 0, limit)
}

// ---------------------------------------------------------------------------
// Params helpers
// ---------------------------------------------------------------------------

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn unsupported(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Unsupported, message)
}

fn provider(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::ProviderProtocol, message)
}

fn limit(what: &str, value: usize, cap: usize) -> ZeroError {
    ZeroError::new(
        ErrorCode::LimitExceeded,
        format!("MCP server {what} {value} exceeds limit {cap}"),
    )
}

/// Malformed host-owned data is a server fault, not a caller error.
fn host_data_error(error: ZeroError) -> ZeroError {
    ZeroError::new(ErrorCode::ProviderProtocol, error.message().to_string())
}

fn params_object(params: Option<&Value>) -> Result<Option<&Map<String, Value>>> {
    match params {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(object)) => Ok(Some(object)),
        Some(_) => Err(invalid("JSON-RPC `params` must be an object")),
    }
}

fn require_params(params: Option<&Value>) -> Result<&Map<String, Value>> {
    params_object(params)?.ok_or_else(|| invalid("JSON-RPC `params` must be an object"))
}

fn required_string(object: &Map<String, Value>, field: &str) -> Result<String> {
    match object.get(field) {
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(value.clone()),
        Some(Value::String(_)) => Err(invalid(format!("MCP `{field}` must not be empty"))),
        Some(_) => Err(invalid(format!("MCP `{field}` must be a string"))),
        None => Err(invalid(format!("MCP request is missing `{field}`"))),
    }
}

fn optional_string(object: &Map<String, Value>, field: &str) -> Result<Option<String>> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(invalid(format!("MCP `{field}` must be a string"))),
    }
}

fn with_result_type(mut value: Value, revision: McpRevision) -> Value {
    if revision.supports_result_type() {
        if let Some(object) = value.as_object_mut() {
            object.insert(
                "resultType".to_string(),
                Value::String("complete".to_string()),
            );
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use zero_types::error::ErrorCode;

    use super::*;
    use crate::events::Event;
    use crate::security::{decide, PolicyMode, ToolDecision};

    // -- scripted hosts -----------------------------------------------------

    struct ScriptedHost {
        tools: Vec<Tool>,
        sessions: Vec<SessionInfo>,
        events: RefCell<Vec<Event>>,
        prompt_error: Option<ZeroError>,
        call_error: Option<ZeroError>,
        events_error: Option<ZeroError>,
        huge_result: bool,
    }

    impl ScriptedHost {
        fn new() -> Self {
            Self {
                tools: vec![tool("search")],
                sessions: vec![SessionInfo {
                    id: "s1".to_string(),
                    name: "editor session".to_string(),
                    state: "idle".to_string(),
                    updated_ms: 1_700_000_000_000,
                }],
                events: RefCell::new(Vec::new()),
                prompt_error: None,
                call_error: None,
                events_error: None,
                huge_result: false,
            }
        }

        fn with_sessions(sessions: Vec<SessionInfo>) -> Self {
            Self {
                sessions,
                ..Self::new()
            }
        }

        fn with_events(events: Vec<Event>) -> Self {
            Self {
                events: RefCell::new(events),
                ..Self::new()
            }
        }
    }

    impl SessionHost for ScriptedHost {
        fn list_sessions(&self) -> Result<Vec<SessionInfo>> {
            Ok(self.sessions.clone())
        }

        fn prompt(&self, session_id: &str, text: &str) -> Result<PromptReceipt> {
            if let Some(error) = &self.prompt_error {
                return Err(error.clone());
            }
            if !self.sessions.iter().any(|session| session.id == session_id) {
                return Err(ZeroError::new(
                    ErrorCode::SessionNotFound,
                    "no such session",
                ));
            }
            let mut events = self.events.borrow_mut();
            let index = events.len();
            events.push(Event::new(
                format!("evt-{index}"),
                "session_message",
                json!({"sessionId": session_id, "role": "user", "text": text}),
                1_000 + index as i64,
            ));
            Ok(PromptReceipt {
                message_id: format!("msg-{index}"),
                event_cursor: Some(EventCursor::new(format!("cursor-{index}"))),
            })
        }

        fn events(&self, session_id: &str, cursor: Option<&EventCursor>) -> Result<EventBatch> {
            if let Some(error) = &self.events_error {
                return Err(error.clone());
            }
            if !self.sessions.iter().any(|session| session.id == session_id) {
                return Err(ZeroError::new(
                    ErrorCode::SessionNotFound,
                    "no such session",
                ));
            }
            let events = self.events.borrow();
            let len = events.len();
            let start = cursor
                .and_then(|cursor| cursor.as_str().strip_prefix("cursor-"))
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0)
                .min(len);
            Ok(EventBatch::new(
                events[start..].to_vec(),
                Some(EventCursor::new(format!("cursor-{len}"))),
                Some(60_000),
            ))
        }
    }

    impl ToolHost for ScriptedHost {
        fn list_tools(&self) -> Result<Vec<Tool>> {
            Ok(self.tools.clone())
        }

        fn call_tool(&self, name: &str, arguments: Value) -> Result<Value> {
            if let Some(error) = &self.call_error {
                return Err(error.clone());
            }
            if self.huge_result {
                return Ok(json!({"blob": "x".repeat(MAX_RESULT_BYTES + 1)}));
            }
            Ok(json!({"tool": name, "arguments": arguments}))
        }
    }

    fn tool(name: &str) -> Tool {
        Tool {
            name: name.to_string(),
            title: None,
            description: None,
            input_schema: json!({"type": "object", "properties": {}}),
            output_schema: None,
            annotations: None,
        }
    }

    fn call<H: SessionHost + ToolHost>(
        server: &McpServer<H>,
        id: u64,
        method: &str,
        params: Option<Value>,
    ) -> Value {
        let mut request = json!({"jsonrpc": "2.0", "id": id, "method": method});
        if let Some(params) = params {
            request["params"] = params;
        }
        server.handle(&request).unwrap()
    }

    fn initialized<H: SessionHost + ToolHost>(server: &McpServer<H>) -> Value {
        let response = call(server, 1, METHOD_INITIALIZE, None);
        assert_eq!(response["jsonrpc"], json!("2.0"));
        response["result"].clone()
    }

    fn zero_code(response: &Value) -> &str {
        response["error"]["data"]["zeroCode"]
            .as_str()
            .expect("error envelope carries data.zeroCode")
    }

    // -- tests --------------------------------------------------------------

    #[test]
    fn the_default_is_disabled_and_a_disabled_server_refuses_everything() {
        let config = ServerConfig::default();
        assert_eq!(config, ServerConfig::disabled());
        assert!(!config.enabled);
        assert!(!config.expose_tools);
        assert!(!config.expose_sessions);
        assert!(!config.expose_events);

        let server = McpServer::new(config, ScriptedHost::new());
        assert!(!server.enabled());
        assert_eq!(
            server.check_enabled().unwrap_err().code(),
            ErrorCode::Unsupported
        );

        let requests = [
            (METHOD_INITIALIZE, None),
            (METHOD_TOOLS_LIST, None),
            (
                METHOD_TOOLS_CALL,
                Some(json!({"name": "search", "arguments": {}})),
            ),
            (METHOD_SESSIONS_LIST, None),
            (
                METHOD_SESSIONS_PROMPT,
                Some(json!({"sessionId": "s1", "text": "hello"})),
            ),
            (METHOD_SESSIONS_EVENTS, Some(json!({"sessionId": "s1"}))),
        ];
        for (id, (method, params)) in requests.into_iter().enumerate() {
            let response = call(&server, id as u64 + 1, method, params);
            assert_eq!(response["jsonrpc"], json!("2.0"));
            assert_eq!(response["id"], json!(id as u64 + 1));
            assert_eq!(response["error"]["code"], json!(METHOD_NOT_FOUND));
            assert_eq!(zero_code(&response), "zero.fnd.unsupported");
            assert!(response.get("result").is_none());
        }

        // The NDJSON entry point refuses the same way.
        let line = server
            .handle_line(r#"{"jsonrpc":"2.0","id":9,"method":"initialize"}"#)
            .unwrap();
        let line: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(zero_code(&line), "zero.fnd.unsupported");
    }

    #[test]
    fn enabling_only_tools_exposes_exactly_the_host_tools() {
        let server = McpServer::new(
            ServerConfig::serving().with_tools(true),
            ScriptedHost::new(),
        );
        let response = call(&server, 1, METHOD_TOOLS_LIST, None);
        assert_eq!(response["result"]["tools"].as_array().unwrap().len(), 1);
        assert_eq!(response["result"]["tools"][0]["name"], json!("search"));

        let capabilities = initialized(&server)["capabilities"].clone();
        assert!(capabilities.get("tools").is_some());
        assert!(capabilities.get("experimental").is_none());

        for (id, (method, params)) in [
            (METHOD_SESSIONS_LIST, None),
            (
                METHOD_SESSIONS_PROMPT,
                Some(json!({"sessionId": "s1", "text": "hello"})),
            ),
            (METHOD_SESSIONS_EVENTS, Some(json!({"sessionId": "s1"}))),
        ]
        .into_iter()
        .enumerate()
        {
            let response = call(&server, id as u64 + 2, method, params);
            assert_eq!(response["error"]["code"], json!(METHOD_NOT_FOUND));
            assert_eq!(zero_code(&response), "zero.fnd.unsupported");
        }
    }

    #[test]
    fn enabling_sessions_exposes_the_session_tools_with_a_destructive_prompt() {
        let server = McpServer::new(
            ServerConfig::serving().with_sessions(true),
            ScriptedHost::new(),
        );
        let response = call(&server, 1, METHOD_TOOLS_LIST, None);
        let tools = response["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec![METHOD_SESSIONS_LIST, METHOD_SESSIONS_PROMPT]);

        let prompt: Tool =
            serde_json::from_value(tools[1].clone()).expect("session tools use the tool shape");
        let annotations = prompt.annotations.as_ref().unwrap();
        assert_eq!(annotations.destructive_hint, Some(true));
        assert_eq!(annotations.read_only_hint, Some(false));
        assert_eq!(annotations.idempotent_hint, Some(false));
        // The default manual policy asks before this tool runs.
        assert_eq!(decide(&prompt, PolicyMode::Manual), ToolDecision::Ask);

        let list: Tool = serde_json::from_value(tools[0].clone()).unwrap();
        assert_eq!(
            list.annotations.as_ref().unwrap().read_only_hint,
            Some(true)
        );
        assert_eq!(decide(&list, PolicyMode::Manual), ToolDecision::Allow);

        // The event feed is a separate capability.
        let response = call(
            &server,
            2,
            METHOD_SESSIONS_EVENTS,
            Some(json!({"sessionId": "s1"})),
        );
        assert_eq!(response["error"]["code"], json!(METHOD_NOT_FOUND));
        assert_eq!(zero_code(&response), "zero.fnd.unsupported");

        // Calling a session tool through `tools/call` also works.
        let response = call(
            &server,
            3,
            METHOD_TOOLS_CALL,
            Some(json!({"name": METHOD_SESSIONS_LIST, "arguments": {}})),
        );
        assert_eq!(
            response["result"]["structuredContent"]["sessions"][0]["id"],
            json!("s1")
        );

        // Enabling events adds the third tool and the method.
        let server = McpServer::new(
            ServerConfig::serving()
                .with_sessions(true)
                .with_events(true),
            ScriptedHost::new(),
        );
        let response = call(&server, 4, METHOD_TOOLS_LIST, None);
        let tools = response["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 3);
        assert_eq!(tools[2]["name"], json!(METHOD_SESSIONS_EVENTS));

        let response = call(
            &server,
            5,
            METHOD_SESSIONS_EVENTS,
            Some(json!({"sessionId": "s1"})),
        );
        assert!(response["result"]["events"].as_array().unwrap().is_empty());
        assert_eq!(response["result"]["nextCursor"], json!("cursor-0"));
        assert_eq!(response["result"]["ttlMs"], json!(60_000));
    }

    #[test]
    fn an_editor_can_drive_a_session_over_mcp() {
        let server = McpServer::new(
            ServerConfig::serving()
                .with_sessions(true)
                .with_events(true),
            ScriptedHost::new(),
        );

        // The editor's handshake goes through the NDJSON entry point.
        let line = server
            .handle_line(
                r#"{"jsonrpc":"2.0","id":"init-1","method":"initialize","params":{"protocolVersion":"2026-07-28"}}"#,
            )
            .unwrap();
        assert!(!line.contains('\n'));
        let init: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(init["id"], json!("init-1"));
        assert_eq!(init["result"]["protocolVersion"], json!("2026-07-28"));
        assert_eq!(init["result"]["serverInfo"]["name"], json!("zero"));
        assert_eq!(
            init["result"]["capabilities"]["experimental"]["zero.sessions"]["prompt"],
            json!(true)
        );
        assert_eq!(
            init["result"]["capabilities"]["experimental"]["zero.events"]["poll"],
            json!(true)
        );
        // The stateless core assigns no session id.
        assert!(init["result"].get("sessionId").is_none());
        assert!(!line.contains("Mcp-Session-Id"));

        // 1. list sessions
        let listed = call(&server, 2, METHOD_SESSIONS_LIST, None);
        let sessions = listed["result"]["sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0]["id"], json!("s1"));
        assert_eq!(sessions[0]["name"], json!("editor session"));
        assert_eq!(sessions[0]["updatedMs"], json!(1_700_000_000_000_i64));

        // 2. prompt the session
        let prompted = call(
            &server,
            3,
            METHOD_SESSIONS_PROMPT,
            Some(json!({"sessionId": "s1", "text": "run the tests"})),
        );
        assert_eq!(prompted["result"]["messageId"], json!("msg-0"));
        assert_eq!(prompted["result"]["eventCursor"], json!("cursor-0"));

        // 3. the new event is visible from the receipt's cursor
        let polled = call(
            &server,
            4,
            METHOD_SESSIONS_EVENTS,
            Some(json!({"sessionId": "s1", "cursor": "cursor-0"})),
        );
        let events = polled["result"]["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["id"], json!("evt-0"));
        assert_eq!(events[0]["kind"], json!("session_message"));
        assert_eq!(events[0]["payload"]["text"], json!("run the tests"));
        assert_eq!(events[0]["deliveredMs"], json!(1_000));
        assert_eq!(polled["result"]["nextCursor"], json!("cursor-1"));
        assert_eq!(polled["result"]["resultType"], json!("complete"));
    }

    #[test]
    fn unknown_methods_and_malformed_params_produce_jsonrpc_errors() {
        let server = McpServer::new(
            ServerConfig::serving()
                .with_tools(true)
                .with_sessions(true)
                .with_events(true),
            ScriptedHost::new(),
        );

        let unknown = call(&server, 1, "nope/nope", None);
        assert_eq!(unknown["error"]["code"], json!(METHOD_NOT_FOUND));
        assert_eq!(zero_code(&unknown), "zero.fnd.unsupported");

        let cases = [
            (METHOD_TOOLS_CALL, Some(json!({"name": 7, "arguments": {}}))),
            (
                METHOD_TOOLS_CALL,
                Some(json!({"name": "search", "arguments": []})),
            ),
            (METHOD_TOOLS_CALL, None),
            (METHOD_TOOLS_CALL, Some(json!("not an object"))),
            (METHOD_SESSIONS_PROMPT, Some(json!({"sessionId": "s1"}))),
            (
                METHOD_SESSIONS_PROMPT,
                Some(json!({"sessionId": "s1", "text": 7})),
            ),
            (
                METHOD_SESSIONS_EVENTS,
                Some(json!({"sessionId": "s1", "cursor": 7})),
            ),
            (METHOD_SESSIONS_LIST, Some(json!([]))),
            (METHOD_INITIALIZE, Some(json!({"protocolVersion": 7}))),
        ];
        for (id, (method, params)) in cases.into_iter().enumerate() {
            let response = call(&server, id as u64 + 2, method, params);
            assert_eq!(
                response["error"]["code"],
                json!(INVALID_PARAMS),
                "{method} with unexpected params accepted"
            );
            assert_eq!(zero_code(&response), "zero.fnd.invalid_input");
        }

        // Envelope failures.
        for request in [
            json!({"id": 1, "method": METHOD_TOOLS_LIST}),
            json!({"jsonrpc": "1.0", "id": 1, "method": METHOD_TOOLS_LIST}),
            json!({"jsonrpc": "2.0", "id": 1}),
            json!({"jsonrpc": "2.0", "method": METHOD_TOOLS_LIST}),
            json!({"jsonrpc": "2.0", "id": true, "method": METHOD_TOOLS_LIST}),
            json!([1, 2, 3]),
        ] {
            let response = server.handle(&request).unwrap();
            assert_eq!(
                response["error"]["code"],
                json!(INVALID_REQUEST),
                "{request}"
            );
            assert_eq!(response["jsonrpc"], json!("2.0"));
        }

        let parse = server.handle_line("{not json").unwrap();
        let parse: Value = serde_json::from_str(&parse).unwrap();
        assert_eq!(parse["error"]["code"], json!(PARSE_ERROR));
        assert_eq!(zero_code(&parse), "zero.fnd.invalid_input");
        assert_eq!(parse["id"], Value::Null);
    }

    #[test]
    fn host_errors_are_mapped_without_leaking_the_message_payload() {
        const SECRET: &str = "SECRET_PROMPT_PAYLOAD_0123456789";
        let host = ScriptedHost {
            prompt_error: Some(ZeroError::new(
                ErrorCode::Internal,
                format!("provider said {SECRET}"),
            )),
            call_error: Some(ZeroError::new(
                ErrorCode::Internal,
                format!("tool returned {SECRET}"),
            )),
            ..ScriptedHost::new()
        };
        let server = McpServer::new(
            ServerConfig::serving().with_tools(true).with_sessions(true),
            host,
        );

        let prompt = call(
            &server,
            1,
            METHOD_SESSIONS_PROMPT,
            Some(json!({"sessionId": "s1", "text": "hello"})),
        );
        assert_eq!(prompt["error"]["code"], json!(INTERNAL_ERROR));
        assert_eq!(prompt["error"]["message"], json!("Internal error"));
        assert_eq!(zero_code(&prompt), "zero.fnd.internal");
        assert!(!prompt.to_string().contains(SECRET));

        let tool_call = call(
            &server,
            2,
            METHOD_TOOLS_CALL,
            Some(json!({"name": "search", "arguments": {"q": SECRET}})),
        );
        assert_eq!(tool_call["error"]["code"], json!(INTERNAL_ERROR));
        assert_eq!(zero_code(&tool_call), "zero.fnd.internal");
        assert!(!tool_call.to_string().contains(SECRET));

        // A typed host not-found keeps its own stable code and stays opaque.
        let host = ScriptedHost {
            prompt_error: Some(ZeroError::new(
                ErrorCode::SessionNotFound,
                format!("missing {SECRET}"),
            )),
            ..ScriptedHost::new()
        };
        let server = McpServer::new(ServerConfig::serving().with_sessions(true), host);
        let missing = call(
            &server,
            3,
            METHOD_SESSIONS_PROMPT,
            Some(json!({"sessionId": "nope", "text": "hello"})),
        );
        assert_eq!(missing["error"]["code"], json!(INVALID_PARAMS));
        assert_eq!(zero_code(&missing), "zero.ses.not_found");
        assert!(!missing.to_string().contains(SECRET));
    }

    #[test]
    fn oversize_arguments_live_data_and_content_are_rejected() {
        let server = McpServer::new(
            ServerConfig::serving()
                .with_tools(true)
                .with_sessions(true)
                .with_events(true),
            ScriptedHost::new(),
        );

        let oversize = call(
            &server,
            1,
            METHOD_TOOLS_CALL,
            Some(json!({
                "name": "search",
                "arguments": {"blob": "x".repeat(MAX_ARGUMENT_BYTES + 1)},
            })),
        );
        assert_eq!(oversize["error"]["code"], json!(INVALID_PARAMS));
        assert_eq!(zero_code(&oversize), "zero.fnd.invalid_input");

        let mut deep = json!(1);
        for _ in 0..(MAX_ARGUMENT_DEPTH + 2) {
            deep = json!({"n": deep});
        }
        let too_deep = call(
            &server,
            2,
            METHOD_TOOLS_CALL,
            Some(json!({"name": "search", "arguments": deep})),
        );
        assert_eq!(too_deep["error"]["code"], json!(INVALID_PARAMS));
        assert_eq!(zero_code(&too_deep), "zero.fnd.invalid_input");

        // Oversize request line, rejected before parsing.
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/list","pad":"{}"}}"#,
            "x".repeat(MAX_REQUEST_BYTES)
        );
        let response = server.handle_line(&line).unwrap();
        let response: Value = serde_json::from_str(&response).unwrap();
        assert_eq!(response["error"]["code"], json!(INVALID_REQUEST));
        assert_eq!(zero_code(&response), "zero.fnd.limit_exceeded");

        // Oversize live session catalogue.
        let sessions: Vec<SessionInfo> = (0..=MAX_SESSIONS)
            .map(|index| SessionInfo {
                id: format!("s{index}"),
                name: format!("session {index}"),
                state: "idle".to_string(),
                updated_ms: 0,
            })
            .collect();
        let server = McpServer::new(
            ServerConfig::serving().with_sessions(true),
            ScriptedHost::with_sessions(sessions),
        );
        let overflow = call(&server, 3, METHOD_SESSIONS_LIST, None);
        assert_eq!(overflow["error"]["code"], json!(INTERNAL_ERROR));
        assert_eq!(zero_code(&overflow), "zero.fnd.limit_exceeded");

        // Oversize live event batch.
        let events: Vec<Event> = (0..=MAX_EVENTS)
            .map(|index| {
                Event::new(
                    format!("evt-{index}"),
                    "session_message",
                    json!({"text": "hello"}),
                    index as i64,
                )
            })
            .collect();
        let server = McpServer::new(
            ServerConfig::serving()
                .with_sessions(true)
                .with_events(true),
            ScriptedHost::with_events(events),
        );
        let overflow = call(
            &server,
            4,
            METHOD_SESSIONS_EVENTS,
            Some(json!({"sessionId": "s1"})),
        );
        assert_eq!(overflow["error"]["code"], json!(INTERNAL_ERROR));
        assert_eq!(zero_code(&overflow), "zero.fnd.limit_exceeded");

        // Oversize returned tool content.
        let host = ScriptedHost {
            huge_result: true,
            ..ScriptedHost::new()
        };
        let server = McpServer::new(ServerConfig::serving().with_tools(true), host);
        let overflow = call(
            &server,
            5,
            METHOD_TOOLS_CALL,
            Some(json!({"name": "search", "arguments": {}})),
        );
        assert_eq!(overflow["error"]["code"], json!(INTERNAL_ERROR));
        assert_eq!(zero_code(&overflow), "zero.fnd.limit_exceeded");
    }

    #[test]
    fn initialize_capabilities_reflect_the_enabled_flags() {
        let server = McpServer::new(ServerConfig::serving(), ScriptedHost::new());
        let result = initialized(&server);
        assert_eq!(result["capabilities"], json!({}));
        assert_eq!(result["protocolVersion"], json!("2026-07-28"));
        assert_eq!(result["serverInfo"]["name"], json!("zero"));
        assert_eq!(
            result["serverInfo"]["version"],
            json!(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(result["resultType"], json!("complete"));
        assert!(result.get("sessionId").is_none());

        let cases = [
            (
                ServerConfig::serving().with_tools(true),
                vec!["tools"],
                Vec::<&str>::new(),
            ),
            (
                ServerConfig::serving().with_sessions(true),
                Vec::new(),
                vec!["zero.sessions"],
            ),
            (
                ServerConfig::serving()
                    .with_sessions(true)
                    .with_events(true),
                Vec::new(),
                vec!["zero.sessions", "zero.events"],
            ),
            (
                ServerConfig::serving()
                    .with_tools(true)
                    .with_sessions(true)
                    .with_events(true),
                vec!["tools"],
                vec!["zero.sessions", "zero.events"],
            ),
        ];
        for (config, plain, experimental) in cases {
            let server = McpServer::new(config, ScriptedHost::new());
            let capabilities = initialized(&server)["capabilities"].clone();
            for key in plain {
                assert!(capabilities.get(key).is_some(), "{key}");
            }
            if experimental.is_empty() {
                assert!(capabilities.get("experimental").is_none());
            } else {
                for key in experimental {
                    assert!(
                        capabilities["experimental"].get(key).is_some(),
                        "{key} missing from {capabilities}"
                    );
                }
            }
        }

        // Events without sessions are inert: nothing is advertised.
        let server = McpServer::new(
            ServerConfig::serving().with_events(true),
            ScriptedHost::new(),
        );
        assert_eq!(initialized(&server)["capabilities"], json!({}));

        // A configured name and an older revision are honoured, and the older
        // revision omits `resultType`.
        let server = McpServer::new(
            ServerConfig::serving()
                .with_server_name("zero-editor")
                .with_protocol_version(McpRevision::V2025_11_25)
                .with_tools(true),
            ScriptedHost::new(),
        );
        let result = initialized(&server);
        assert_eq!(result["serverInfo"]["name"], json!("zero-editor"));
        assert_eq!(result["protocolVersion"], json!("2025-11-25"));
        assert!(result.get("resultType").is_none());
        let listed = call(&server, 2, METHOD_TOOLS_LIST, None);
        assert!(listed["result"].get("resultType").is_none());
    }
}
