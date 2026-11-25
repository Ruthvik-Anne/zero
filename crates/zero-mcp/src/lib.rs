//! `zero-mcp` — see `architecture.md` section 5 for the module contract.
//!
//! Implements the stateless MCP core client (T-MCP-01, MCP-01..MCP-05), the
//! stdio and Streamable HTTP transports (T-MCP-02, MCP-06/MCP-17), and MRTR
//! with elicitation (T-MCP-03, MCP-07/MCP-08): JSON-RPC 2.0 envelopes,
//! revision negotiation for `2025-11-25` and `2026-07-28`, `resultType`
//! classification, routing headers, a cached `tools/list`, bounded tool
//! schemas, a scrubbed stdio child, a POST/SSE HTTP transport, an
//! `input_required` outcome parser, one-shot `inputResponses` retries,
//! form-mode credential refusal, and URL-mode host approval. The legacy
//! HTTP+SSE shim is off by default. Tasks, events, apps, auth, security caps,
//! resources, server mode, and the conformance suite are later tasks.

pub mod client;
pub mod headers;
pub mod jsonrpc;
pub mod mrtr;
pub mod revision;
pub mod schema;
pub mod transport;

pub use client::{
    Client, InitializeResult, ResultType, ServerInfo, Tool, ToolCallResult, ToolCatalog,
    ToolsCacheKey, ToolsRefresh, Transport, CLIENT_NAME, METHOD_INITIALIZE, METHOD_TOOLS_CALL,
    METHOD_TOOLS_LIST,
};
pub use headers::{
    Headers, HEADER_METHOD, HEADER_NAME, HEADER_PROTOCOL_VERSION, HEADER_SESSION_ID,
};
pub use jsonrpc::{expect_object, expect_result, protocol_error, Request, RequestId, RpcError};
pub use mrtr::{
    ElicitationAction, ElicitationResult, HostAction, InputMode, InputRequest, InputResponses,
    InputSensitivity, ToolCallOutcome, METHOD_ELICITATION_CREATE,
};
pub use revision::{McpRevision, DEFAULT_REVISION};
pub use schema::{
    schema_hash, validate_schema, validate_schema_with, SchemaLimits, MAX_SCHEMA_BYTES,
    MAX_SCHEMA_DEPTH, MAX_SCHEMA_NODES,
};
pub use transport::{
    connect, is_secret_variable, scrubbed_env, HttpConfig, HttpTransport, StdioConfig,
    StdioTransport, TransportConfig, TransportMode,
};
