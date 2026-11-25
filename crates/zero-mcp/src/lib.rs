//! `zero-mcp` — see `architecture.md` section 5 for the module contract.
//!
//! Implements the stateless MCP core client (T-MCP-01, MCP-01..MCP-05) and the
//! stdio and Streamable HTTP transports (T-MCP-02, MCP-06/MCP-17): JSON-RPC 2.0
//! envelopes, revision negotiation for `2025-11-25` and `2026-07-28`,
//! `resultType` classification, routing headers, a cached `tools/list`, bounded
//! tool schemas, a scrubbed stdio child, and a POST/SSE HTTP transport. The
//! legacy HTTP+SSE shim is off by default. MRTR and elicitation, tasks, events,
//! apps, auth, security caps, resources, server mode, and the conformance suite
//! are later tasks.

pub mod client;
pub mod headers;
pub mod jsonrpc;
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
pub use revision::{McpRevision, DEFAULT_REVISION};
pub use schema::{
    schema_hash, validate_schema, validate_schema_with, SchemaLimits, MAX_SCHEMA_BYTES,
    MAX_SCHEMA_DEPTH, MAX_SCHEMA_NODES,
};
pub use transport::{
    connect, is_secret_variable, scrubbed_env, HttpConfig, HttpTransport, StdioConfig,
    StdioTransport, TransportConfig, TransportMode,
};
