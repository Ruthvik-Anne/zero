//! `zero-mcp` — see `architecture.md` section 5 for the module contract.
//!
//! Implements the stateless MCP core client (T-MCP-01, MCP-01..MCP-05):
//! JSON-RPC 2.0 envelopes, revision negotiation for `2025-11-25` and
//! `2026-07-28`, `resultType` classification, routing headers, a cached
//! `tools/list`, and bounded tool schemas. Transports, MRTR and elicitation,
//! tasks, events, apps, auth, security caps, resources, server mode, and the
//! conformance suite are later tasks; no production transport is implemented
//! here.

pub mod client;
pub mod headers;
pub mod jsonrpc;
pub mod revision;
pub mod schema;

pub use client::{
    Client, InitializeResult, ResultType, ServerInfo, Tool, ToolCallResult, ToolCatalog,
    ToolsCacheKey, ToolsRefresh, Transport, CLIENT_NAME, METHOD_INITIALIZE, METHOD_TOOLS_CALL,
    METHOD_TOOLS_LIST,
};
pub use headers::{Headers, HEADER_METHOD, HEADER_NAME, HEADER_PROTOCOL_VERSION};
pub use jsonrpc::{expect_object, expect_result, protocol_error, Request, RequestId, RpcError};
pub use revision::{McpRevision, DEFAULT_REVISION};
pub use schema::{
    schema_hash, validate_schema, validate_schema_with, SchemaLimits, MAX_SCHEMA_BYTES,
    MAX_SCHEMA_DEPTH, MAX_SCHEMA_NODES,
};
