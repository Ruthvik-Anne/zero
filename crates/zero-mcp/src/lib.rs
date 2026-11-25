//! `zero-mcp` — see `architecture.md` section 5 for the module contract.
//!
//! Implements the stateless MCP core client (T-MCP-01, MCP-01..MCP-05), the
//! stdio and Streamable HTTP transports (T-MCP-02, MCP-06/MCP-17), MRTR
//! with elicitation (T-MCP-03, MCP-07/MCP-08), the tasks extension
//! (T-MCP-04, MCP-09), and the event seam (T-MCP-05, MCP-10): JSON-RPC 2.0
//! envelopes, revision negotiation for `2025-11-25` and `2026-07-28`,
//! `resultType` classification, routing headers, a cached `tools/list`,
//! bounded tool schemas, a scrubbed stdio child, a POST/SSE HTTP transport, an
//! `input_required` outcome parser, one-shot `inputResponses` retries,
//! form-mode credential refusal, URL-mode host approval, end-to-end task
//! handles (`ToolCallOutcome::Task`), redacted `tasks/get`, `tasks/update`, and
//! `tasks/cancel` clients with TTL-aware polling, cursors with mandatory
//! resync, subscription TTLs, and HMAC-SHA256 webhook verification with a
//! replay window and bounded dedupe. The apps extension (T-MCP-06, MCP-11)
//! and extension negotiation (MCP-12) add `ui://` validation, a sandboxed
//! iframe document with a strict CSP, a host-side navigation gate, and
//! unknown-extension tolerance. OAuth 2.1 authorization (T-MCP-07, MCP-07 and
//! MCP-13) adds authorization server discovery with strict issuer checks,
//! PKCE S256, RFC 8707 resource indicators, public-client code exchange and
//! refresh, access-token binding validation, and Client ID Metadata Document
//! validation. Security controls (T-MCP-08, MCP-08 and MCP-14) add schema
//! pinning with host approval, the destructive-tool risk matrix, result size
//! caps, timeout budgets, a resource-URL SSRF policy, and a bounded replay
//! guard. The resources and prompts seam (T-MCP-09, MCP-16) adds validated
//! resource and prompt catalogues, `@` references with restart-safe
//! persistence, slash commands, and bounded local completions. Server mode
//! (T-MCP-10, MCP-10 and MCP-15) adds a default-off JSON-RPC endpoint that
//! exposes tools, sessions, and events through injectable host seams, with a
//! capability gate, bounded requests and results, and envelope-only error
//! mapping. Code mode (T-MCP-12, MCP-20) adds typed TypeScript and Python stub
//! generation, single-tool and search/execute server shapes, and a bridged
//! executor with per-call policy, approval, replay, and size caps. The
//! conformance suite (T-MCP-11, MCP-19) replays declarative fixtures for
//! `2025-11-25` and `2026-07-28` through the real client types. The release
//! gate (T-TST-08, TST-10) requires every MCP fixture to pass, both revisions
//! to be covered, and every protocol golden fixture to decode and project
//! stably.

pub mod apps;
pub mod auth;
pub mod client;
pub mod code_mode;
pub mod conformance;
pub mod conformance_gate;
pub mod events;
pub mod headers;
pub mod jsonrpc;
pub mod mrtr;
pub mod resources;
pub mod revision;
pub mod schema;
pub mod security;
pub mod server;
pub mod tasks;
pub mod transport;

pub use apps::{
    authorize, authorize_message, escape_html, negotiate, negotiate_values, AppFrame,
    ExtensionOffer, NavigationDisposition, NavigationIntent, NavigationPolicy, Negotiation,
    UiResource, APP_CSP, APP_SANDBOX, MAX_EXTENSION_ID_BYTES, MAX_UI_URI_BYTES, MESSAGE_NAVIGATE,
    MESSAGE_OPEN_WINDOW, TASKS_EXTENSION_ID, UI_EXTENSION, UI_SCHEME,
};
pub use auth::{
    canonical_resource, fetch_client_metadata, validate_client_id_url, validate_client_metadata,
    validate_issuer_url, validate_mcp_server_url, validate_redirect_uri, validate_token,
    AccessToken, AuthHttpResponse, AuthorizationServer, ClientMetadata, MetadataFetcher, Pkce,
    ReqwestMetadataFetcher, ReqwestTokenTransport, TokenBinding, TokenGrant, TokenTransport,
    DEFAULT_AUTH_TIMEOUT, MAX_CLIENT_METADATA_BYTES, MAX_REDIRECT_URIS, MAX_STATE_BYTES,
    MAX_TOKEN_RESPONSE_BYTES, PKCE_METHOD_S256, WELL_KNOWN_AUTHORIZATION_SERVER,
    WELL_KNOWN_OPENID_CONFIGURATION,
};
pub use client::{
    Client, InitializeResult, ResultType, ServerInfo, Tool, ToolAnnotations, ToolCallResult,
    ToolCatalog, ToolsCacheKey, ToolsRefresh, Transport, CLIENT_NAME, METHOD_INITIALIZE,
    METHOD_TOOLS_CALL, METHOD_TOOLS_LIST,
};
pub use code_mode::{
    code_tool, execute, generate_api, search_execute_tools, ApprovalOracle, CallRecord, CodeApi,
    CodeExecutor, CodeLanguage, CodeModeBridge, CodeModeConfig, CodeModeHost, CodeModeLimits,
    CodeModePattern, DenyAllApproval, GeneratedTool, SearchHit, CODE_TOOL_NAME,
    DEFAULT_MAX_API_BYTES, DEFAULT_MAX_ARGUMENT_BYTES, DEFAULT_MAX_ARGUMENT_DEPTH,
    DEFAULT_MAX_CALLS, DEFAULT_MAX_DESCRIPTION_BYTES, DEFAULT_MAX_RESULT_BYTES,
    DEFAULT_MAX_SEARCH_HITS, DEFAULT_MAX_SOURCE_BYTES, DEFAULT_SEARCH_EXECUTE_THRESHOLD,
    EXECUTE_TOOL_NAME, MAX_EXAMPLE_BYTES, MAX_SEARCH_DESCRIPTION_BYTES, MAX_TYPE_DEPTH,
    MIN_MAX_API_BYTES, SEARCH_TOOL_NAME,
};
pub use events::{
    resync_required, verify_webhook, Event, EventBatch, EventCursor, EventPollOutcome,
    EventPollSummary, EventPoller, EventSource, HmacSha256Verifier, ResyncRequired,
    SignatureVerifier, WebhookOutcome, WebhookReceiver, DEFAULT_WEBHOOK_TOLERANCE_MS,
    HEADER_EVENT_KEY_ID, HEADER_EVENT_SIGNATURE, HEADER_EVENT_TIMESTAMP, MAX_SEEN_EVENT_IDS,
    RESYNC_REQUIRED_MARKER,
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
pub use resources::{
    complete, parse_reference, parse_slash, request_completion, CompletionArgument, CompletionKind,
    CompletionRequest, CompletionResponse, CompletionSource, CompletionTarget, CompletionTransport,
    LookupFailure, Prompt, PromptArgument, PromptCatalog, Resource, ResourceCatalog, ResourceRef,
    ResourceStore, ResourceTemplate, Resolved, SlashCommand, MAX_COMPLETIONS,
    METHOD_COMPLETION_COMPLETE, METHOD_PROMPTS_GET, METHOD_PROMPTS_LIST, METHOD_RESOURCES_LIST,
    METHOD_RESOURCES_READ, METHOD_RESOURCES_TEMPLATES_LIST, RESOURCE_STORE_SCHEMA_VERSION,
};
pub use schema::{
    schema_hash, validate_schema, validate_schema_with, SchemaLimits, MAX_SCHEMA_BYTES,
    MAX_SCHEMA_DEPTH, MAX_SCHEMA_NODES,
};
pub use security::{
    check_resource_url, classify, decide, ChangedTool, PinOutcome, PolicyMode, ReplayGuard,
    ReplayOutcome, ResponseLimits, SchemaApproval, SchemaPinStore, TimeoutPolicy, ToolDecision,
    ToolRisk, DEFAULT_MAX_CONTENT_BYTES, DEFAULT_MAX_ITEMS, DEFAULT_MAX_STRUCTURED_BYTES,
    DEFAULT_REPLAY_CAPACITY, DEFAULT_REPLAY_TTL_MS, DEFAULT_REQUEST_TIMEOUT_MS,
    DEFAULT_TOTAL_TIMEOUT_MS, MAX_REQUEST_TIMEOUT_MS, MAX_TOTAL_TIMEOUT_MS,
};
pub use server::{
    McpServer, PromptReceipt, ServerConfig, SessionHost, SessionInfo, ToolHost, MAX_ARGUMENT_BYTES,
    MAX_ARGUMENT_DEPTH, MAX_EVENTS, MAX_REQUEST_BYTES, MAX_RESULT_BYTES, MAX_SESSIONS, MAX_TOOLS,
    METHOD_SESSIONS_EVENTS, METHOD_SESSIONS_LIST, METHOD_SESSIONS_PROMPT,
};
pub use tasks::{
    NoopSleeper, PollDeadline, Sleeper, SystemSleeper, Task, TaskId, TaskState,
    METHOD_TASKS_CANCEL, METHOD_TASKS_GET, METHOD_TASKS_UPDATE, TASKS_EXTENSION,
};
pub use transport::{
    connect, is_secret_variable, scrubbed_env, HttpConfig, HttpTransport, StdioConfig,
    StdioTransport, TransportConfig, TransportMode,
};
