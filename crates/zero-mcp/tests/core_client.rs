//! Core-client fixtures and protocol behaviour (T-MCP-01).
//!
//! Every exchange is scripted in memory; no test opens a socket or a process.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::sync::Arc;

use serde_json::{json, Value};
use zero_mcp::{
    Client, McpRevision, ResultType, Transport, CLIENT_NAME, MAX_SCHEMA_BYTES, METHOD_TOOLS_CALL,
    METHOD_TOOLS_LIST,
};
use zero_types::clock::FakeClock;
use zero_types::error::{ErrorCode, Result};

fn fixture(revision: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/{revision}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("parse {path}: {error}"))
}

/// A fixture-backed transport with optional per-call result overrides.
struct ScriptedTransport {
    fixture: Value,
    queued_results: RefCell<VecDeque<Value>>,
    requests: RefCell<Vec<Value>>,
    exchanges: Cell<usize>,
}

impl ScriptedTransport {
    fn new(fixture: Value) -> Self {
        Self {
            fixture,
            queued_results: RefCell::new(VecDeque::new()),
            requests: RefCell::new(Vec::new()),
            exchanges: Cell::new(0),
        }
    }

    fn queue_result(&self, result: Value) {
        self.queued_results.borrow_mut().push_back(result);
    }

    fn exchange_count(&self) -> usize {
        self.exchanges.get()
    }

    fn request(&self, index: usize) -> Value {
        self.requests.borrow()[index].clone()
    }
}

impl Transport for ScriptedTransport {
    fn exchange(&self, request: &Value) -> Result<Value> {
        self.exchanges.set(self.exchanges.get() + 1);
        self.requests.borrow_mut().push(request.clone());

        let result = match self.queued_results.borrow_mut().pop_front() {
            Some(result) => result,
            None => {
                let method = request["method"].as_str().unwrap_or_default();
                match method {
                    "initialize" => self.fixture["initialize"].clone(),
                    "tools/list" => self.fixture["tools_list"].clone(),
                    "tools/call" => self.fixture["tools_call"].clone(),
                    other => panic!("unexpected method `{other}`"),
                }
            }
        };

        Ok(json!({
            "jsonrpc": "2.0",
            "id": request["id"].clone(),
            "result": result,
        }))
    }
}

/// A transport that returns pre-built envelopes, for malformed-wire tests.
struct FixedTransport {
    responses: RefCell<VecDeque<Value>>,
    requests: RefCell<Vec<Value>>,
}

impl FixedTransport {
    fn one(response: Value) -> Self {
        Self {
            responses: RefCell::new(VecDeque::from([response])),
            requests: RefCell::new(Vec::new()),
        }
    }
}

impl Transport for FixedTransport {
    fn exchange(&self, request: &Value) -> Result<Value> {
        self.requests.borrow_mut().push(request.clone());
        self.responses
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| zero_mcp::protocol_error("test transport ran out of responses"))
    }
}

fn assert_request_ids_and_methods(transport: &ScriptedTransport, methods: &[&str]) {
    assert_eq!(transport.requests.borrow().len(), methods.len());
    for (index, method) in methods.iter().enumerate() {
        let request = transport.request(index);
        assert_eq!(request["jsonrpc"], "2.0");
        assert_eq!(request["method"], *method);
        assert_eq!(request["id"], json!(index as u64 + 1));
    }
}

#[test]
fn fixture_2025_11_25_runs_initialize_list_and_call() {
    let transport = ScriptedTransport::new(fixture("2025-11-25"));
    let mut client =
        Client::new("fixture-2025", &transport).with_revision(McpRevision::V2025_11_25);

    assert_eq!(client.current_revision(), McpRevision::V2025_11_25);

    let initialized = client.initialize().unwrap();
    assert_eq!(initialized.protocol_version, McpRevision::V2025_11_25);
    assert_eq!(initialized.result_type, ResultType::Complete);
    assert_eq!(initialized.server_info.unwrap().name, "fixture-2025");
    assert_eq!(client.negotiated_revision(), Some(McpRevision::V2025_11_25));
    assert_eq!(
        client.headers().get("mcp-protocol-version"),
        Some("2025-11-25")
    );

    let catalog = client.tools_list().unwrap();
    assert_eq!(catalog.tools.len(), 2);
    assert_eq!(catalog.tools[0].name, "echo");
    assert_eq!(catalog.next_cursor, None);
    assert_eq!(catalog.ttl_ms, None);
    assert_eq!(catalog.cache_scope, None);
    assert_eq!(catalog.result_type, ResultType::Complete);

    let called = client.tools_call("echo", json!({"text": "hello"})).unwrap();
    assert_eq!(called.result_type, ResultType::Complete);
    assert!(!called.is_error);
    assert_eq!(called.content.len(), 1);
    assert_eq!(called.content[0]["text"], "hello from 2025-11-25");
    assert_eq!(called.structured_content, None);

    assert_eq!(transport.exchange_count(), 3);
    assert_request_ids_and_methods(
        &transport,
        &["initialize", METHOD_TOOLS_LIST, METHOD_TOOLS_CALL],
    );
    assert_eq!(
        transport.request(0)["params"]["protocolVersion"],
        "2025-11-25"
    );
    assert_eq!(
        transport.request(0)["params"]["clientInfo"]["name"],
        CLIENT_NAME
    );
    assert_eq!(transport.request(1)["params"], json!({}));
    assert_eq!(transport.request(2)["params"]["name"], "echo");
    assert_eq!(
        transport.request(2)["params"]["arguments"],
        json!({"text": "hello"})
    );
}

#[test]
fn fixture_2026_07_28_runs_initialize_list_and_call() {
    let transport = ScriptedTransport::new(fixture("2026-07-28"));
    let mut client =
        Client::new("fixture-2026", &transport).with_revision(McpRevision::V2026_07_28);

    let initialized = client.initialize().unwrap();
    assert_eq!(initialized.protocol_version, McpRevision::V2026_07_28);
    assert_eq!(initialized.result_type, ResultType::Complete);
    assert_eq!(
        initialized.instructions.as_deref(),
        Some("Fixture server for the stateless core.")
    );
    let server_info = initialized.server_info.unwrap();
    assert_eq!(server_info.name, "fixture-2026");
    assert_eq!(server_info.title.as_deref(), Some("Fixture 2026"));

    let catalog = client.tools_list().unwrap();
    assert_eq!(catalog.tools.len(), 1);
    assert_eq!(catalog.ttl_ms, Some(60_000));
    assert_eq!(catalog.cache_scope.as_deref(), Some("session"));
    assert_eq!(catalog.result_type, ResultType::Complete);
    assert!(catalog.tools[0].output_schema.is_some());

    let called = client.tools_call("echo", json!({"text": "hello"})).unwrap();
    assert_eq!(called.result_type, ResultType::Complete);
    assert_eq!(
        called.structured_content,
        Some(json!({"text": "hello from 2026-07-28"}))
    );

    assert_eq!(transport.exchange_count(), 3);
    assert_request_ids_and_methods(
        &transport,
        &["initialize", METHOD_TOOLS_LIST, METHOD_TOOLS_CALL],
    );
    assert_eq!(
        transport.request(0)["params"]["protocolVersion"],
        "2026-07-28"
    );
}

#[test]
fn stateless_calls_need_no_handshake() {
    let transport = ScriptedTransport::new(fixture("2026-07-28"));
    let mut client = Client::new("fixture-2026", &transport);
    assert_eq!(client.negotiated_revision(), None);
    assert_eq!(client.current_revision(), McpRevision::V2026_07_28);

    let catalog = client.tools_list().unwrap();
    assert_eq!(catalog.result_type, ResultType::Complete);
    assert_eq!(transport.exchange_count(), 1);
    assert_request_ids_and_methods(&transport, &[METHOD_TOOLS_LIST]);
}

#[test]
fn an_older_negotiated_revision_is_used_for_later_calls() {
    let transport = ScriptedTransport::new(fixture("2025-11-25"));
    let mut client =
        Client::new("fixture-2025", &transport).with_revision(McpRevision::V2026_07_28);

    let initialized = client.initialize().unwrap();
    assert_eq!(initialized.protocol_version, McpRevision::V2025_11_25);
    assert_eq!(client.current_revision(), McpRevision::V2025_11_25);
    assert_eq!(
        client.headers().get("mcp-protocol-version"),
        Some("2025-11-25")
    );
    assert_eq!(client.cache_key().revision, McpRevision::V2025_11_25);

    // Even if an old server emits a newer field, older revisions are complete.
    transport.queue_result(json!({
        "tools": [],
        "resultType": "input_required",
    }));
    let catalog = client.tools_list().unwrap();
    assert_eq!(catalog.result_type, ResultType::Complete);
}

#[test]
fn tools_list_is_cached_until_invalidated() {
    let transport = ScriptedTransport::new(fixture("2026-07-28"));
    let mut client = Client::new("fixture-2026", &transport);
    client.initialize().unwrap();

    assert!(client.cached_tools().is_none());
    let first = client.tools_list().unwrap();
    assert_eq!(transport.exchange_count(), 2);
    assert!(client.cached_tools().is_some());

    let second = client.tools_list().unwrap();
    assert_eq!(second, first);
    assert_eq!(
        transport.exchange_count(),
        2,
        "a cached list must not exchange again"
    );

    client.invalidate_tools();
    assert!(client.cached_tools().is_none());
    client.tools_list().unwrap();
    assert_eq!(transport.exchange_count(), 3);
}

#[test]
fn ttl_ms_expires_the_cache() {
    let clock = Arc::new(FakeClock::at(0));
    let transport = ScriptedTransport::new(fixture("2026-07-28"));
    let mut client = Client::new("fixture-2026", &transport).with_clock(clock.clone());
    client.initialize().unwrap();

    client.tools_list().unwrap();
    client.tools_list().unwrap();
    assert_eq!(transport.exchange_count(), 2);

    clock.advance(60_001);
    client.tools_list().unwrap();
    assert_eq!(
        transport.exchange_count(),
        3,
        "an expired catalogue must be refetched"
    );
}

#[test]
fn refresh_reports_a_changed_schema_hash() {
    let transport = ScriptedTransport::new(fixture("2026-07-28"));
    let mut client = Client::new("fixture-2026", &transport);
    client.initialize().unwrap();

    let initial = client.tools_list().unwrap();
    let initial_hash = initial.schema_hash();

    let changed_catalog = json!({
        "resultType": "complete",
        "ttlMs": 60000,
        "tools": [{
            "name": "echo",
            "inputSchema": {
                "type": "object",
                "properties": {"text": {"type": "integer"}},
                "required": ["text"]
            }
        }]
    });
    transport.queue_result(changed_catalog.clone());
    transport.queue_result(changed_catalog);
    let refresh = client.refresh_tools().unwrap();
    assert_eq!(refresh.previous_schema_hash, Some(initial_hash));
    assert!(refresh.schema_changed);
    assert_ne!(refresh.catalog.schema_hash(), initial_hash);
    assert_eq!(
        client.cached_tools().map(|catalog| catalog.schema_hash()),
        Some(refresh.catalog.schema_hash())
    );

    let unchanged = client.refresh_tools().unwrap();
    assert!(!unchanged.schema_changed);
    assert_eq!(
        unchanged.previous_schema_hash,
        Some(refresh.catalog.schema_hash())
    );
}

#[test]
fn input_required_is_surfaced_but_not_retried() {
    let transport = ScriptedTransport::new(fixture("2026-07-28"));
    let mut client = Client::new("fixture-2026", &transport);
    client.initialize().unwrap();
    client.tools_list().unwrap();

    transport.queue_result(json!({
        "resultType": "input_required",
        "inputRequests": [{"kind": "elicitation", "message": "Which project?"}]
    }));
    let called = client.tools_call("echo", json!({})).unwrap();
    assert_eq!(called.result_type, ResultType::InputRequired);
    assert!(called.input_requests.is_some());
    assert_eq!(
        transport.exchange_count(),
        3,
        "MRTR is a later task; the client must not retry on its own"
    );
}

#[test]
fn unknown_result_type_is_passed_through() {
    let transport = ScriptedTransport::new(fixture("2026-07-28"));
    let mut client = Client::new("fixture-2026", &transport);
    client.initialize().unwrap();
    client.tools_list().unwrap();

    transport.queue_result(json!({
        "resultType": "deferred",
        "content": []
    }));
    let called = client.tools_call("echo", json!({})).unwrap();
    assert_eq!(
        called.result_type,
        ResultType::Other("deferred".to_string())
    );
    assert_eq!(
        called.result_type.as_str(),
        "deferred",
        "unknown result types pass through unchanged"
    );
}

#[test]
fn malformed_envelopes_are_provider_protocol_errors() {
    let responses = [
        json!({"jsonrpc": "1.0", "id": 1, "result": {"tools": []}}),
        json!({"jsonrpc": "2.0", "id": 1}),
        json!({"jsonrpc": "2.0", "id": 2, "result": {"tools": []}}),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": []},
            "error": {"code": -32603, "message": "both"}
        }),
    ];
    for response in responses {
        let mut client = Client::new("bad", FixedTransport::one(response.clone()));
        let error = client.tools_list().unwrap_err();
        assert_eq!(
            error.code(),
            ErrorCode::ProviderProtocol,
            "unexpected code for {response}"
        );
    }
}

#[test]
fn json_rpc_errors_become_typed_errors_with_code_and_message() {
    let not_found = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32601, "message": "Method not found"}
    });
    let mut client = Client::new("bad", FixedTransport::one(not_found));
    let error = client.tools_list().unwrap_err();
    assert_eq!(error.code(), ErrorCode::Unsupported);
    assert!(error.message().contains("-32601"));
    assert!(error.message().contains("Method not found"));

    let invalid_params = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32602, "message": "Invalid params"}
    });
    let mut client = Client::new("bad", FixedTransport::one(invalid_params));
    let error = client.tools_call("echo", json!({})).unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidInput);
    assert!(error.message().contains("Invalid params"));
}

#[test]
fn schema_bounds_reject_bad_tool_schemas() {
    let mut deep = json!({"type": "object"});
    for _ in 0..40 {
        deep = json!({"type": "object", "properties": {"next": deep}});
    }
    let deep_result = json!({
        "resultType": "complete",
        "tools": [{"name": "deep", "inputSchema": deep}]
    });
    let mut client = Client::new(
        "bad",
        FixedTransport::one(json!({
            "jsonrpc": "2.0", "id": 1, "result": deep_result
        })),
    );
    let error = client.tools_list().unwrap_err();
    assert_eq!(error.code(), ErrorCode::LimitExceeded);
    assert!(error.message().contains("deep"));
    assert!(error.message().contains("depth"));

    let large_result = json!({
        "resultType": "complete",
        "tools": [{
            "name": "large",
            "inputSchema": {
                "type": "object",
                "description": "x".repeat(MAX_SCHEMA_BYTES + 1)
            }
        }]
    });
    let mut client = Client::new(
        "bad",
        FixedTransport::one(json!({
            "jsonrpc": "2.0", "id": 1, "result": large_result
        })),
    );
    let error = client.tools_list().unwrap_err();
    assert_eq!(error.code(), ErrorCode::LimitExceeded);
    assert!(error.message().contains("large"));
    assert!(error.message().contains("size"));
}

#[test]
fn routing_headers_are_case_insensitive_and_include_the_revision() {
    let transport = ScriptedTransport::new(fixture("2026-07-28"));
    let mut client = Client::new("fixture-2026", &transport);
    client.headers_mut().insert("X-Custom", "one");

    let headers = client.request_headers(METHOD_TOOLS_CALL, Some("echo"));
    assert_eq!(headers.get("mcp-method"), Some("tools/call"));
    assert_eq!(headers.get("MCP-NAME"), Some("echo"));
    assert_eq!(headers.get("mcp-protocol-version"), Some("2026-07-28"));
    assert_eq!(headers.get("x-custom"), Some("one"));

    let list_headers = client.request_headers(METHOD_TOOLS_LIST, None);
    assert_eq!(list_headers.get("mcp-method"), Some("tools/list"));
    assert_eq!(list_headers.get("mcp-name"), None);
}

#[test]
fn initialize_rejects_an_unsupported_revision() {
    let response = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "serverInfo": {"name": "old", "version": "0.1.0"}
        }
    });
    let mut client = Client::new("old", FixedTransport::one(response));
    let error = client.initialize().unwrap_err();
    assert_eq!(error.code(), ErrorCode::Unsupported);
    assert!(error.message().contains("2024-11-05"));
}
