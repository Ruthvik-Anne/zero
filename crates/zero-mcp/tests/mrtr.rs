//! MRTR and elicitation fixtures (T-MCP-03, MCP-03, MCP-07, MCP-08).
//!
//! Every exchange is scripted in memory; no test opens a socket or a process.

use std::cell::RefCell;
use std::collections::VecDeque;

use serde_json::{json, Map, Value};
use zero_mcp::{
    Client, InputMode, InputResponses, InputSensitivity, McpRevision, ToolCallOutcome, Transport,
};
use zero_types::error::{ErrorCode, Result};

/// A transport that returns one queued result per exchange and records every
/// request so a test can inspect the exact wire payload.
struct ScriptedTransport {
    queued: RefCell<VecDeque<Value>>,
    requests: RefCell<Vec<Value>>,
}

impl ScriptedTransport {
    fn new(results: Vec<Value>) -> Self {
        Self {
            queued: RefCell::new(VecDeque::from(results)),
            requests: RefCell::new(Vec::new()),
        }
    }

    fn exchanges(&self) -> usize {
        self.requests.borrow().len()
    }

    fn request(&self, index: usize) -> Value {
        self.requests.borrow()[index].clone()
    }
}

impl Transport for ScriptedTransport {
    fn exchange(&self, request: &Value) -> Result<Value> {
        self.requests.borrow_mut().push(request.clone());
        let result = self
            .queued
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| zero_mcp::protocol_error("scripted transport ran out of results"))?;
        Ok(json!({
            "jsonrpc": "2.0",
            "id": request["id"].clone(),
            "result": result,
        }))
    }
}

fn client(results: Vec<Value>) -> Client<ScriptedTransport> {
    Client::new("mrtr-fixture", ScriptedTransport::new(results))
        .with_revision(McpRevision::V2026_07_28)
}

fn complete(text: &str) -> Value {
    json!({
        "resultType": "complete",
        "content": [{"type": "text", "text": text}],
        "structuredContent": {"text": text}
    })
}

fn input_required(input_requests: Value, state: Option<Value>) -> Value {
    let mut result = json!({
        "resultType": "input_required",
        "inputRequests": input_requests
    });
    if let Some(state) = state {
        result["requestState"] = state;
    }
    result
}

fn city_request() -> Value {
    json!({
        "city": {
            "method": "elicitation/create",
            "params": {
                "mode": "form",
                "message": "Which city?",
                "requestedSchema": {
                    "type": "object",
                    "properties": {"city": {"type": "string"}},
                    "required": ["city"]
                }
            }
        }
    })
}

#[test]
fn input_required_then_complete_retries_once_with_input_responses() {
    let mut client = client(vec![
        input_required(city_request(), Some(json!("sealed-state"))),
        complete("sunny in Paris"),
    ]);

    let outcome = client
        .tools_call_outcome("weather", json!({"units": "metric"}))
        .unwrap();
    match &outcome {
        ToolCallOutcome::InputRequired { requests, state } => {
            assert_eq!(requests.len(), 1);
            let request = &requests[0];
            assert_eq!(request.id, "city");
            assert_eq!(request.mode, InputMode::Form);
            assert_eq!(request.message, "Which city?");
            assert_eq!(request.fields, vec!["city".to_string()]);
            assert_eq!(request.sensitivity, InputSensitivity::NonSensitive);
            assert!(request.requested_schema.is_some());
            assert_eq!(request.url, None);
            assert_eq!(state, &Some(json!("sealed-state")));
        }
        other => panic!("expected input_required, got {other:?}"),
    }
    assert!(client.has_pending_input());
    assert_eq!(client.pending_input_requests().len(), 1);
    assert_eq!(client.transport().exchanges(), 1);
    let initial = client.transport().request(0);
    assert_eq!(initial["id"], json!(1));
    assert_eq!(initial["params"]["name"], "weather");
    assert_eq!(initial["params"]["arguments"], json!({"units": "metric"}));
    assert!(
        initial["params"].get("inputResponses").is_none(),
        "the initial call must not carry inputResponses"
    );

    let mut responses = InputResponses::new();
    responses.accept_form("city", json!({"city": "Paris"}));
    let outcome = client.retry_with_inputs(responses).unwrap();
    match outcome {
        ToolCallOutcome::Complete {
            content,
            structured,
        } => {
            assert_eq!(content, json!([{"type": "text", "text": "sunny in Paris"}]));
            assert_eq!(structured, Some(json!({"text": "sunny in Paris"})));
        }
        other => panic!("expected complete, got {other:?}"),
    }
    assert!(!client.has_pending_input());
    assert_eq!(
        client.transport().exchanges(),
        2,
        "MRTR is exactly one additional request"
    );
    let retry = client.transport().request(1);
    assert_ne!(retry["id"], initial["id"], "the retry has its own id");
    assert_eq!(retry["method"], "tools/call");
    assert_eq!(retry["params"]["name"], "weather");
    assert_eq!(retry["params"]["arguments"], json!({"units": "metric"}));
    assert_eq!(
        retry["params"]["inputResponses"],
        json!({"city": {"action": "accept", "content": {"city": "Paris"}}})
    );
    assert_eq!(retry["params"]["requestState"], json!("sealed-state"));
}

#[test]
fn a_second_input_required_is_returned_and_not_looped() {
    let mut client = client(vec![
        input_required(city_request(), None),
        input_required(city_request(), None),
        complete("never reached by a loop"),
    ]);

    assert!(client
        .tools_call_outcome("weather", json!({}))
        .unwrap()
        .is_input_required());
    let mut responses = InputResponses::new();
    responses.accept_form("city", json!({"city": "Paris"}));
    let second = client.retry_with_inputs(responses).unwrap();
    assert!(second.is_input_required());
    assert_eq!(
        client.transport().exchanges(),
        2,
        "a second input_required must stop instead of looping"
    );
    assert!(!client.has_pending_input());

    let error = client.retry_with_inputs(InputResponses::new()).unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidInput);
    assert_eq!(client.transport().exchanges(), 2);

    // A fresh call is allowed; it consumes the next scripted result, proving
    // the client is not holding a stream or an open retry.
    assert!(client
        .tools_call_outcome("weather", json!({}))
        .unwrap()
        .is_complete());
    assert_eq!(client.transport().exchanges(), 3);
}

#[test]
fn state_only_input_required_retries_without_input_responses() {
    let mut client = client(vec![
        json!({"resultType": "input_required", "requestState": "opaque"}),
        complete("done"),
    ]);

    let outcome = client
        .tools_call_outcome("long_task", json!({"step": 1}))
        .unwrap();
    match outcome {
        ToolCallOutcome::InputRequired { requests, state } => {
            assert!(requests.is_empty());
            assert_eq!(state, Some(json!("opaque")));
        }
        other => panic!("expected input_required, got {other:?}"),
    }

    assert!(client
        .retry_with_inputs(InputResponses::new())
        .unwrap()
        .is_complete());
    let retry = client.transport().request(1);
    assert_eq!(retry["params"]["requestState"], json!("opaque"));
    assert!(
        retry["params"].get("inputResponses").is_none(),
        "no responses means no inputResponses field"
    );
}

#[test]
fn a_form_request_may_omit_mode_and_is_non_sensitive() {
    let mut client = client(vec![
        input_required(
            json!({
                "name": {
                    "method": "elicitation/create",
                    "params": {
                        "message": "What is your name?",
                        "requestedSchema": {
                            "type": "object",
                            "properties": {"name": {"type": "string"}}
                        }
                    }
                }
            }),
            None,
        ),
        complete("hello"),
    ]);

    let outcome = client.tools_call_outcome("greet", json!({})).unwrap();
    let request = &outcome.requests()[0];
    assert_eq!(request.mode, InputMode::Form);
    assert_eq!(request.sensitivity, InputSensitivity::NonSensitive);
    assert_eq!(request.fields, vec!["name".to_string()]);

    let mut responses = InputResponses::new();
    responses.accept_form("name", json!({"name": "Ada"}));
    assert!(client.retry_with_inputs(responses).unwrap().is_complete());
}

#[test]
fn form_mode_credential_fields_are_refused_without_a_retry() {
    let cases = [
        ("password", json!({"type": "string"})),
        ("passphrase", json!({"type": "string"})),
        ("api_key", json!({"type": "string"})),
        ("accessToken", json!({"type": "string"})),
        ("private_key", json!({"type": "string"})),
        ("session_id", json!({"type": "string"})),
        (
            "value",
            json!({"type": "string", "description": "Your API token"}),
        ),
        ("value", json!({"type": "string", "format": "password"})),
        ("value", json!({"type": "string", "writeOnly": true})),
    ];

    for (field, schema) in cases {
        let mut properties = Map::new();
        properties.insert(field.to_string(), schema);
        let result = input_required(
            json!({
                "sensitive": {
                    "method": "elicitation/create",
                    "params": {
                        "mode": "form",
                        "message": "Sign in",
                        "requestedSchema": {"type": "object", "properties": properties}
                    }
                }
            }),
            None,
        );
        let mut client = client(vec![result]);

        let error = client.tools_call_outcome("sign_in", json!({})).unwrap_err();
        assert_eq!(
            error.code(),
            ErrorCode::PolicyDenied,
            "field `{field}` must be refused"
        );
        assert!(
            error.message().contains(field),
            "the refusal names the field: {}",
            error.message()
        );
        assert_eq!(
            client.transport().exchanges(),
            1,
            "a refused form must not trigger a wire retry"
        );
        assert!(!client.has_pending_input());
    }
}

#[test]
fn url_mode_is_returned_for_host_approval_and_never_auto_submitted() {
    let url = "https://mcp.example.com/ui/set_api_key";
    let mut client = client(vec![
        input_required(
            json!({
                "login": {
                    "method": "elicitation/create",
                    "params": {
                        "mode": "url",
                        "url": url,
                        "message": "Provide an API key to continue."
                    }
                }
            }),
            Some(json!("url-state")),
        ),
        complete("connected"),
    ]);

    let outcome = client.tools_call_outcome("connect", json!({})).unwrap();
    let request = &outcome.requests()[0];
    assert_eq!(request.mode, InputMode::Url);
    assert_eq!(request.url.as_deref(), Some(url));
    assert_eq!(request.sensitivity, InputSensitivity::Sensitive);
    assert!(request.requires_host_approval());

    let actions = outcome.host_actions();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].request_id(), "login");
    assert_eq!(actions[0].url(), url);
    assert_eq!(actions[0].message(), "Provide an API key to continue.");
    assert_eq!(
        client.transport().exchanges(),
        1,
        "the client must not open, follow, or submit the URL"
    );

    // A missing response is not silently accepted.
    let error = client.retry_with_inputs(InputResponses::new()).unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidInput);
    assert_eq!(client.transport().exchanges(), 1);
    assert!(client.has_pending_input());

    // Nor is an unapproved accept for a URL request.
    let mut unapproved = InputResponses::new();
    unapproved.accept_form("login", json!({}));
    let error = client.retry_with_inputs(unapproved).unwrap_err();
    assert_eq!(error.code(), ErrorCode::PolicyDenied);
    assert_eq!(client.transport().exchanges(), 1);
    assert!(client.has_pending_input());

    // Only the host action can produce the URL-mode accept response.
    let mut approved = InputResponses::new();
    approved.approve_url(&actions[0]);
    assert!(client.retry_with_inputs(approved).unwrap().is_complete());
    assert_eq!(client.transport().exchanges(), 2);
    let retry = client.transport().request(1);
    assert_eq!(
        retry["params"]["inputResponses"]["login"],
        json!({"action": "accept"})
    );
    assert_eq!(retry["params"]["requestState"], json!("url-state"));
}

#[test]
fn malformed_input_requests_are_provider_protocol_errors() {
    let valid_request = || {
        json!({
            "method": "elicitation/create",
            "params": {
                "mode": "form",
                "message": "Value?",
                "requestedSchema": {
                    "type": "object",
                    "properties": {"value": {"type": "string"}}
                }
            }
        })
    };

    let cases = vec![
        json!({"resultType": "input_required", "inputRequests": [], "requestState": "s"}),
        json!({"resultType": "input_required", "inputRequests": {"x": "not an object"}}),
        json!({"resultType": "input_required", "inputRequests": {"x": {"method": "elicitation/create"}}}),
        json!({"resultType": "input_required", "inputRequests": {"x": {"method": "elicitation/create", "params": {"requestedSchema": {"type": "object", "properties": {}}}}}}),
        json!({"resultType": "input_required", "inputRequests": {"x": {"method": "elicitation/create", "params": {"mode": "telepathy", "message": "Value?"}}}}),
        json!({"resultType": "input_required", "inputRequests": {"x": {"method": "elicitation/create", "params": {"mode": "form", "message": "Value?"}}}}),
        json!({"resultType": "input_required", "inputRequests": {"x": {"method": "elicitation/create", "params": {"mode": "form", "message": "Value?", "requestedSchema": {"type": "array", "properties": {}}}}}}),
        json!({"resultType": "input_required", "inputRequests": {"x": {"method": "elicitation/create", "params": {"mode": "url", "message": "Open this"}}}}),
        json!({"resultType": "input_required", "inputRequests": {"x": {"method": "elicitation/create", "params": {"mode": "url", "message": "Open this", "url": "javascript:alert(1)"}}}}),
        json!({"resultType": "input_required", "inputRequests": {"x": {"method": "sampling/createMessage", "params": {}}}}),
        json!({"resultType": "input_required", "requestState": 7}),
        json!({"resultType": "input_required"}),
        json!({"resultType": "complete", "content": [], "inputRequests": {"x": valid_request()}}),
        json!({"resultType": "input_required", "content": [], "inputRequests": {"x": valid_request()}}),
    ];

    for result in cases {
        let mut client = client(vec![result.clone()]);
        let error = client.tools_call_outcome("tool", json!({})).unwrap_err();
        assert_eq!(
            error.code(),
            ErrorCode::ProviderProtocol,
            "unexpected code for {result}"
        );
        assert_eq!(client.transport().exchanges(), 1);
        assert!(!client.has_pending_input(), "no pending call for {result}");
    }
}

#[test]
fn an_older_revision_never_yields_input_required() {
    let mut client = Client::new(
        "old",
        ScriptedTransport::new(vec![json!({
            "resultType": "input_required",
            "inputRequests": city_request(),
            "requestState": "ignored"
        })]),
    )
    .with_revision(McpRevision::V2025_11_25);

    let outcome = client.tools_call_outcome("weather", json!({})).unwrap();
    match outcome {
        ToolCallOutcome::Complete {
            content,
            structured,
        } => {
            assert_eq!(content, json!([]));
            assert_eq!(structured, None);
        }
        other => panic!("older revisions must be complete, got {other:?}"),
    }
    assert!(!client.has_pending_input());
    assert_eq!(client.transport().exchanges(), 1);
}
