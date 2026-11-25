//! MCP tasks fixtures (T-MCP-04, MCP-04, MCP-09).
//!
//! Every exchange is scripted in memory; no test opens a socket or a process,
//! and no test sleeps for real.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::Arc;

use serde_json::{json, Value};
use zero_mcp::{
    Client, InputResponses, McpRevision, PollDeadline, Task, TaskId, TaskState, ToolCallOutcome,
    Transport, METHOD_TASKS_CANCEL, METHOD_TASKS_GET, METHOD_TASKS_UPDATE,
};
use zero_types::clock::FakeClock;
use zero_types::error::{ErrorCode, Result};

const SECRET: &str = "task_9f8e7d6c5b4a39281706f5e4d3c2b1a0";
const OTHER: &str = "task_00000000000000000000000000000000";

/// One scripted reply. Errors are envelopes so tests can exercise the
/// JSON-RPC error path and id scrubbing.
enum Reply {
    Ok(Value),
    Err { code: i64, message: String },
}

impl Reply {
    fn ok(result: Value) -> Self {
        Reply::Ok(result)
    }

    fn err(code: i64, message: impl Into<String>) -> Self {
        Reply::Err {
            code,
            message: message.into(),
        }
    }
}

struct ScriptedTransport {
    queued: RefCell<VecDeque<Reply>>,
    requests: RefCell<Vec<Value>>,
}

impl ScriptedTransport {
    fn new(replies: Vec<Reply>) -> Self {
        Self {
            queued: RefCell::new(VecDeque::from(replies)),
            requests: RefCell::new(Vec::new()),
        }
    }

    fn requests(&self) -> Vec<Value> {
        self.requests.borrow().clone()
    }

    fn request(&self, index: usize) -> Value {
        self.requests.borrow()[index].clone()
    }
}

impl Transport for ScriptedTransport {
    fn exchange(&self, request: &Value) -> Result<Value> {
        self.requests.borrow_mut().push(request.clone());
        let reply = self
            .queued
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| zero_mcp::protocol_error("scripted transport ran out of replies"))?;
        Ok(match reply {
            Reply::Ok(result) => json!({
                "jsonrpc": "2.0",
                "id": request["id"].clone(),
                "result": result,
            }),
            Reply::Err { code, message } => json!({
                "jsonrpc": "2.0",
                "id": request["id"].clone(),
                "error": {"code": code, "message": message},
            }),
        })
    }
}

fn task_client(transport: &ScriptedTransport) -> Client<&ScriptedTransport> {
    Client::new("tasks-fixture", transport).with_revision(McpRevision::V2026_07_28)
}

fn working(ttl_ms: u64, poll_interval_ms: u64) -> Value {
    json!({
        "resultType": "complete",
        "taskId": SECRET,
        "status": "working",
        "createdAt": "2025-11-25T10:30:00Z",
        "lastUpdatedAt": "2025-11-25T10:40:00Z",
        "ttlMs": ttl_ms,
        "pollIntervalMs": poll_interval_ms,
    })
}

fn working_without_interval() -> Value {
    let mut value = working(60_000, 1_000);
    value.as_object_mut().unwrap().remove("pollIntervalMs");
    value
}

fn input_required() -> Value {
    json!({
        "resultType": "complete",
        "taskId": SECRET,
        "status": "input_required",
        "createdAt": "2025-11-25T10:30:00Z",
        "lastUpdatedAt": "2025-11-25T10:40:00Z",
        "ttlMs": 60_000,
        "pollIntervalMs": 1_000,
        "inputRequests": {
            "approval": {
                "method": "elicitation/create",
                "params": {
                    "mode": "form",
                    "message": "Approve deployment to production?",
                    "requestedSchema": {
                        "type": "object",
                        "properties": {"approved": {"type": "boolean"}},
                        "required": ["approved"]
                    }
                }
            }
        }
    })
}

fn completed() -> Value {
    json!({
        "resultType": "complete",
        "taskId": SECRET,
        "status": "completed",
        "createdAt": "2025-11-25T10:30:00Z",
        "lastUpdatedAt": "2025-11-25T10:50:00Z",
        "ttlMs": 60_000,
        "pollIntervalMs": 1_000,
        "result": {
            "content": [{"type": "text", "text": "deployed"}],
            "isError": false
        }
    })
}

fn url_input_required() -> Value {
    json!({
        "resultType": "complete",
        "taskId": SECRET,
        "status": "input_required",
        "createdAt": "2025-11-25T10:30:00Z",
        "lastUpdatedAt": "2025-11-25T10:40:00Z",
        "ttlMs": 60_000,
        "pollIntervalMs": 1_000,
        "inputRequests": {
            "login": {
                "method": "elicitation/create",
                "params": {
                    "mode": "url",
                    "url": "https://mcp.example.com/ui/set_api_key",
                    "message": "Provide an API key to continue."
                }
            }
        }
    })
}

fn failed() -> Value {
    json!({
        "resultType": "complete",
        "taskId": SECRET,
        "status": "failed",
        "createdAt": "2025-11-25T10:30:00Z",
        "lastUpdatedAt": "2025-11-25T10:40:00Z",
        "ttlMs": 60_000,
        "pollIntervalMs": 1_000,
        "statusMessage": "Tool execution failed: API rate limit exceeded",
        "error": {"code": -32603, "message": "API rate limit exceeded"}
    })
}

fn create_result() -> Value {
    json!({
        "resultType": "task",
        "taskId": SECRET,
        "status": "working",
        "statusMessage": "The operation is now in progress.",
        "createdAt": "2025-11-25T10:30:00Z",
        "lastUpdatedAt": "2025-11-25T10:40:00Z",
        "ttlMs": 60_000,
        "pollIntervalMs": 5_000
    })
}

fn without(mut value: Value, key: &str) -> Value {
    value.as_object_mut().unwrap().remove(key);
    value
}

fn set(mut value: Value, key: &str, replacement: Value) -> Value {
    value[key] = replacement;
    value
}

fn assert_no_secret(text: &str) {
    assert!(!text.contains(SECRET), "raw task id leaked: {text}");
    assert!(!text.contains(OTHER), "other raw task id leaked: {text}");
}

#[test]
fn full_lifecycle_working_input_required_update_completed() {
    let transport = ScriptedTransport::new(vec![
        Reply::ok(working(60_000, 1_000)),
        Reply::ok(input_required()),
        Reply::ok(json!({"resultType": "complete"})),
        Reply::ok(working(60_000, 1_000)),
        Reply::ok(completed()),
    ]);
    let mut client = task_client(&transport);

    let created = Task::from_create_result(create_result()).unwrap();
    assert_eq!(created.state, TaskState::Working);
    assert!(!created.is_terminal());
    assert_eq!(created.id.secret(), SECRET);
    assert_eq!(
        created.status_message.as_deref(),
        Some("The operation is now in progress.")
    );

    let task = client.tasks_get(&created.id).unwrap();
    assert_eq!(task.state, TaskState::Working);

    let task = client.tasks_get(&created.id).unwrap();
    assert_eq!(task.state, TaskState::InputRequired);
    assert!(task.requires_input());
    assert_eq!(task.input_requests.len(), 1);
    assert_eq!(task.input_requests[0].id, "approval");

    let mut responses = InputResponses::new();
    responses.accept_form("approval", json!({"approved": true}));
    client.tasks_update_for(&task, &responses).unwrap();

    let sleeps = RefCell::new(Vec::new());
    let task = client
        .poll_until_done(
            &created.id,
            &|millis: u64| sleeps.borrow_mut().push(millis),
            PollDeadline::new(5),
        )
        .unwrap();
    assert_eq!(task.state, TaskState::Completed);
    assert!(task.is_terminal());
    assert_eq!(task.result.as_ref().unwrap()["isError"], json!(false));
    assert_eq!(*sleeps.borrow(), vec![1_000]);

    let requests = transport.requests();
    assert_eq!(requests.len(), 5);
    assert_eq!(requests[0]["method"], METHOD_TASKS_GET);
    assert_eq!(requests[0]["params"], json!({"taskId": SECRET}));
    assert_eq!(requests[1]["method"], METHOD_TASKS_GET);
    assert_eq!(requests[2]["method"], METHOD_TASKS_UPDATE);
    assert_eq!(
        requests[2]["params"],
        json!({
            "taskId": SECRET,
            "inputResponses": {
                "approval": {"action": "accept", "content": {"approved": true}}
            }
        })
    );
    assert_eq!(requests[3]["method"], METHOD_TASKS_GET);
    assert_eq!(requests[4]["method"], METHOD_TASKS_GET);
    for (index, request) in requests.iter().enumerate() {
        assert_eq!(request["jsonrpc"], "2.0");
        assert_eq!(request["id"], json!(index as u64 + 1));
    }

    assert_no_secret(&format!("{task:?}"));
    assert_eq!(format!("{}", task.id), "[redacted]");
    assert_eq!(format!("{:?}", task.id), "[redacted]");
}

#[test]
fn tools_call_task_result_is_polled_to_completion() {
    let transport = ScriptedTransport::new(vec![
        Reply::ok(create_result()),
        Reply::ok(working(60_000, 1_000)),
        Reply::ok(completed()),
    ]);
    let mut client = task_client(&transport);

    let outcome = client
        .tools_call_outcome("deploy", json!({"environment": "production"}))
        .unwrap();
    let task = match outcome {
        ToolCallOutcome::Task(task) => task,
        other => panic!("expected a task outcome, got {other:?}"),
    };
    assert_eq!(task.state, TaskState::Working);
    assert_eq!(task.id.secret(), SECRET);
    assert_no_secret(&format!("{task:?}"));

    let sleeps = RefCell::new(Vec::new());
    let task = client
        .poll_until_done(
            &task.id,
            &|millis: u64| sleeps.borrow_mut().push(millis),
            PollDeadline::new(3),
        )
        .unwrap();
    assert_eq!(task.state, TaskState::Completed);
    assert_eq!(
        task.result.as_ref().unwrap()["content"][0]["text"],
        json!("deployed")
    );
    assert_eq!(*sleeps.borrow(), vec![1_000]);

    let requests = transport.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0]["method"], "tools/call");
    assert_eq!(requests[0]["params"]["name"], "deploy");
    assert_eq!(requests[1]["method"], METHOD_TASKS_GET);
    assert_eq!(requests[1]["params"], json!({"taskId": SECRET}));
    assert_eq!(requests[2]["method"], METHOD_TASKS_GET);
}

#[test]
fn older_revision_never_yields_a_task_outcome() {
    let transport = ScriptedTransport::new(vec![Reply::ok(create_result())]);
    let mut client =
        Client::new("tasks-fixture", &transport).with_revision(McpRevision::V2025_11_25);

    let outcome = client.tools_call_outcome("deploy", json!({})).unwrap();
    match outcome {
        ToolCallOutcome::Complete {
            content,
            structured,
        } => {
            assert_eq!(content, json!([]));
            assert_eq!(structured, None);
        }
        other => panic!("2025-11-25 must not yield a task, got {other:?}"),
    }
    assert_eq!(transport.requests().len(), 1);
}

#[test]
fn task_input_url_mode_requires_host_approval() {
    let transport = ScriptedTransport::new(vec![
        Reply::ok(url_input_required()),
        Reply::ok(json!({"resultType": "complete"})),
    ]);
    let mut client = task_client(&transport);
    let task = client.tasks_get(&TaskId::new(SECRET)).unwrap();
    let request = &task.input_requests[0];
    assert!(request.requires_host_approval());

    // A bare accept without the matching HostAction is refused before any
    // tasks/update is sent.
    let mut unapproved = InputResponses::new();
    unapproved.accept_form("login", json!({}));
    let error = client.tasks_update_for(&task, &unapproved).unwrap_err();
    assert_eq!(error.code(), ErrorCode::PolicyDenied);
    assert_eq!(transport.requests().len(), 1);
    assert_no_secret(error.message());

    // Missing responses are refused too.
    let error = client
        .tasks_update_for(&task, &InputResponses::new())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidInput);
    assert_eq!(transport.requests().len(), 1);

    let mut approved = InputResponses::new();
    approved.approve_url(&request.host_action().unwrap());
    client.tasks_update_for(&task, &approved).unwrap();

    assert_eq!(transport.requests().len(), 2);
    let update = transport.request(1);
    assert_eq!(update["method"], METHOD_TASKS_UPDATE);
    assert_eq!(
        update["params"]["inputResponses"]["login"],
        json!({"action": "accept"})
    );
    assert_no_secret(&format!("{task:?}"));
}

#[test]
fn cancel_acknowledges_and_stops_polling() {
    let transport = ScriptedTransport::new(vec![
        Reply::ok(json!({"resultType": "complete"})),
        Reply::ok(json!({"resultType": "complete"})),
    ]);
    let mut client = task_client(&transport);
    let id = TaskId::new(SECRET);

    client.tasks_cancel(&id).unwrap();
    let request = transport.request(0);
    assert_eq!(request["method"], METHOD_TASKS_CANCEL);
    assert_eq!(request["params"], json!({"taskId": SECRET}));

    // A cancellation ack must be complete, not another task or input request.
    let transport = ScriptedTransport::new(vec![Reply::ok(json!({
        "resultType": "input_required"
    }))]);
    let mut client = task_client(&transport);
    let error = client.tasks_cancel(&id).unwrap_err();
    assert_eq!(error.code(), ErrorCode::ProviderProtocol);
    assert_no_secret(&error.to_string());
}

#[test]
fn failed_task_is_terminal_and_preserves_the_jsonrpc_error() {
    let transport = ScriptedTransport::new(vec![Reply::ok(failed())]);
    let mut client = task_client(&transport);
    let sleeps = RefCell::new(Vec::new());

    let task = client
        .poll_until_done(
            &TaskId::new(SECRET),
            &|millis: u64| sleeps.borrow_mut().push(millis),
            PollDeadline::new(3),
        )
        .unwrap();

    assert_eq!(task.state, TaskState::Failed);
    assert!(task.is_terminal());
    assert!(task.error.is_some());
    assert_eq!(task.error.as_ref().unwrap()["code"], json!(-32603));
    assert!(task
        .status_message
        .as_deref()
        .unwrap()
        .contains("rate limit"));
    assert!(sleeps.borrow().is_empty());
    assert_no_secret(&format!("{task:?}"));
}

#[test]
fn malformed_task_shapes_are_provider_protocol_errors() {
    let cases = vec![
        without(working(60_000, 1_000), "taskId"),
        set(working(60_000, 1_000), "taskId", json!(7)),
        set(working(60_000, 1_000), "taskId", json!(OTHER)),
        without(working(60_000, 1_000), "status"),
        set(working(60_000, 1_000), "status", json!(7)),
        without(working(60_000, 1_000), "createdAt"),
        set(working(60_000, 1_000), "lastUpdatedAt", json!(7)),
        set(working(60_000, 1_000), "ttlMs", json!(-1)),
        set(working(60_000, 1_000), "ttlMs", json!(1.5)),
        set(working(60_000, 1_000), "pollIntervalMs", json!("soon")),
        set(working(60_000, 1_000), "statusMessage", json!(7)),
        set(working(60_000, 1_000), "resultType", json!("task")),
        set(
            working(60_000, 1_000),
            "resultType",
            json!("input_required"),
        ),
        set(working(60_000, 1_000), "resultType", json!(7)),
        without(completed(), "result"),
        set(completed(), "result", json!("not an object")),
        without(failed(), "error"),
        set(failed(), "error", json!("not an object")),
        set(failed(), "error", json!({"message": "missing code"})),
        set(failed(), "error", json!({"code": -32603})),
        set(
            failed(),
            "error",
            json!({"code": "boom", "message": "bad code"}),
        ),
        without(input_required(), "inputRequests"),
        set(input_required(), "inputRequests", json!([])),
        json!("not an object"),
    ];

    for (index, result) in cases.into_iter().enumerate() {
        let transport = ScriptedTransport::new(vec![Reply::ok(result)]);
        let mut client = task_client(&transport);
        let error = client.tasks_get(&TaskId::new(SECRET)).unwrap_err();
        assert_eq!(
            error.code(),
            ErrorCode::ProviderProtocol,
            "unexpected code for malformed case {index}"
        );
        assert_no_secret(error.message());
        assert_no_secret(&error.to_string());
    }
}

#[test]
fn update_and_cancel_acks_must_be_complete() {
    let transport = ScriptedTransport::new(vec![
        Reply::ok(json!({"resultType": "input_required"})),
        Reply::ok(json!("not an object")),
    ]);
    let mut client = task_client(&transport);
    let id = TaskId::new(SECRET);

    let error = client
        .tasks_update(&id, &InputResponses::new())
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::ProviderProtocol);
    assert_no_secret(error.message());

    let error = client.tasks_cancel(&id).unwrap_err();
    assert_eq!(error.code(), ErrorCode::ProviderProtocol);
    assert_no_secret(error.message());
}

#[test]
fn polling_stops_at_task_ttl_without_leaking_the_id() {
    let replies = (0..10).map(|_| Reply::ok(working(5_000, 1_000))).collect();
    let transport = ScriptedTransport::new(replies);
    let clock = Arc::new(FakeClock::at(0));
    let mut client = task_client(&transport).with_clock(clock.clone());
    let sleeps = RefCell::new(Vec::new());
    let sleeper = |millis: u64| {
        sleeps.borrow_mut().push(millis);
        clock.advance(millis);
    };

    let error = client
        .poll_until_done(&TaskId::new(SECRET), &sleeper, PollDeadline::new(20))
        .unwrap_err();

    assert_eq!(error.code(), ErrorCode::ProviderTimeout);
    assert!(error.message().contains("TTL"));
    assert_no_secret(error.message());
    assert_eq!(*sleeps.borrow(), vec![1_000; 5]);
    assert_eq!(
        transport.requests().len(),
        6,
        "the TTL is detected before the sixth sleep"
    );

    // A poll interval longer than the remaining TTL is capped, so the loop
    // does not sleep past the TTL.
    let transport = ScriptedTransport::new(vec![
        Reply::ok(working(5_000, 10_000)),
        Reply::ok(working(5_000, 10_000)),
    ]);
    let clock = Arc::new(FakeClock::at(0));
    let mut client = task_client(&transport).with_clock(clock.clone());
    let sleeps = RefCell::new(Vec::new());
    let sleeper = |millis: u64| {
        sleeps.borrow_mut().push(millis);
        clock.advance(millis);
    };
    let error = client
        .poll_until_done(&TaskId::new(SECRET), &sleeper, PollDeadline::new(5))
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::ProviderTimeout);
    assert_no_secret(error.message());
    assert_eq!(*sleeps.borrow(), vec![5_000]);
    assert_eq!(transport.requests().len(), 2);
}

#[test]
fn polling_honours_and_follows_a_changing_poll_interval() {
    let transport = ScriptedTransport::new(vec![
        Reply::ok(working(60_000, 2_000)),
        Reply::ok(working(60_000, 500)),
        Reply::ok(completed()),
    ]);
    let clock = Arc::new(FakeClock::at(0));
    let mut client = task_client(&transport).with_clock(clock.clone());
    let sleeps = RefCell::new(Vec::new());
    let sleeper = |millis: u64| {
        sleeps.borrow_mut().push(millis);
        clock.advance(millis);
    };

    let task = client
        .poll_until_done(&TaskId::new(SECRET), &sleeper, PollDeadline::new(5))
        .unwrap();
    assert_eq!(task.state, TaskState::Completed);
    assert_eq!(*sleeps.borrow(), vec![2_000, 500]);

    // No pollIntervalMs uses the caller's default interval.
    let transport = ScriptedTransport::new(vec![
        Reply::ok(working_without_interval()),
        Reply::ok(completed()),
    ]);
    let clock = Arc::new(FakeClock::at(0));
    let mut client = task_client(&transport).with_clock(clock.clone());
    let sleeps = RefCell::new(Vec::new());
    let sleeper = |millis: u64| {
        sleeps.borrow_mut().push(millis);
        clock.advance(millis);
    };
    let deadline = PollDeadline::new(3).with_default_poll_interval_ms(750);
    client
        .poll_until_done(&TaskId::new(SECRET), &sleeper, deadline)
        .unwrap();
    assert_eq!(*sleeps.borrow(), vec![750]);
}

#[test]
fn polling_deadline_and_attempt_count_are_bounded() {
    let transport = ScriptedTransport::new(vec![
        Reply::ok(working(60_000, 1_000)),
        Reply::ok(working(60_000, 1_000)),
        Reply::ok(working(60_000, 1_000)),
    ]);
    let clock = Arc::new(FakeClock::at(0));
    let mut client = task_client(&transport).with_clock(clock.clone());
    let sleeps = RefCell::new(Vec::new());
    let sleeper = |millis: u64| {
        sleeps.borrow_mut().push(millis);
        clock.advance(millis);
    };

    let error = client
        .poll_until_done(&TaskId::new(SECRET), &sleeper, PollDeadline::new(3))
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::ProviderTimeout);
    assert!(error.message().contains("3 attempts"));
    assert_no_secret(error.message());
    assert_eq!(*sleeps.borrow(), vec![1_000, 1_000]);
}

#[test]
fn task_id_is_a_bearer_secret_in_debug_display_and_errors() {
    let id = TaskId::new(SECRET);
    assert_eq!(format!("{id:?}"), "[redacted]");
    assert_eq!(format!("{id}"), "[redacted]");
    assert_eq!(id.secret(), SECRET);
    assert_eq!(
        serde_json::to_value(&id).unwrap(),
        json!(SECRET),
        "the wire form must carry the raw id"
    );

    // A server that echoes the id in statusMessage must not leak it through
    // the Task debug form.
    let mut result = completed();
    result["statusMessage"] = json!(format!("completed {SECRET}"));
    result["createdAt"] = json!(format!("2025-11-25T10:30:00Z-{SECRET}"));
    let transport = ScriptedTransport::new(vec![Reply::ok(result)]);
    let mut client = task_client(&transport);
    let task = client.tasks_get(&id).unwrap();
    let debug = format!("{task:?}");
    assert_no_secret(&debug);
    assert!(debug.contains("[redacted]"));

    // An unknown status is preserved, but the debug form scrubs the secret.
    let mut unknown = working(60_000, 1_000);
    unknown["status"] = json!(format!("deploying-{SECRET}"));
    let transport = ScriptedTransport::new(vec![Reply::ok(unknown)]);
    let mut client = task_client(&transport);
    let task = client.tasks_get(&id).unwrap();
    assert_eq!(
        task.state,
        TaskState::Unknown(format!("deploying-{SECRET}"))
    );
    assert_no_secret(&format!("{task:?}"));

    // A server error message that contains the id is scrubbed.
    let transport = ScriptedTransport::new(vec![Reply::err(
        -32602,
        format!("Task not found: {SECRET}"),
    )]);
    let mut client = task_client(&transport);
    let error = client.tasks_get(&id).unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidInput);
    assert_no_secret(error.message());
    assert!(error.message().contains("[redacted]"));
    assert_no_secret(&error.to_string());
}

#[test]
fn unknown_state_is_preserved_and_stops_polling() {
    let mut paused = working(60_000, 1_000);
    paused["status"] = json!("paused");
    let transport = ScriptedTransport::new(vec![Reply::ok(paused)]);
    let mut client = task_client(&transport);
    let sleeps = RefCell::new(Vec::new());

    let task = client
        .poll_until_done(
            &TaskId::new(SECRET),
            &|millis: u64| sleeps.borrow_mut().push(millis),
            PollDeadline::new(3),
        )
        .unwrap();

    assert_eq!(task.state, TaskState::Unknown("paused".to_string()));
    assert!(!task.is_terminal());
    assert!(sleeps.borrow().is_empty());
    assert_no_secret(&format!("{task:?}"));
}

#[test]
fn tasks_require_the_2026_07_28_revision() {
    let transport = ScriptedTransport::new(vec![]);
    let mut client =
        Client::new("tasks-fixture", &transport).with_revision(McpRevision::V2025_11_25);
    let id = TaskId::new(SECRET);

    for error in [
        client.tasks_get(&id).unwrap_err(),
        client
            .tasks_update(&id, &InputResponses::new())
            .unwrap_err(),
        client.tasks_cancel(&id).unwrap_err(),
    ] {
        assert_eq!(error.code(), ErrorCode::Unsupported);
        assert_no_secret(error.message());
    }
    assert!(
        transport.requests().is_empty(),
        "an unsupported revision must not exchange a task request"
    );
}
