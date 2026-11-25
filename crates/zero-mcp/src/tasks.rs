//! MCP tasks (T-MCP-04, MCP-04, MCP-09).
//!
//! Source: the MCP Tasks extension `io.modelcontextprotocol/tasks` for revision
//! `2026-07-28`
//! ([specification](https://tasks.extensions.modelcontextprotocol.io/specification/2026-07-28/tasks.html),
//! [schema](https://github.com/modelcontextprotocol/ext-tasks/blob/main/schema/2026-07-28/schema.ts)).
//! The extension defines three methods:
//!
//! - `tasks/get` with `params.taskId` returns the current [`Task`] with
//!   `resultType: "complete"`.
//! - `tasks/update` with `params.taskId` and `params.inputResponses` answers
//!   outstanding `inputRequests` and returns an empty `complete` acknowledgement.
//! - `tasks/cancel` with `params.taskId` returns an empty `complete`
//!   acknowledgement. Cancellation is cooperative.
//!
//! A server creates a task by returning a `CreateTaskResult` (`resultType:
//! "task"`, a flat `Task` plus `resultType`) from a supported request such as
//! `tools/call`; [`Task::from_create_result`] parses that handle.
//!
//! Task IDs are bearer secrets (MCP-09): [`TaskId`] prints `[redacted]` through
//! `Debug` and `Display`, the raw value is available only through
//! [`TaskId::secret`], and this module scrubs the raw value from every error it
//! returns, including error messages supplied by the server.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::client::{Client, ResultType, Transport};
use crate::jsonrpc::{expect_object, protocol_error};
use crate::mrtr::{parse_input_requests, InputRequest, InputResponses};

/// `tasks/get` method name.
pub const METHOD_TASKS_GET: &str = "tasks/get";
/// `tasks/update` method name.
pub const METHOD_TASKS_UPDATE: &str = "tasks/update";
/// `tasks/cancel` method name.
pub const METHOD_TASKS_CANCEL: &str = "tasks/cancel";

/// Extension identifier used in per-request capabilities.
pub const TASKS_EXTENSION: &str = "io.modelcontextprotocol/tasks";

/// A server-generated task identifier.
///
/// The identifier is a bearer secret. It serialises to the raw string on the
/// wire, but its `Debug` and `Display` forms are always `[redacted]`. Use
/// [`TaskId::secret`] only at the point where the raw value must be sent.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TaskId(String);

impl TaskId {
    /// Wrap a raw task id received from a server or restored from storage.
    ///
    /// This constructor does not validate the value; [`Client::tasks_get`] and
    /// the other task methods refuse an empty id with `zero.fnd.invalid_input`.
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// The raw bearer value. Never log or format this.
    pub fn secret(&self) -> &str {
        &self.0
    }

    /// Whether the id is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn from_wire(value: String) -> Result<Self> {
        if value.is_empty() {
            return Err(protocol_error("`taskId` must be a non-empty string"));
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for TaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl fmt::Display for TaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// The task state machine from the `2026-07-28` extension.
///
/// `completed`, `failed`, and `cancelled` are terminal. This client retains an
/// unrecognised status as [`TaskState::Unknown`] rather than failing, so a
/// newer server can add a state without breaking the lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskState {
    /// The operation is in progress.
    Working,
    /// The server needs client input; `Task::input_requests` carries the
    /// outstanding requests to answer with [`Client::tasks_update`].
    InputRequired,
    /// The operation finished; `Task::result` carries the original result.
    Completed,
    /// The operation failed with a JSON-RPC error in `Task::error`.
    Failed,
    /// The operation was cancelled (cooperatively; not guaranteed).
    Cancelled,
    /// A status this client does not know, preserved verbatim.
    Unknown(String),
}

impl TaskState {
    /// Parse a wire status. Unknown strings become [`TaskState::Unknown`].
    pub fn parse(value: &str) -> Self {
        match value {
            "working" => TaskState::Working,
            "input_required" => TaskState::InputRequired,
            "completed" => TaskState::Completed,
            "failed" => TaskState::Failed,
            "cancelled" => TaskState::Cancelled,
            other => TaskState::Unknown(other.to_string()),
        }
    }

    /// Wire spelling, preserved for an unknown state.
    pub fn as_str(&self) -> &str {
        match self {
            TaskState::Working => "working",
            TaskState::InputRequired => "input_required",
            TaskState::Completed => "completed",
            TaskState::Failed => "failed",
            TaskState::Cancelled => "cancelled",
            TaskState::Unknown(value) => value,
        }
    }

    /// Whether the state is terminal (`completed`, `failed`, or `cancelled`).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TaskState::Completed | TaskState::Failed | TaskState::Cancelled
        )
    }

    /// Whether the state can make progress without client action.
    pub fn is_working(&self) -> bool {
        matches!(self, TaskState::Working)
    }
}

impl fmt::Display for TaskState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One task returned by `tasks/get` or embedded in a `CreateTaskResult`.
///
/// `result`, `error`, `status_message`, and the input-request payloads are
/// untrusted server data. The manual `Debug` implementation reports only
/// presence and scrub the raw task id; it never prints result or error content,
/// because a server can echo its own task id in arbitrary payloads.
#[derive(Clone, PartialEq)]
pub struct Task {
    /// Server-generated bearer-secret id.
    pub id: TaskId,
    /// Current state.
    pub state: TaskState,
    /// Optional human-readable state message.
    pub status_message: Option<String>,
    /// Time-to-live from creation in milliseconds; `None` means unlimited.
    pub ttl_ms: Option<u64>,
    /// Suggested polling interval in milliseconds.
    pub poll_interval_ms: Option<u64>,
    /// Final result for a completed task, passed through as untrusted data.
    pub result: Option<Value>,
    /// JSON-RPC error for a failed task, passed through as untrusted data.
    pub error: Option<Value>,
    /// Outstanding requests for an `input_required` task, validated by the
    /// same parser used for MRTR elicitation.
    pub input_requests: Vec<InputRequest>,
    /// ISO 8601 creation timestamp, preserved as a string.
    pub created_at: String,
    /// ISO 8601 last-update timestamp, preserved as a string.
    pub last_updated_at: String,
}

impl Task {
    /// Whether the task reached a terminal state.
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Whether the task is waiting for client input.
    pub fn requires_input(&self) -> bool {
        self.state == TaskState::InputRequired
    }

    /// Parse the flat `CreateTaskResult` (`resultType: "task"`) returned by a
    /// server in place of a normal result.
    pub fn from_create_result(result: Value) -> Result<Self> {
        let object = expect_object(result, "CreateTaskResult")?;
        match object.get("resultType") {
            Some(Value::String(value)) if value == "task" => {}
            Some(Value::String(_)) => {
                return Err(protocol_error(
                    "`CreateTaskResult` resultType must be `task`",
                ))
            }
            Some(other) => {
                return Err(field_type_error(
                    "CreateTaskResult",
                    "resultType",
                    "a string",
                    other,
                ))
            }
            None => return Err(protocol_error("`CreateTaskResult` is missing `resultType`")),
        }
        Self::from_object(&object, None, "CreateTaskResult")
    }

    fn from_object(
        object: &Map<String, Value>,
        expected: Option<&TaskId>,
        context: &str,
    ) -> Result<Self> {
        let id = match object.get("taskId") {
            Some(Value::String(value)) => TaskId::from_wire(value.clone())?,
            Some(other) => {
                return Err(field_type_error(context, "taskId", "a string", other));
            }
            None => {
                return Err(protocol_error(format!(
                    "`{context}` result is missing `taskId`"
                )))
            }
        };
        if let Some(expected) = expected {
            if &id != expected {
                return Err(protocol_error(format!(
                    "`{context}` returned a different `taskId`"
                )));
            }
        }

        let state = match object.get("status") {
            Some(Value::String(value)) => TaskState::parse(value),
            Some(other) => {
                return Err(field_type_error(context, "status", "a string", other));
            }
            None => {
                return Err(protocol_error(format!(
                    "`{context}` result is missing `status`"
                )))
            }
        };

        let status_message = optional_string(object, "statusMessage", context)?;
        let ttl_ms = optional_u64(object, "ttlMs", context)?;
        let poll_interval_ms = optional_u64(object, "pollIntervalMs", context)?;
        let created_at = required_string(object, "createdAt", context)?;
        let last_updated_at = required_string(object, "lastUpdatedAt", context)?;
        let result = optional_object(object, "result", context)?;
        let error = optional_object(object, "error", context)?;

        if state == TaskState::Completed && result.is_none() {
            return Err(protocol_error(format!(
                "`{context}` completed task is missing `result`"
            )));
        }
        if state == TaskState::Failed {
            let error = error.as_ref().ok_or_else(|| {
                protocol_error(format!("`{context}` failed task is missing `error`"))
            })?;
            validate_jsonrpc_error(error, context)?;
        }
        if state == TaskState::InputRequired && !has_non_null(object, "inputRequests") {
            return Err(protocol_error(format!(
                "`{context}` input_required task is missing `inputRequests`"
            )));
        }
        let input_requests = match object.get("inputRequests") {
            None | Some(Value::Null) => Vec::new(),
            Some(value) => parse_input_requests(value)?,
        };

        Ok(Self {
            id,
            state,
            status_message,
            ttl_ms,
            poll_interval_ms,
            result,
            error,
            input_requests,
            created_at,
            last_updated_at,
        })
    }
}

impl fmt::Debug for Task {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secret = self.id.secret();
        let state = match &self.state {
            TaskState::Unknown(value) => format!("Unknown({:?})", redact(value, secret)),
            state => format!("{state:?}"),
        };
        let status_message = self
            .status_message
            .as_deref()
            .map(|message| redact(message, secret));
        let created_at = redact(&self.created_at, secret);
        let last_updated_at = redact(&self.last_updated_at, secret);
        f.debug_struct("Task")
            .field("id", &self.id)
            .field("state", &state)
            .field("status_message", &status_message)
            .field("ttl_ms", &self.ttl_ms)
            .field("poll_interval_ms", &self.poll_interval_ms)
            .field("has_result", &self.result.is_some())
            .field("has_error", &self.error.is_some())
            .field("input_requests", &self.input_requests.len())
            .field("created_at", &created_at)
            .field("last_updated_at", &last_updated_at)
            .finish()
    }
}

/// A sleep seam for polling. Tests inject a recorder instead of sleeping.
pub trait Sleeper {
    /// Sleep for `millis` milliseconds.
    fn sleep_ms(&self, millis: u64);
}

impl<F: Fn(u64)> Sleeper for F {
    fn sleep_ms(&self, millis: u64) {
        self(millis);
    }
}

/// A sleeper that does nothing. Useful for scripts and tests that only care
/// about the attempt bound.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopSleeper;

impl Sleeper for NoopSleeper {
    fn sleep_ms(&self, _millis: u64) {}
}

/// A sleeper backed by the operating system.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemSleeper;

impl Sleeper for SystemSleeper {
    fn sleep_ms(&self, millis: u64) {
        std::thread::sleep(Duration::from_millis(millis));
    }
}

/// Bounds for [`Client::poll_until_done`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollDeadline {
    /// Maximum number of `tasks/get` calls, including the first. Must be at
    /// least one.
    pub max_attempts: u32,
    /// Optional wall-clock budget measured from the first poll. `None` means
    /// only the task TTL and the attempt count bound the loop.
    pub max_wait_ms: Option<u64>,
    /// Interval used when a task response omits `pollIntervalMs`.
    pub default_poll_interval_ms: u64,
}

impl PollDeadline {
    /// Default attempt bound.
    pub const DEFAULT_MAX_ATTEMPTS: u32 = 60;
    /// Default interval when a server gives no hint.
    pub const DEFAULT_POLL_INTERVAL_MS: u64 = 1_000;

    /// A deadline with `max_attempts` and no extra wall-clock budget.
    pub fn new(max_attempts: u32) -> Self {
        Self {
            max_attempts,
            max_wait_ms: None,
            default_poll_interval_ms: Self::DEFAULT_POLL_INTERVAL_MS,
        }
    }

    /// Add an absolute wall-clock budget, measured from the first poll.
    pub fn with_max_wait_ms(mut self, max_wait_ms: u64) -> Self {
        self.max_wait_ms = Some(max_wait_ms);
        self
    }

    /// Replace the interval used when a task omits `pollIntervalMs`.
    pub fn with_default_poll_interval_ms(mut self, interval_ms: u64) -> Self {
        self.default_poll_interval_ms = interval_ms;
        self
    }
}

impl Default for PollDeadline {
    fn default() -> Self {
        Self::new(Self::DEFAULT_MAX_ATTEMPTS)
    }
}

impl<T: Transport> Client<T> {
    /// Fetch the current state of a task with `tasks/get`.
    ///
    /// The result must carry `resultType: "complete"`, the same `taskId` that
    /// was requested, a known or unknown status, `createdAt` and
    /// `lastUpdatedAt` strings, and the status-specific payload the extension
    /// requires: `result` for `completed`, `error` for `failed`, and
    /// `inputRequests` for `input_required`. A malformed shape is
    /// `zero.prv.protocol`. An empty id is `zero.fnd.invalid_input`; revisions
    /// before `2026-07-28` are `zero.fnd.unsupported` because this method set
    /// is defined by the `2026-07-28` extension.
    pub fn tasks_get(&mut self, id: &TaskId) -> Result<Task> {
        self.check_task_request(id)?;
        let params = json!({"taskId": id.secret()});
        let result = self
            .exchange(METHOD_TASKS_GET, Some(params))
            .map_err(|error| scrub_task_id(error, id))?;
        self.parse_get_task_result(result, id)
            .map_err(|error| scrub_task_id(error, id))
    }

    /// Answer outstanding `inputRequests` with `tasks/update`.
    ///
    /// The extension has no progress field: `statusMessage` is server-provided
    /// and `tasks/update` accepts only `inputResponses`. Responses are built
    /// through [`InputResponses`]; use [`Self::tasks_update_for`] to validate
    /// them against the task's outstanding requests and URL approvals. The
    /// acknowledgement must be `resultType: "complete"`.
    pub fn tasks_update(&mut self, id: &TaskId, responses: &InputResponses) -> Result<()> {
        self.check_task_request(id)?;
        let params = json!({
            "taskId": id.secret(),
            "inputResponses": responses.as_value(),
        });
        let result = self
            .exchange(METHOD_TASKS_UPDATE, Some(params))
            .map_err(|error| scrub_task_id(error, id))?;
        self.expect_task_ack(result, METHOD_TASKS_UPDATE)
            .map_err(|error| scrub_task_id(error, id))
    }

    /// Validate `responses` against the task's outstanding `inputRequests`,
    /// then send `tasks/update`.
    ///
    /// This is the checked form of [`Self::tasks_update`]: it uses the same
    /// [`InputResponses`] validation as MRTR, so every outstanding request has
    /// a response, no extra key is present, and a URL-mode acceptance needs the
    /// [`crate::HostAction`] from the matching request. The task must carry the
    /// requests from the most recent `tasks/get` (or notification).
    pub fn tasks_update_for(&mut self, task: &Task, responses: &InputResponses) -> Result<()> {
        responses
            .validate_for(&task.input_requests)
            .map_err(|error| scrub_task_id(error, &task.id))?;
        self.tasks_update(&task.id, responses)
    }

    /// Signal cancellation intent with `tasks/cancel`.
    ///
    /// Cancellation is cooperative and eventually consistent: the server
    /// acknowledges the request with an empty `complete` result and may still
    /// finish the work or reach another terminal state.
    pub fn tasks_cancel(&mut self, id: &TaskId) -> Result<()> {
        self.check_task_request(id)?;
        let params = json!({"taskId": id.secret()});
        let result = self
            .exchange(METHOD_TASKS_CANCEL, Some(params))
            .map_err(|error| scrub_task_id(error, id))?;
        self.expect_task_ack(result, METHOD_TASKS_CANCEL)
            .map_err(|error| scrub_task_id(error, id))
    }

    /// Poll `tasks/get` until the task leaves `working`.
    ///
    /// `pollIntervalMs` from each response is used for the next sleep and may
    /// change over the lifetime of the task; when it is absent the deadline's
    /// `default_poll_interval_ms` is used. Each sleep is capped by the
    /// remaining TTL or wall-clock budget. Polling stops and returns the task
    /// in every non-`working` state: terminal (`completed`, `failed`,
    /// `cancelled`), `input_required` (the caller answers with
    /// [`Self::tasks_update`] and may poll again), and an unknown status.
    ///
    /// A non-null `ttlMs` is treated as a budget measured from the first poll,
    /// because this crate deliberately has no date parser; `createdAt` is
    /// preserved but not used for arithmetic. `ttlMs: 0` expires immediately
    /// unless the first response is already terminal. Exceeding the TTL, the
    /// optional wall-clock budget, or the attempt count returns
    /// `zero.prv.timeout` without naming the task id. The sleeper is injected:
    /// tests record sleeps instead of waiting, and a test sleeper that advances
    /// the client's clock makes TTL and deadline checks deterministic.
    pub fn poll_until_done<S: Sleeper + ?Sized>(
        &mut self,
        id: &TaskId,
        sleeper: &S,
        deadline: PollDeadline,
    ) -> Result<Task> {
        self.check_task_request(id)?;
        if deadline.max_attempts == 0 {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                "task polling needs at least one attempt",
            ));
        }

        let started_ms = self.clock_now().0;
        let mut interval_ms = deadline.default_poll_interval_ms;

        for attempt in 1..=deadline.max_attempts {
            let task = self.tasks_get(id)?;
            if !task.state.is_working() {
                return Ok(task);
            }

            let elapsed_ms = self.clock_now().0.saturating_sub(started_ms).max(0) as u64;
            if let Some(ttl_ms) = task.ttl_ms {
                if elapsed_ms >= ttl_ms {
                    return Err(ZeroError::new(
                        ErrorCode::ProviderTimeout,
                        format!(
                            "task TTL expired after {ttl_ms} ms without reaching a terminal state"
                        ),
                    ));
                }
            }
            if let Some(max_wait_ms) = deadline.max_wait_ms {
                if elapsed_ms >= max_wait_ms {
                    return Err(ZeroError::new(
                        ErrorCode::ProviderTimeout,
                        format!("task polling deadline expired after {max_wait_ms} ms"),
                    ));
                }
            }
            if attempt == deadline.max_attempts {
                break;
            }
            if let Some(poll_interval_ms) = task.poll_interval_ms {
                interval_ms = poll_interval_ms;
            }
            let mut sleep_ms = interval_ms;
            if let Some(ttl_ms) = task.ttl_ms {
                sleep_ms = sleep_ms.min(ttl_ms.saturating_sub(elapsed_ms));
            }
            if let Some(max_wait_ms) = deadline.max_wait_ms {
                sleep_ms = sleep_ms.min(max_wait_ms.saturating_sub(elapsed_ms));
            }
            sleeper.sleep_ms(sleep_ms);
        }

        Err(ZeroError::new(
            ErrorCode::ProviderTimeout,
            format!(
                "task polling gave up after {} attempts without reaching a terminal state",
                deadline.max_attempts
            ),
        ))
    }

    fn parse_get_task_result(&self, result: Value, expected: &TaskId) -> Result<Task> {
        let object = expect_object(result, METHOD_TASKS_GET)?;
        if !ResultType::from_result(self.current_revision(), &object)?.is_complete() {
            return Err(protocol_error("`tasks/get` resultType must be `complete`"));
        }
        Task::from_object(&object, Some(expected), METHOD_TASKS_GET)
    }

    fn expect_task_ack(&self, result: Value, method: &str) -> Result<()> {
        let object = expect_object(result, method)?;
        if !ResultType::from_result(self.current_revision(), &object)?.is_complete() {
            return Err(protocol_error(format!(
                "`{method}` resultType must be `complete`"
            )));
        }
        Ok(())
    }

    fn check_task_request(&self, id: &TaskId) -> Result<()> {
        if !self.current_revision().supports_result_type() {
            return Err(ZeroError::new(
                ErrorCode::Unsupported,
                "MCP tasks require the `2026-07-28` revision",
            ));
        }
        if id.is_empty() {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                "task id must not be empty",
            ));
        }
        Ok(())
    }
}

/// Replace any occurrence of the raw task id in an error message.
///
/// A server is free to echo the id in a JSON-RPC error message, so the client
/// cannot rely on its own messages alone. The code is preserved.
fn scrub_task_id(error: ZeroError, id: &TaskId) -> ZeroError {
    let secret = id.secret();
    if secret.is_empty() || !error.message().contains(secret) {
        return error;
    }
    ZeroError::new(error.code(), error.message().replace(secret, "[redacted]"))
}

fn redact(value: &str, secret: &str) -> String {
    if secret.is_empty() {
        value.to_string()
    } else {
        value.replace(secret, "[redacted]")
    }
}

fn has_non_null(object: &Map<String, Value>, key: &str) -> bool {
    object.get(key).is_some_and(|value| !value.is_null())
}

/// Check the JSON-RPC error shape carried by a failed task.
///
/// The error is retained as raw untrusted data, but a failed task must carry a
/// JSON-RPC error, so the required `code` (integer) and `message` (string)
/// fields are validated. Their values are never formatted into an error.
fn validate_jsonrpc_error(value: &Value, context: &str) -> Result<()> {
    let object = value.as_object().ok_or_else(|| {
        protocol_error(format!(
            "`{context}` failed task `error` must be a JSON object"
        ))
    })?;
    match object.get("code") {
        Some(Value::Number(number)) if number.as_i64().is_some() => {}
        Some(_) => {
            return Err(protocol_error(format!(
                "`{context}` failed task `error.code` must be an integer"
            )))
        }
        None => {
            return Err(protocol_error(format!(
                "`{context}` failed task `error` is missing `code`"
            )))
        }
    }
    match object.get("message") {
        Some(Value::String(_)) => {}
        Some(_) => {
            return Err(protocol_error(format!(
                "`{context}` failed task `error.message` must be a string"
            )))
        }
        None => {
            return Err(protocol_error(format!(
                "`{context}` failed task `error` is missing `message`"
            )))
        }
    }
    Ok(())
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Build a type error without formatting the offending value, so an id or
/// other secret in the value cannot leak into an error message.
fn field_type_error(context: &str, key: &str, expected: &str, value: &Value) -> ZeroError {
    protocol_error(format!(
        "`{context}` {key} must be {expected}, got {}",
        type_name(value)
    ))
}

fn required_string(object: &Map<String, Value>, key: &str, context: &str) -> Result<String> {
    match object.get(key) {
        Some(Value::String(value)) if !value.is_empty() => Ok(value.clone()),
        Some(Value::String(_)) => Err(protocol_error(format!(
            "`{context}` {key} must not be empty"
        ))),
        Some(other) => Err(field_type_error(context, key, "a string", other)),
        None => Err(protocol_error(format!(
            "`{context}` result is missing `{key}`"
        ))),
    }
}

fn optional_string(
    object: &Map<String, Value>,
    key: &str,
    context: &str,
) -> Result<Option<String>> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(other) => Err(field_type_error(context, key, "a string", other)),
    }
}

fn optional_u64(object: &Map<String, Value>, key: &str, context: &str) -> Result<Option<u64>> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => number.as_u64().map(Some).ok_or_else(|| {
            protocol_error(format!("`{context}` {key} must be a non-negative integer"))
        }),
        Some(other) => Err(field_type_error(
            context,
            key,
            "a non-negative integer",
            other,
        )),
    }
}

fn optional_object(object: &Map<String, Value>, key: &str, context: &str) -> Result<Option<Value>> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value @ Value::Object(_)) => Ok(Some(value.clone())),
        Some(other) => Err(field_type_error(context, key, "a JSON object", other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_id_redacts_debug_and_display_but_serialises_the_wire_value() {
        let id = TaskId::new("secret-task-id");
        assert_eq!(format!("{id:?}"), "[redacted]");
        assert_eq!(format!("{id}"), "[redacted]");
        assert_eq!(id.secret(), "secret-task-id");
        assert_eq!(serde_json::to_value(&id).unwrap(), json!("secret-task-id"));
        assert_eq!(
            serde_json::from_value::<TaskId>(json!("secret-task-id")).unwrap(),
            id
        );
    }

    #[test]
    fn unknown_states_are_preserved_and_terminal_states_are_recognised() {
        assert_eq!(
            TaskState::parse("paused"),
            TaskState::Unknown("paused".into())
        );
        assert_eq!(TaskState::Unknown("paused".into()).as_str(), "paused");
        assert!(!TaskState::Working.is_terminal());
        assert!(!TaskState::InputRequired.is_terminal());
        assert!(TaskState::Completed.is_terminal());
        assert!(TaskState::Failed.is_terminal());
        assert!(TaskState::Cancelled.is_terminal());
        assert!(!TaskState::Unknown("paused".into()).is_terminal());
    }
}
