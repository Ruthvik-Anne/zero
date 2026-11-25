//! JSON-RPC 2.0 envelopes and error mapping (MCP-01).
//!
//! Only the shapes the client needs are modelled: a request with a numeric or
//! string id, and a response carrying exactly one of `result` or `error`.
//! Notifications and server-initiated requests are later tasks.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zero_types::error::{ErrorCode, Result, ZeroError};

/// The only JSON-RPC version this crate speaks.
pub const JSONRPC_VERSION: &str = "2.0";

/// A JSON-RPC request id. The client emits numbers; a string is accepted when
/// parsing a response so a server that echoes a string is not a protocol error.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    /// Numeric id, as emitted by [`crate::Client`].
    Number(u64),
    /// String id, for generic envelope handling.
    String(String),
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestId::Number(n) => write!(f, "{n}"),
            RequestId::String(s) => write!(f, "`{s}`"),
        }
    }
}

/// A JSON-RPC 2.0 request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    /// Always [`JSONRPC_VERSION`].
    pub jsonrpc: String,
    /// Request id, echoed by the response.
    pub id: RequestId,
    /// Method name such as `tools/list`.
    pub method: String,
    /// Method parameters, omitted when there are none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl Request {
    /// Build a request for `method` with an explicit id and optional params.
    pub fn new(id: RequestId, method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            method: method.into(),
            params,
        }
    }
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcError {
    /// JSON-RPC error code. `-32020..=-32099` are reserved by the MCP
    /// specification; this crate does not assign them.
    pub code: i64,
    /// Human-readable message from the server. Untrusted server data.
    pub message: String,
    /// Optional structured details. Kept out of the mapped [`ZeroError`]
    /// message so a large or sensitive blob is not copied into logs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcError {
    /// Map a JSON-RPC code onto the stable Zero error taxonomy.
    ///
    /// The original code and message are preserved in the mapped error's
    /// message; the stable code is chosen from the caller's point of view:
    ///
    /// - `-32700` parse error, `-32600` invalid request, and `-32602` invalid
    ///   params: we sent something the server could not accept
    ///   ([`ErrorCode::InvalidInput`]).
    /// - `-32601` method not found: the server does not implement it
    ///   ([`ErrorCode::Unsupported`]).
    /// - Everything else, including `-32603` internal error: a server or
    ///   protocol failure ([`ErrorCode::ProviderProtocol`]).
    pub fn error_code(&self) -> ErrorCode {
        match self.code {
            -32700 | -32600 | -32602 => ErrorCode::InvalidInput,
            -32601 => ErrorCode::Unsupported,
            _ => ErrorCode::ProviderProtocol,
        }
    }

    /// Render as a [`ZeroError`], keeping the wire code and message.
    pub fn into_zero_error(self) -> ZeroError {
        let code = self.error_code();
        ZeroError::new(
            code,
            format!("JSON-RPC error {}: {}", self.code, self.message),
        )
    }
}

impl From<RpcError> for ZeroError {
    fn from(error: RpcError) -> Self {
        error.into_zero_error()
    }
}

/// A protocol-shape failure: malformed envelope, mismatched id, or missing
/// `result`/`error`. This never describes a server-declared JSON-RPC error.
pub fn protocol_error(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::ProviderProtocol, message)
}

/// Validate a response envelope and return its `result`.
///
/// The envelope must be an object, name JSON-RPC `2.0`, echo `expected_id`,
/// and contain exactly one of `result` or `error`. A JSON-RPC error object is
/// mapped through [`RpcError`]; every other shape failure is
/// [`ErrorCode::ProviderProtocol`].
pub fn expect_result(response: Value, expected_id: &RequestId) -> Result<Value> {
    let object = match response {
        Value::Object(object) => object,
        _ => return Err(protocol_error("JSON-RPC response must be a JSON object")),
    };

    match object.get("jsonrpc") {
        Some(Value::String(version)) if version == JSONRPC_VERSION => {}
        Some(other) => {
            return Err(protocol_error(format!(
                "JSON-RPC response has unsupported version {other}"
            )))
        }
        None => return Err(protocol_error("JSON-RPC response is missing `jsonrpc`")),
    }

    let id_value = object
        .get("id")
        .ok_or_else(|| protocol_error("JSON-RPC response is missing `id`"))?;
    let id: RequestId = serde_json::from_value(id_value.clone()).map_err(|_| {
        protocol_error(format!(
            "JSON-RPC response id must be a number or string, got {id_value}"
        ))
    })?;
    if &id != expected_id {
        return Err(protocol_error(format!(
            "JSON-RPC response id {id} does not match request id {expected_id}"
        )));
    }

    let has_result = object.get("result").is_some();
    let error = object.get("error").filter(|value| !value.is_null());

    if let Some(error) = error {
        if has_result {
            return Err(protocol_error(
                "JSON-RPC response contains both `result` and `error`",
            ));
        }
        let error: RpcError = serde_json::from_value(error.clone())
            .map_err(|cause| protocol_error(format!("malformed JSON-RPC error object: {cause}")))?;
        return Err(error.into_zero_error());
    }

    match object.get("result") {
        Some(result) => Ok(result.clone()),
        None => Err(protocol_error(
            "JSON-RPC response contains neither `result` nor `error`",
        )),
    }
}

/// Require a result object and name the method in any error.
pub fn expect_object(result: Value, method: &str) -> Result<Map<String, Value>> {
    match result {
        Value::Object(object) => Ok(object),
        _ => Err(protocol_error(format!(
            "`{method}` result must be a JSON object"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_serialises_without_empty_params() {
        let request = Request::new(RequestId::Number(7), "tools/list", None);
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list"})
        );
    }

    #[test]
    fn successful_result_is_returned() {
        let response = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}});
        let result = expect_result(response, &RequestId::Number(1)).unwrap();
        assert_eq!(result, json!({"tools": []}));
    }

    #[test]
    fn error_object_keeps_code_and_message() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32601, "message": "Method not found"}
        });
        let error = expect_result(response, &RequestId::Number(1)).unwrap_err();
        assert_eq!(error.code(), ErrorCode::Unsupported);
        assert!(error.message().contains("-32601"));
        assert!(error.message().contains("Method not found"));
    }

    #[test]
    fn malformed_envelopes_are_protocol_errors() {
        let expected = RequestId::Number(1);
        let cases = [
            json!({"id": 1, "result": {}}),
            json!({"jsonrpc": "1.0", "id": 1, "result": {}}),
            json!({"jsonrpc": "2.0", "result": {}}),
            json!({"jsonrpc": "2.0", "id": 2, "result": {}}),
            json!({"jsonrpc": "2.0", "id": 1}),
            json!({"jsonrpc": "2.0", "id": 1, "result": {}, "error": {"code": -1, "message": "x"}}),
            json!({"jsonrpc": "2.0", "id": 1, "error": {"message": "no code"}}),
        ];
        for response in cases {
            let error = expect_result(response.clone(), &expected).unwrap_err();
            assert_eq!(
                error.code(),
                ErrorCode::ProviderProtocol,
                "unexpected code for {response}"
            );
        }

        let error = expect_result(json!("not an object"), &expected).unwrap_err();
        assert_eq!(error.code(), ErrorCode::ProviderProtocol);
    }
}
