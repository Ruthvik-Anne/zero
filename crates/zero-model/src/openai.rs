//! OpenAI-compatible hosted adapter (PRV-02). Streaming SSE, tool calls, usage.
//!
//! The adapter is the production path for any OpenAI-compatible endpoint; the
//! parser is separated from the transport so recorded fixtures test it exactly.

use crate::errors::{map_reqwest, map_status, map_transport, malformed_body, retry_after};
use crate::provider::{
    Capabilities, CompletionRequest, Control, EventSink, Message, Provider, ProviderEvent,
    ProviderResponse, Role, StopReason, ToolCall, Usage,
};
use std::io::{BufRead, BufReader};
use std::time::Instant;
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone)]
pub struct OpenAiConfig {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
    pub timeout_ms: u64,
    pub context_limit: u64,
    pub output_limit: u64,
}

impl OpenAiConfig {
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            api_key: api_key.into(),
            model: model.into(),
            timeout_ms: 120_000,
            context_limit: 128_000,
            output_limit: 8_192,
        }
    }
}

pub struct OpenAiProvider {
    config: OpenAiConfig,
    client: reqwest::blocking::Client,
    calls: u32,
}

impl OpenAiProvider {
    pub fn new(config: OpenAiConfig) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|e| map_reqwest(&e))?;
        Ok(Self { config, client, calls: 0 })
    }

    pub fn calls(&self) -> u32 {
        self.calls
    }

    fn endpoint(&self) -> String {
        format!("{}/chat/completions", self.config.base_url.trim_end_matches('/'))
    }
}

impl Provider for OpenAiProvider {
    fn id(&self) -> &str {
        "openai"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            streaming: true,
            tool_calls: true,
            vision: true,
            context_limit: self.config.context_limit,
            output_limit: self.config.output_limit,
        }
    }

    fn complete(
        &mut self,
        request: &CompletionRequest,
        sink: &mut dyn EventSink,
    ) -> Result<ProviderResponse> {
        self.calls += 1;
        let started = Instant::now();
        let body = request_body(request, &self.config.model);
        let response = self
            .client
            .post(self.endpoint())
            .bearer_auth(&self.config.api_key)
            .json(&body)
            .send()
            .map_err(|e| map_reqwest(&e))?;
        let status = response.status();
        if !status.is_success() {
            let retry = retry_after(response.headers());
            let text = response.text().unwrap_or_default();
            return Err(map_status(status.as_u16(), &text, retry));
        }
        let reader = BufReader::new(response);
        let mut out = parse_sse(reader, sink)?;
        out.latency_ms = started.elapsed().as_millis() as u64;
        Ok(out)
    }
}

pub fn request_body(request: &CompletionRequest, default_model: &str) -> serde_json::Value {
    let model = if request.model.is_empty() { default_model } else { &request.model };
    let mut body = serde_json::json!({
        "model": model,
        "stream": true,
        "stream_options": {"include_usage": true},
        "messages": request.messages.iter().map(message_json).collect::<Vec<_>>(),
    });
    if !request.tools.is_empty() {
        body["tools"] = serde_json::Value::Array(
            request
                .tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "type": "function",
                        "function": {
                            "name": t.name,
                            "description": t.description,
                            "parameters": t.parameters,
                        }
                    })
                })
                .collect(),
        );
    }
    if let Some(max) = request.max_tokens {
        body["max_tokens"] = serde_json::json!(max);
    }
    if let Some(temp) = request.temperature {
        body["temperature"] = serde_json::json!(temp);
    }
    body
}

fn message_json(message: &Message) -> serde_json::Value {
    let role = match message.role {
        Role::System => "system",
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::Tool => "tool",
    };
    let mut value = serde_json::json!({"role": role, "content": message.content});
    if !message.tool_calls.is_empty() {
        value["tool_calls"] = serde_json::Value::Array(
            message
                .tool_calls
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "id": c.id,
                        "type": "function",
                        "function": {"name": c.name, "arguments": c.arguments.to_string()}
                    })
                })
                .collect(),
        );
    }
    if let Some(id) = &message.tool_call_id {
        value["tool_call_id"] = serde_json::json!(id);
    }
    value
}

#[derive(Debug, Default)]
struct PartialCall {
    id: String,
    name: String,
    arguments: String,
}

/// Parse an OpenAI SSE stream. Emits text/thinking deltas as they arrive and one
/// `ToolCall` event per completed call, then usage and done.
pub fn parse_sse<R: BufRead>(reader: R, sink: &mut dyn EventSink) -> Result<ProviderResponse> {
    let mut text = String::new();
    let mut thinking = String::new();
    let mut calls: Vec<PartialCall> = Vec::new();
    let mut usage = Usage::default();
    let mut stop = StopReason::EndTurn;
    let mut saw_done = false;
    let mut saw_event = false;

    for line in reader.lines() {
        let line = line.map_err(|e| crate::errors::map_transport("stream", &e.to_string()))?;
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data.is_empty() {
            continue;
        }
        if data == "[DONE]" {
            saw_done = true;
            break;
        }
        let value: serde_json::Value = serde_json::from_str(data)
            .map_err(|e| malformed_body(&format!("{e}: {}", &data[..data.len().min(120)])))?;
        if let Some(err) = value.get("error") {
            let message = err.get("message").and_then(|m| m.as_str()).unwrap_or("provider error");
            return Err(map_status(400, message, None));
        }
        saw_event = true;
        if let Some(u) = value.get("usage").filter(|u| !u.is_null()) {
            usage = Usage {
                input_tokens: u.get("prompt_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
                output_tokens: u.get("completion_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
                cache_read_tokens: u
                    .get("prompt_tokens_details")
                    .and_then(|d| d.get("cached_tokens"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                cache_write_tokens: 0,
                cost_micros: 0,
            };
        }
        let Some(choice) = value.get("choices").and_then(|c| c.as_array()).and_then(|c| c.first()) else {
            continue;
        };
        if let Some(delta) = choice.get("delta") {
            if let Some(content) = delta.get("content").and_then(|v| v.as_str()) {
                if !content.is_empty() {
                    text.push_str(content);
                    if sink.event(ProviderEvent::TextDelta { text: content.to_string() }) == Control::Cancel {
                        return Ok(finish("openai", text, thinking, calls, usage, StopReason::Cancelled));
                    }
                }
            }
            if let Some(reasoning) = delta.get("reasoning_content").and_then(|v| v.as_str()) {
                if !reasoning.is_empty() {
                    thinking.push_str(reasoning);
                    if sink.event(ProviderEvent::ThinkingDelta { text: reasoning.to_string() }) == Control::Cancel {
                        return Ok(finish("openai", text, thinking, calls, usage, StopReason::Cancelled));
                    }
                }
            }
            if let Some(tool_calls) = delta.get("tool_calls").and_then(|v| v.as_array()) {
                for call in tool_calls {
                    let index = call.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                    while calls.len() <= index {
                        calls.push(PartialCall::default());
                    }
                    let entry = &mut calls[index];
                    if let Some(id) = call.get("id").and_then(|v| v.as_str()) {
                        if !id.is_empty() {
                            entry.id = id.to_string();
                        }
                    }
                    if let Some(function) = call.get("function") {
                        if let Some(name) = function.get("name").and_then(|v| v.as_str()) {
                            entry.name.push_str(name);
                        }
                        if let Some(args) = function.get("arguments").and_then(|v| v.as_str()) {
                            entry.arguments.push_str(args);
                        }
                    }
                }
            }
        }
        if let Some(reason) = choice.get("finish_reason").and_then(|v| v.as_str()) {
            stop = match reason {
                "tool_calls" | "function_call" => StopReason::ToolCalls,
                "length" => StopReason::MaxTokens,
                "content_filter" => StopReason::ContentFilter,
                _ => StopReason::EndTurn,
            };
        }
    }

    if !saw_event && !saw_done {
        return Err(map_transport("incomplete", "the stream ended without any event"));
    }
    if !calls.is_empty() {
        stop = StopReason::ToolCalls;
    }
    let response = finish("openai", text, thinking, calls, usage, stop);
    // Emit the completed tool calls now that their arguments are whole.
    for call in &response.tool_calls {
        sink.event(ProviderEvent::ToolCall { call: call.clone() });
    }
    sink.event(ProviderEvent::Usage { usage: response.usage });
    sink.event(ProviderEvent::Done { stop: response.stop });
    Ok(response)
}

fn finish(
    model: &str,
    text: String,
    thinking: String,
    calls: Vec<PartialCall>,
    usage: Usage,
    stop: StopReason,
) -> ProviderResponse {
    let mut out = Vec::new();
    for (i, call) in calls.into_iter().enumerate() {
        if call.name.is_empty() {
            continue;
        }
        let arguments = if call.arguments.trim().is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str(&call.arguments).unwrap_or_else(|_| serde_json::json!({"raw": call.arguments}))
        };
        out.push(ToolCall {
            id: if call.id.is_empty() { format!("call-{i}") } else { call.id },
            name: call.name,
            arguments,
        });
    }
    let stop = if out.is_empty() && stop == StopReason::ToolCalls { StopReason::EndTurn } else { stop };
    ProviderResponse {
        model: model.into(),
        text,
        thinking,
        tool_calls: out,
        usage,
        stop,
        latency_ms: 0,
    }
}

/// Validate that a key looks like the documented OpenAI style. Used to fail fast
/// with `zero.prv.auth` instead of making a call.
pub fn validate_key(key: &str) -> Result<()> {
    if key.starts_with("sk-") && key.len() > 20 {
        Ok(())
    } else {
        Err(ZeroError::new(ErrorCode::ProviderAuth, "the API key does not start with `sk-`"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::Collector;

    const STREAM: &str = include_str!("../tests/fixtures/openai_stream.sse");

    #[test]
    fn recorded_stream_parses_to_text_tools_and_usage() {
        let mut sink = Collector::default();
        let response = parse_sse(STREAM.as_bytes(), &mut sink).unwrap();
        assert_eq!(response.text, "Let me check. ");
        assert_eq!(response.thinking, "user wants a file");
        assert_eq!(response.tool_calls.len(), 1);
        assert_eq!(response.tool_calls[0].id, "call_abc");
        assert_eq!(response.tool_calls[0].name, "read_file");
        assert_eq!(response.tool_calls[0].arguments, serde_json::json!({"path":"a.txt"}));
        assert_eq!(response.usage.input_tokens, 21);
        assert_eq!(response.usage.output_tokens, 7);
        assert_eq!(response.usage.cache_read_tokens, 4);
        assert_eq!(response.stop, StopReason::ToolCalls);
        // Deltas arrived before the tool call.
        let first_delta = sink.events.iter().position(|e| matches!(e, ProviderEvent::TextDelta { .. }));
        let tool = sink.events.iter().position(|e| matches!(e, ProviderEvent::ToolCall { .. }));
        assert!(first_delta.unwrap() < tool.unwrap());
        assert!(matches!(sink.events.last(), Some(ProviderEvent::Done { .. })));
    }

    #[test]
    fn a_broken_stream_is_a_typed_error() {
        let err = parse_sse("data: {not json}\n\n".as_bytes(), &mut Collector::default()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProviderProtocol);
        let err = parse_sse("".as_bytes(), &mut Collector::default()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProviderStreamBroken);
    }

    #[test]
    fn cancellation_stops_the_stream() {
        let mut sink = Collector { cancel_after: Some(1), ..Collector::default() };
        let response = parse_sse(STREAM.as_bytes(), &mut sink).unwrap();
        assert_eq!(response.stop, StopReason::Cancelled);
        assert_eq!(sink.events.len(), 1);
    }

    #[test]
    fn request_body_carries_tools_and_stream_flag() {
        let mut request = CompletionRequest::new("gpt-test", vec![Message::user("hi")]);
        request.tools.push(crate::provider::ToolSchema {
            name: "echo".into(),
            description: "echo".into(),
            parameters: serde_json::json!({"type":"object"}),
        });
        let body = request_body(&request, "gpt-test");
        assert_eq!(body["stream"], true);
        assert_eq!(body["tools"][0]["function"]["name"], "echo");
        assert_eq!(body["messages"][0]["role"], "user");
    }

    #[test]
    fn key_validation_fails_fast() {
        assert!(validate_key("sk-abcdefghijklmnopqrstuvwx").is_ok());
        assert_eq!(validate_key("nope").unwrap_err().code(), ErrorCode::ProviderAuth);
    }
}
