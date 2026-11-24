//! Local adapter for Ollama and LM Studio (PRV-03, PRV-05).
//!
//! Both expose an Ollama-compatible `/api/chat` NDJSON stream. Tool support is
//! detected from `/api/show` capabilities instead of assumed.

use crate::errors::{map_reqwest, map_status, malformed_body};
use crate::provider::{
    Capabilities, CompletionRequest, Control, EventSink, Message, Provider, ProviderEvent,
    ProviderResponse, Role, StopReason, ToolCall, Usage,
};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader};
use std::time::Instant;
use zero_types::error::Result;

#[derive(Debug, Clone)]
pub struct OllamaConfig {
    pub base_url: String,
    pub model: String,
    pub timeout_ms: u64,
    pub tool_support: bool,
}

impl OllamaConfig {
    pub fn new(base_url: impl Into<String>, model: impl Into<String>) -> Self {
        Self { base_url: base_url.into(), model: model.into(), timeout_ms: 120_000, tool_support: false }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolSupport {
    pub supported: bool,
    pub reason: String,
}

/// Read the `/api/show` response and report whether the model advertises tools.
pub fn detect_tool_support(show: &serde_json::Value) -> ToolSupport {
    if let Some(caps) = show.get("capabilities").and_then(|c| c.as_array()) {
        let supported = caps.iter().any(|c| c.as_str() == Some("tools"));
        return ToolSupport {
            supported,
            reason: if supported {
                "capabilities lists `tools`".into()
            } else {
                format!(
                    "capabilities list does not include `tools`: {}",
                    caps.iter().filter_map(|c| c.as_str()).collect::<Vec<_>>().join(", ")
                )
            },
        };
    }
    ToolSupport {
        supported: false,
        reason: "the server did not report capabilities; tool support is not assumed".into(),
    }
}

pub struct OllamaProvider {
    config: OllamaConfig,
    client: reqwest::blocking::Client,
    calls: u32,
}

impl OllamaProvider {
    pub fn new(config: OllamaConfig) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|e| map_reqwest(&e))?;
        Ok(Self { config, client, calls: 0 })
    }

    pub fn calls(&self) -> u32 {
        self.calls
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.config.base_url.trim_end_matches('/'), path)
    }

    /// Query `/api/show` for capabilities. Offline against a fixture in tests.
    pub fn probe_tools(&mut self) -> Result<ToolSupport> {
        let response = self
            .client
            .post(self.endpoint("/api/show"))
            .json(&serde_json::json!({"model": self.config.model}))
            .send()
            .map_err(|e| map_reqwest(&e))?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().unwrap_or_default();
            return Err(map_status(status, &body, None));
        }
        let show: serde_json::Value = response.json().map_err(|e| malformed_body(&e.to_string()))?;
        Ok(detect_tool_support(&show))
    }
}

impl Provider for OllamaProvider {
    fn id(&self) -> &str {
        "ollama"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            streaming: true,
            tool_calls: self.config.tool_support,
            vision: false,
            context_limit: 32_768,
            output_limit: 4_096,
        }
    }

    fn complete(
        &mut self,
        request: &CompletionRequest,
        sink: &mut dyn EventSink,
    ) -> Result<ProviderResponse> {
        self.calls += 1;
        let started = Instant::now();
        if !request.tools.is_empty() && !self.config.tool_support {
            return Err(zero_types::error::ZeroError::new(
                zero_types::ErrorCode::ProviderNoTools,
                format!(
                    "model `{}` did not advertise tool support; disable tools or pick another model",
                    self.config.model
                ),
            ));
        }
        let body = request_body(request, &self.config.model, self.config.tool_support);
        let response = self
            .client
            .post(self.endpoint("/api/chat"))
            .json(&body)
            .send()
            .map_err(|e| map_reqwest(&e))?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let text = response.text().unwrap_or_default();
            return Err(map_status(status, &text, None));
        }
        let mut out = parse_ndjson(BufReader::new(response), sink)?;
        out.latency_ms = started.elapsed().as_millis() as u64;
        Ok(out)
    }
}

pub fn request_body(request: &CompletionRequest, model: &str, tools: bool) -> serde_json::Value {
    let messages: Vec<serde_json::Value> = request
        .messages
        .iter()
        .map(|m: &Message| {
            let role = match m.role {
                Role::System => "system",
                Role::User => "user",
                Role::Assistant => "assistant",
                Role::Tool => "tool",
            };
            let mut value = serde_json::json!({"role": role, "content": m.content});
            if !m.tool_calls.is_empty() {
                value["tool_calls"] = serde_json::Value::Array(
                    m.tool_calls
                        .iter()
                        .map(|c| {
                            serde_json::json!({
                                "function": {"name": c.name, "arguments": c.arguments}
                            })
                        })
                        .collect(),
                );
            }
            value
        })
        .collect();
    let mut body = serde_json::json!({
        "model": if request.model.is_empty() { model } else { &request.model },
        "messages": messages,
        "stream": true,
    });
    if tools && !request.tools.is_empty() {
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
    body
}

/// Parse the NDJSON chat stream. Content arrives per line; the final line carries
/// usage and `done: true`.
pub fn parse_ndjson<R: BufRead>(reader: R, sink: &mut dyn EventSink) -> Result<ProviderResponse> {
    let mut text = String::new();
    let mut thinking = String::new();
    let mut calls: Vec<ToolCall> = Vec::new();
    let mut usage = Usage::default();
    let mut stop = StopReason::EndTurn;
    let mut saw = false;

    for line in reader.lines() {
        let line = line.map_err(|e| crate::errors::map_transport("stream", &e.to_string()))?;
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(&line)
            .map_err(|e| malformed_body(&format!("{e}: {}", &line[..line.len().min(120)])))?;
        saw = true;
        if let Some(err) = value.get("error") {
            let message = err.as_str().unwrap_or("ollama error");
            return Err(crate::errors::map_status(400, message, None));
        }
        if let Some(message) = value.get("message") {
            if let Some(content) = message.get("content").and_then(|v| v.as_str()) {
                if !content.is_empty() {
                    text.push_str(content);
                    if sink.event(ProviderEvent::TextDelta { text: content.to_string() }) == Control::Cancel {
                        return Ok(response("ollama", text, thinking, calls, usage, StopReason::Cancelled));
                    }
                }
            }
            if let Some(reasoning) = message.get("thinking").and_then(|v| v.as_str()) {
                if !reasoning.is_empty() {
                    thinking.push_str(reasoning);
                    if sink.event(ProviderEvent::ThinkingDelta { text: reasoning.to_string() }) == Control::Cancel {
                        return Ok(response("ollama", text, thinking, calls, usage, StopReason::Cancelled));
                    }
                }
            }
            if let Some(tool_calls) = message.get("tool_calls").and_then(|v| v.as_array()) {
                for raw in tool_calls {
                    let function = raw.get("function").cloned().unwrap_or_default();
                    let name = function.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    if name.is_empty() {
                        continue;
                    }
                    let arguments = function
                        .get("arguments")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!({}));
                    let arguments = match arguments {
                        serde_json::Value::String(s) => serde_json::from_str(&s).unwrap_or(serde_json::json!({"raw": s})),
                        other => other,
                    };
                    let id = raw
                        .get("id")
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("ollama-call-{}", calls.len()));
                    let call = ToolCall { id, name, arguments };
                    calls.push(call.clone());
                    if sink.event(ProviderEvent::ToolCall { call }) == Control::Cancel {
                        return Ok(response("ollama", text, thinking, calls, usage, StopReason::Cancelled));
                    }
                }
            }
        }
        if value.get("done").and_then(|v| v.as_bool()) == Some(true) {
            usage = Usage {
                input_tokens: value.get("prompt_eval_count").and_then(|v| v.as_u64()).unwrap_or(0),
                output_tokens: value.get("eval_count").and_then(|v| v.as_u64()).unwrap_or(0),
                ..Usage::default()
            };
            stop = match value.get("done_reason").and_then(|v| v.as_str()) {
                Some("length") => StopReason::MaxTokens,
                _ if !calls.is_empty() => StopReason::ToolCalls,
                _ => StopReason::EndTurn,
            };
            break;
        }
    }

    if !saw {
        return Err(crate::errors::map_transport("incomplete", "the stream ended without any line"));
    }
    let out = response("ollama", text, thinking, calls, usage, stop);
    sink.event(ProviderEvent::Usage { usage: out.usage });
    sink.event(ProviderEvent::Done { stop: out.stop });
    Ok(out)
}

fn response(
    model: &str,
    text: String,
    thinking: String,
    tool_calls: Vec<ToolCall>,
    usage: Usage,
    stop: StopReason,
) -> ProviderResponse {
    ProviderResponse { model: model.into(), text, thinking, tool_calls, usage, stop, latency_ms: 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::Collector;

    const STREAM: &str = include_str!("../tests/fixtures/ollama_stream.ndjson");
    const SHOW: &str = include_str!("../tests/fixtures/ollama_show.json");
    const SHOW_NO_TOOLS: &str = include_str!("../tests/fixtures/ollama_show_notools.json");

    #[test]
    fn offline_stream_parses_without_a_network() {
        let mut sink = Collector::default();
        let response = parse_ndjson(STREAM.as_bytes(), &mut sink).unwrap();
        assert_eq!(response.text, "Reading a.txt. ");
        assert_eq!(response.thinking, "plan");
        assert_eq!(response.tool_calls.len(), 1);
        assert_eq!(response.tool_calls[0].name, "read_file");
        assert_eq!(response.tool_calls[0].arguments, serde_json::json!({"path":"a.txt"}));
        assert_eq!(response.usage.input_tokens, 12);
        assert_eq!(response.usage.output_tokens, 5);
        assert_eq!(response.stop, StopReason::ToolCalls);
        assert!(matches!(sink.events.last(), Some(ProviderEvent::Done { .. })));
    }

    #[test]
    fn tool_support_is_detected_not_assumed() {
        let show: serde_json::Value = serde_json::from_str(SHOW).unwrap();
        let support = detect_tool_support(&show);
        assert!(support.supported, "{}", support.reason);

        let show: serde_json::Value = serde_json::from_str(SHOW_NO_TOOLS).unwrap();
        let support = detect_tool_support(&show);
        assert!(!support.supported);
        assert!(support.reason.contains("does not include `tools`"));

        let support = detect_tool_support(&serde_json::json!({}));
        assert!(!support.supported);
        assert!(support.reason.contains("not assumed"));
    }

    #[test]
    fn missing_tool_support_is_a_typed_error() {
        // A provider configured without tool support refuses a tool-bearing call
        // before any network attempt.
        let config = OllamaConfig::new("http://127.0.0.1:9", "llama");
        let mut provider = OllamaProvider::new(config).unwrap();
        let mut request = CompletionRequest::new("llama", vec![Message::user("hi")]);
        request.tools.push(crate::provider::ToolSchema {
            name: "echo".into(),
            description: "e".into(),
            parameters: serde_json::json!({"type":"object"}),
        });
        let err = provider.complete(&request, &mut Collector::default()).unwrap_err();
        assert_eq!(err.code(), zero_types::ErrorCode::ProviderNoTools);
        assert_eq!(provider.calls(), 1);
    }
}
