//! Provider trait, streaming events, retry classification, and usage
//! normalization (PRV-01, PRV-03, PRV-11).
//!
//! The trait is synchronous and callback-driven: adapters push events into an
//! [`EventSink`], which can cancel mid-stream. This keeps deterministic tests
//! simple and makes cancellation a first-class part of the contract.

use serde::{Deserialize, Serialize};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: String,
    #[serde(default)]
    pub tool_calls: Vec<ToolCall>,
    #[serde(default)]
    pub tool_call_id: Option<String>,
}

impl Message {
    pub fn system(text: impl Into<String>) -> Self {
        Self { role: Role::System, content: text.into(), tool_calls: Vec::new(), tool_call_id: None }
    }

    pub fn user(text: impl Into<String>) -> Self {
        Self { role: Role::User, content: text.into(), tool_calls: Vec::new(), tool_call_id: None }
    }

    pub fn assistant(text: impl Into<String>) -> Self {
        Self { role: Role::Assistant, content: text.into(), tool_calls: Vec::new(), tool_call_id: None }
    }

    pub fn tool_result(call_id: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            role: Role::Tool,
            content: text.into(),
            tool_calls: Vec::new(),
            tool_call_id: Some(call_id.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolSchema {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub cost_micros: u64,
}

impl Usage {
    pub fn total_tokens(&self) -> u64 {
        self.input_tokens + self.output_tokens
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompletionRequest {
    pub model: String,
    pub messages: Vec<Message>,
    #[serde(default)]
    pub tools: Vec<ToolSchema>,
    #[serde(default)]
    pub max_tokens: Option<u32>,
    #[serde(default)]
    pub temperature: Option<f32>,
}

impl CompletionRequest {
    pub fn new(model: impl Into<String>, messages: Vec<Message>) -> Self {
        Self { model: model.into(), messages, tools: Vec::new(), max_tokens: None, temperature: None }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    EndTurn,
    ToolCalls,
    MaxTokens,
    Cancelled,
    ContentFilter,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProviderEvent {
    TextDelta { text: String },
    ThinkingDelta { text: String },
    ToolCall { call: ToolCall },
    Usage { usage: Usage },
    Done { stop: StopReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    Continue,
    Cancel,
}

pub trait EventSink {
    fn event(&mut self, event: ProviderEvent) -> Control;
}

/// Collects events; used by tests and the line-mode client.
#[derive(Debug, Default)]
pub struct Collector {
    pub events: Vec<ProviderEvent>,
    /// Cancel after this many events, if set.
    pub cancel_after: Option<usize>,
}

impl EventSink for Collector {
    fn event(&mut self, event: ProviderEvent) -> Control {
        self.events.push(event);
        if let Some(n) = self.cancel_after {
            if self.events.len() >= n {
                return Control::Cancel;
            }
        }
        Control::Continue
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProviderResponse {
    pub model: String,
    pub text: String,
    pub thinking: String,
    pub tool_calls: Vec<ToolCall>,
    pub usage: Usage,
    pub stop: StopReason,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub streaming: bool,
    pub tool_calls: bool,
    pub vision: bool,
    pub context_limit: u64,
    pub output_limit: u64,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self { streaming: true, tool_calls: true, vision: false, context_limit: 128_000, output_limit: 8_192 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryClass {
    /// Idempotent to retry with backoff.
    Safe,
    /// Retrying could duplicate a side effect.
    Unsafe,
    /// Never retry.
    Never,
}

pub trait Provider {
    fn id(&self) -> &str;

    fn capabilities(&self) -> Capabilities;

    fn complete(
        &mut self,
        request: &CompletionRequest,
        sink: &mut dyn EventSink,
    ) -> Result<ProviderResponse>;

    /// Classify an error for retry purposes. Codes are stable, so this default
    /// implementation is shared by every adapter.
    fn classify(&self, error: &ZeroError) -> RetryClass {
        classify_code(error.code())
    }
}

pub fn classify_code(code: ErrorCode) -> RetryClass {
    match code {
        ErrorCode::ProviderRateLimited
        | ErrorCode::ProviderOverloaded
        | ErrorCode::ProviderTimeout
        | ErrorCode::ProviderUnavailable
        | ErrorCode::Offline
        | ErrorCode::Timeout => RetryClass::Safe,
        ErrorCode::ProviderStreamBroken => RetryClass::Unsafe,
        _ => RetryClass::Never,
    }
}

/// Configuration of retryable failures, used by the scheduler later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self { max_attempts: 3, base_delay_ms: 250, max_delay_ms: 5_000 }
    }
}

impl RetryPolicy {
    /// Exponential backoff with a deterministic jitter derived from the attempt
    /// number (no OS entropy, so simulations reproduce).
    pub fn delay_ms(&self, attempt: u32) -> u64 {
        let exp = self.base_delay_ms.saturating_mul(1u64 << attempt.min(10));
        let capped = exp.min(self.max_delay_ms);
        capped + (attempt as u64 * 17) % 50
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_classification_is_stable_per_code() {
        assert_eq!(classify_code(ErrorCode::ProviderRateLimited), RetryClass::Safe);
        assert_eq!(classify_code(ErrorCode::ProviderTimeout), RetryClass::Safe);
        assert_eq!(classify_code(ErrorCode::ProviderStreamBroken), RetryClass::Unsafe);
        assert_eq!(classify_code(ErrorCode::ProviderAuth), RetryClass::Never);
        assert_eq!(classify_code(ErrorCode::ProviderBadRequest), RetryClass::Never);
        assert_eq!(classify_code(ErrorCode::ProviderContextLength), RetryClass::Never);
    }

    #[test]
    fn usage_is_normalized_to_one_shape() {
        let usage = Usage { input_tokens: 10, output_tokens: 5, cache_read_tokens: 2, cache_write_tokens: 1, cost_micros: 42 };
        assert_eq!(usage.total_tokens(), 15);
    }

    #[test]
    fn backoff_is_deterministic_and_capped() {
        let p = RetryPolicy::default();
        assert_eq!(p.delay_ms(0), 250);
        assert!(p.delay_ms(1) < p.delay_ms(2));
        assert_eq!(p.delay_ms(20), 5_000 + (20 * 17) % 50);
    }
}
