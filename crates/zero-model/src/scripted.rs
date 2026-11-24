//! Scripted provider for deterministic tests and the conformance suite.
//! It is also the stub used by the agent loop fixtures.

use crate::provider::{
    Capabilities, CompletionRequest, Control, EventSink, Provider, ProviderEvent, ProviderResponse,
    StopReason, Usage,
};
use std::collections::VecDeque;
use zero_types::error::{Result, ZeroError};

#[derive(Debug, Clone)]
pub struct ScriptTurn {
    pub text: String,
    pub thinking: String,
    pub tool_calls: Vec<crate::provider::ToolCall>,
    pub usage: Usage,
    pub stop: StopReason,
    /// When set, the call fails before emitting anything.
    pub fail: Option<ZeroError>,
}

impl ScriptTurn {
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            thinking: String::new(),
            tool_calls: Vec::new(),
            usage: Usage::default(),
            stop: StopReason::EndTurn,
            fail: None,
        }
    }

    pub fn tool_call(call: crate::provider::ToolCall) -> Self {
        Self {
            text: String::new(),
            thinking: String::new(),
            tool_calls: vec![call],
            usage: Usage::default(),
            stop: StopReason::ToolCalls,
            fail: None,
        }
    }

    pub fn failing(error: ZeroError) -> Self {
        let mut t = Self::text("");
        t.fail = Some(error);
        t
    }

    pub fn with_usage(mut self, usage: Usage) -> Self {
        self.usage = usage;
        self
    }

    pub fn with_thinking(mut self, thinking: impl Into<String>) -> Self {
        self.thinking = thinking.into();
        self
    }
}

/// A provider that replays a fixed script. Every call is recorded so tests can
/// assert turn accounting.
#[derive(Debug, Clone, Default)]
pub struct ScriptedProvider {
    script: VecDeque<ScriptTurn>,
    model: String,
    calls: Vec<CompletionRequest>,
    caps: Capabilities,
    /// Emit each delta in chunks of this size; 0 means one delta per field.
    chunk: usize,
}

impl ScriptedProvider {
    pub fn new(turns: Vec<ScriptTurn>) -> Self {
        Self {
            script: turns.into(),
            model: "scripted-1".into(),
            calls: Vec::new(),
            caps: Capabilities::default(),
            chunk: 0,
        }
    }

    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    pub fn without_tools(mut self) -> Self {
        self.caps.tool_calls = false;
        self
    }

    pub fn with_chunk(mut self, chunk: usize) -> Self {
        self.chunk = chunk;
        self
    }

    pub fn calls(&self) -> &[CompletionRequest] {
        &self.calls
    }

    pub fn remaining(&self) -> usize {
        self.script.len()
    }

    fn emit_text(&self, text: &str, sink: &mut dyn EventSink, thinking: bool) -> Control {
        if text.is_empty() {
            return Control::Continue;
        }
        if self.chunk == 0 {
            let event = if thinking {
                ProviderEvent::ThinkingDelta { text: text.to_string() }
            } else {
                ProviderEvent::TextDelta { text: text.to_string() }
            };
            return sink.event(event);
        }
        for piece in text.as_bytes().chunks(self.chunk) {
            let piece = String::from_utf8_lossy(piece).to_string();
            let event = if thinking {
                ProviderEvent::ThinkingDelta { text: piece }
            } else {
                ProviderEvent::TextDelta { text: piece }
            };
            if sink.event(event) == Control::Cancel {
                return Control::Cancel;
            }
        }
        Control::Continue
    }
}

impl Provider for ScriptedProvider {
    fn id(&self) -> &str {
        "scripted"
    }

    fn capabilities(&self) -> Capabilities {
        self.caps.clone()
    }

    fn complete(
        &mut self,
        request: &CompletionRequest,
        sink: &mut dyn EventSink,
    ) -> Result<ProviderResponse> {
        self.calls.push(request.clone());
        let turn = self.script.pop_front().unwrap_or_else(|| ScriptTurn::text("script exhausted"));
        let started = std::time::Instant::now();
        if let Some(err) = turn.fail.clone() {
            return Err(err);
        }
        let mut text = String::new();
        let mut thinking = String::new();
        if self.emit_text(&turn.thinking, sink, true) == Control::Cancel {
            return Ok(ProviderResponse {
                model: self.model.clone(),
                text,
                thinking,
                tool_calls: Vec::new(),
                usage: turn.usage,
                stop: StopReason::Cancelled,
                latency_ms: started.elapsed().as_millis() as u64,
            });
        }
        if self.emit_text(&turn.text, sink, false) == Control::Cancel {
            return Ok(ProviderResponse {
                model: self.model.clone(),
                text: turn.text,
                thinking,
                tool_calls: Vec::new(),
                usage: turn.usage,
                stop: StopReason::Cancelled,
                latency_ms: started.elapsed().as_millis() as u64,
            });
        }
        text.push_str(&turn.text);
        thinking.push_str(&turn.thinking);
        for call in &turn.tool_calls {
            if sink.event(ProviderEvent::ToolCall { call: call.clone() }) == Control::Cancel {
                return Ok(ProviderResponse {
                    model: self.model.clone(),
                    text,
                    thinking,
                    tool_calls: Vec::new(),
                    usage: turn.usage,
                    stop: StopReason::Cancelled,
                    latency_ms: started.elapsed().as_millis() as u64,
                });
            }
        }
        sink.event(ProviderEvent::Usage { usage: turn.usage });
        sink.event(ProviderEvent::Done { stop: turn.stop });
        Ok(ProviderResponse {
            model: self.model.clone(),
            text,
            thinking,
            tool_calls: turn.tool_calls,
            usage: turn.usage,
            stop: turn.stop,
            latency_ms: started.elapsed().as_millis() as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{Collector, Message};

    #[test]
    fn streams_deltas_and_records_calls() {
        let mut provider = ScriptedProvider::new(vec![ScriptTurn::text("hello world")]).with_chunk(4);
        let mut sink = Collector::default();
        let response = provider
            .complete(&CompletionRequest::new("m", vec![Message::user("hi")]), &mut sink)
            .unwrap();
        assert_eq!(response.text, "hello world");
        assert_eq!(response.stop, StopReason::EndTurn);
        let text: String = sink
            .events
            .iter()
            .filter_map(|e| match e {
                ProviderEvent::TextDelta { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(text, "hello world");
        assert!(matches!(sink.events.last(), Some(ProviderEvent::Done { .. })));
        assert_eq!(provider.calls().len(), 1);
    }
}
