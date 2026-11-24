//! Provider conformance suite (PRV-01): every adapter must stream, shape tool
//! calls, normalize usage, classify retries, and honour cancellation.
//!
//! `ScriptedProvider` passes it; adapters are checked by their fixture tests and
//! by the same cases through their parsers.

use crate::provider::{
    classify_code, Collector, CompletionRequest, Control, EventSink, Message, Provider,
    ProviderEvent, StopReason, ToolCall, ToolSchema, Usage,
};
use zero_types::error::{ErrorCode, ZeroError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseResult {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConformanceReport {
    pub cases: Vec<CaseResult>,
}

impl ConformanceReport {
    pub fn passed(&self) -> bool {
        !self.cases.is_empty() && self.cases.iter().all(|c| c.passed)
    }

    pub fn failures(&self) -> Vec<&CaseResult> {
        self.cases.iter().filter(|c| !c.passed).collect()
    }

    fn push(&mut self, name: &'static str, passed: bool, detail: impl Into<String>) {
        self.cases.push(CaseResult { name, passed, detail: detail.into() });
    }
}

fn tool(name: &str, args: serde_json::Value) -> ToolCall {
    ToolCall { id: "call-1".into(), name: name.into(), arguments: args }
}

/// Run every case against one provider, in order. The provider's script must
/// supply at least four turns (text, tool, usage, cancellation).
pub fn run(provider: &mut dyn Provider) -> ConformanceReport {
    let mut report = ConformanceReport::default();
    let request = CompletionRequest::new("conformance-model", vec![Message::user("hello")]);

    // 1. Text streams in order and ends with Done.
    {
        let mut sink = Collector::default();
        match provider.complete(&request, &mut sink) {
            Ok(response) => {
                let streamed: String = sink
                    .events
                    .iter()
                    .filter_map(|e| match e {
                        ProviderEvent::TextDelta { text } => Some(text.as_str()),
                        _ => None,
                    })
                    .collect();
                let done_last = matches!(sink.events.last(), Some(ProviderEvent::Done { .. }));
                let ok = !response.text.is_empty()
                    && streamed == response.text
                    && done_last
                    && response.stop == StopReason::EndTurn;
                report.push(
                    "stream_text",
                    ok,
                    format!("streamed={streamed:?} text={:?} done_last={done_last}", response.text),
                );
            }
            Err(e) => report.push("stream_text", false, e.to_string()),
        }
    }

    // 2. Tool calls carry stable ids, names, and JSON arguments.
    {
        let mut sink = Collector::default();
        match provider.complete(&request, &mut sink) {
            Ok(response) => {
                let emitted: Vec<&ToolCall> = sink
                    .events
                    .iter()
                    .filter_map(|e| match e {
                        ProviderEvent::ToolCall { call } => Some(call),
                        _ => None,
                    })
                    .collect();
                let ok = !response.tool_calls.is_empty()
                    && response.stop == StopReason::ToolCalls
                    && response.tool_calls.iter().all(|c| !c.id.is_empty() && !c.name.is_empty() && c.arguments.is_object())
                    && emitted.len() == response.tool_calls.len();
                report.push(
                    "tool_call_shape",
                    ok,
                    format!("calls={} emitted={}", response.tool_calls.len(), emitted.len()),
                );
            }
            Err(e) => report.push("tool_call_shape", false, e.to_string()),
        }
    }

    // 3. Usage is normalized and emitted once.
    {
        let mut sink = Collector::default();
        match provider.complete(&request, &mut sink) {
            Ok(response) => {
                let usage_events: Vec<&Usage> = sink
                    .events
                    .iter()
                    .filter_map(|e| match e {
                        ProviderEvent::Usage { usage } => Some(usage),
                        _ => None,
                    })
                    .collect();
                let ok = usage_events.len() == 1
                    && *usage_events[0] == response.usage
                    && response.usage.total_tokens() == response.usage.input_tokens + response.usage.output_tokens;
                report.push("usage_normalized", ok, format!("usage={:?}", response.usage));
            }
            Err(e) => report.push("usage_normalized", false, e.to_string()),
        }
    }

    // 4. Retry classification.
    {
        let cases = [
            (ErrorCode::ProviderRateLimited, crate::provider::RetryClass::Safe),
            (ErrorCode::ProviderTimeout, crate::provider::RetryClass::Safe),
            (ErrorCode::ProviderStreamBroken, crate::provider::RetryClass::Unsafe),
            (ErrorCode::ProviderAuth, crate::provider::RetryClass::Never),
        ];
        let mut failures = Vec::new();
        for (code, expected) in cases {
            let got = provider.classify(&ZeroError::new(code, "x"));
            if got != expected {
                failures.push(format!("{} -> {:?}, expected {:?}", code.as_str(), got, expected));
            }
            // The shared table must agree with the adapter.
            if classify_code(code) != got {
                failures.push(format!("adapter disagrees with the shared table for {}", code.as_str()));
            }
        }
        report.push("retry_classification", failures.is_empty(), failures.join("; "));
    }

    // 5. Cancellation stops the stream.
    {
        let mut sink = Collector { cancel_after: Some(1), ..Collector::default() };
        // Ensure a fresh turn is available.
        match provider.complete(&request, &mut sink) {
            Ok(response) => {
                let ok = response.stop == StopReason::Cancelled && sink.events.len() == 1;
                report.push(
                    "cancellation",
                    ok,
                    format!("stop={:?} events={}", response.stop, sink.events.len()),
                );
            }
            Err(e) => report.push("cancellation", false, e.to_string()),
        }
    }

    report
}

/// Convenience: the reference script every provider conformance run expects.
pub fn conformance_script() -> Vec<crate::scripted::ScriptTurn> {
    use crate::scripted::ScriptTurn;
    vec![
        ScriptTurn::text("conformance text").with_usage(Usage {
            input_tokens: 3,
            output_tokens: 2,
            ..Usage::default()
        }),
        ScriptTurn {
            text: String::new(),
            thinking: String::new(),
            tool_calls: vec![tool("echo", serde_json::json!({"text":"hi"}))],
            usage: Usage::default(),
            stop: StopReason::ToolCalls,
            fail: None,
        },
        ScriptTurn::text("usage turn").with_usage(Usage {
            input_tokens: 11,
            output_tokens: 7,
            cache_read_tokens: 2,
            cache_write_tokens: 1,
            cost_micros: 9,
        }),
        ScriptTurn::text("cancel me"),
    ]
}

/// A sink that always cancels immediately; useful for adapters.
pub struct CancelSink;
impl EventSink for CancelSink {
    fn event(&mut self, _event: ProviderEvent) -> Control {
        Control::Cancel
    }
}

#[allow(dead_code)]
fn unused_tool_schema() -> ToolSchema {
    ToolSchema { name: "x".into(), description: "x".into(), parameters: serde_json::json!({}) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scripted::ScriptedProvider;

    #[test]
    fn scripted_provider_passes_the_conformance_suite() {
        let mut provider = ScriptedProvider::new(conformance_script()).with_chunk(3);
        let report = run(&mut provider);
        assert!(report.passed(), "failures: {:?}", report.failures());
        assert_eq!(report.cases.len(), 5);
        assert_eq!(
            report.cases.iter().map(|c| c.name).collect::<Vec<_>>(),
            vec!["stream_text", "tool_call_shape", "usage_normalized", "retry_classification", "cancellation"]
        );
    }

    #[test]
    fn a_provider_without_tool_support_fails_the_tool_case() {
        // A provider that reports no tools and returns none fails case 2, which
        // proves the suite can reject an adapter rather than always passing.
        let mut provider = ScriptedProvider::new(vec![
            crate::scripted::ScriptTurn::text("only text"),
            crate::scripted::ScriptTurn::text("no tools"),
            crate::scripted::ScriptTurn::text("usage"),
            crate::scripted::ScriptTurn::text("cancel"),
        ]);
        let report = run(&mut provider);
        assert!(!report.passed());
        assert!(report.failures().iter().any(|c| c.name == "tool_call_shape"));
    }
}
