//! PRV-02 and PRV-03 evidence without a network: a local HTTP server replays
//! recorded responses, and the real adapters route a turn through them.
//!
//! The live variants are in `live.rs` and are behind environment flags.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread::JoinHandle;
use zero_model::{
    Collector, CompletionRequest, Message, OpenAiConfig, OpenAiProvider, OllamaConfig,
    OllamaProvider, Provider, StopReason, Usage,
};

/// Serve exactly one request with a fixed response. Returns the base URL and the
/// server thread, which reads the request (headers and Content-Length body) first.
fn serve_once(status: &str, content_type: &str, body: Vec<u8>) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().unwrap();
    let status = status.to_string();
    let content_type = content_type.to_string();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut data = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => data.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
            if let Some(head_end) = find(&data, b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&data[..head_end]).to_ascii_lowercase();
                let length = headers
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if data.len() >= head_end + 4 + length {
                    break;
                }
            }
        }
        let head = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(&body);
        let _ = stream.flush();
        // Give the client time to read before the socket closes.
        std::thread::sleep(std::time::Duration::from_millis(30));
    });
    (format!("http://{addr}"), handle)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

const OPENAI_SSE: &str = include_str!("fixtures/openai_stream.sse");
const OLLAMA_NDJSON: &str = include_str!("fixtures/ollama_stream.ndjson");

#[test]
fn hosted_adapter_routes_a_turn_from_a_recorded_response() {
    let (base_url, server) = serve_once("200 OK", "text/event-stream", OPENAI_SSE.as_bytes().to_vec());
    let config = OpenAiConfig::new(base_url, "sk-test-abcdefghijklmnopqrstuvwx", "gpt-test");
    let mut provider = OpenAiProvider::new(config).unwrap();
    let mut sink = Collector::default();
    let response = provider
        .complete(&CompletionRequest::new("gpt-test", vec![Message::user("read a.txt")]), &mut sink)
        .unwrap();
    server.join().unwrap();
    assert_eq!(provider.calls(), 1);
    assert!(response.text.contains("Let me check."));
    assert_eq!(response.tool_calls.len(), 1);
    assert_eq!(response.tool_calls[0].name, "read_file");
    assert_eq!(response.usage, Usage { input_tokens: 21, output_tokens: 7, cache_read_tokens: 4, cache_write_tokens: 0, cost_micros: 0 });
    assert_eq!(response.stop, StopReason::ToolCalls);
}

#[test]
fn hosted_auth_failure_maps_to_the_documented_code() {
    let body = br#"{"error":{"message":"Incorrect API key provided"}}"#.to_vec();
    let (base_url, server) = serve_once("401 Unauthorized", "application/json", body);
    let config = OpenAiConfig::new(base_url, "sk-test-abcdefghijklmnopqrstuvwx", "gpt-test");
    let mut provider = OpenAiProvider::new(config).unwrap();
    let err = provider
        .complete(&CompletionRequest::new("gpt-test", vec![Message::user("hi")]), &mut Collector::default())
        .unwrap_err();
    server.join().unwrap();
    assert_eq!(err.code(), zero_types::ErrorCode::ProviderAuth);
    assert!(!err.remediation().is_empty());
}

#[test]
fn local_adapter_runs_an_offline_session_against_a_fixture() {
    let (base_url, server) = serve_once("200 OK", "application/x-ndjson", OLLAMA_NDJSON.as_bytes().to_vec());
    let mut config = OllamaConfig::new(base_url, "llama3.1");
    config.tool_support = true;
    let mut provider = OllamaProvider::new(config).unwrap();
    let mut request = CompletionRequest::new("llama3.1", vec![Message::user("read a.txt")]);
    request.tools.push(zero_model::ToolSchema {
        name: "read_file".into(),
        description: "read".into(),
        parameters: serde_json::json!({"type":"object"}),
    });
    let mut sink = Collector::default();
    let response = provider.complete(&request, &mut sink).unwrap();
    server.join().unwrap();
    assert_eq!(response.text, "Reading a.txt. ");
    assert_eq!(response.tool_calls.len(), 1);
    assert_eq!(response.usage.input_tokens, 12);
    assert_eq!(response.stop, StopReason::ToolCalls);
}

#[test]
fn local_adapter_detects_tool_support_over_http() {
    let show = br#"{"capabilities":["completion","tools"]}"#.to_vec();
    let (base_url, server) = serve_once("200 OK", "application/json", show);
    let mut provider = OllamaProvider::new(OllamaConfig::new(base_url, "llama3.1")).unwrap();
    let support = provider.probe_tools().unwrap();
    server.join().unwrap();
    assert!(support.supported, "{}", support.reason);
}
