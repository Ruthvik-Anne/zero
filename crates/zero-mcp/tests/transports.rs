//! Transport behaviour (T-MCP-02): stdio framing, environment scrubbing,
//! timeouts, Streamable HTTP JSON/SSE responses, and the legacy switch.
//!
//! No external host is contacted. The stdio tests spawn this same test binary as
//! a child and the HTTP tests use a loopback `TcpListener`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use zero_mcp::{
    connect, Client, Headers, HttpConfig, HttpTransport, McpRevision, StdioConfig, StdioTransport,
    Transport, TransportConfig, TransportMode, HEADER_SESSION_ID,
};
use zero_types::error::ErrorCode;

const HELPER_ENV: &str = "ZERO_MCP_STDIO_HELPER";
const HELPER_TEST: &str = "stdio_helper_process";

fn env_present(name: &str) -> bool {
    std::env::var_os(name).is_some()
}

/// Child-side of the stdio tests. It is a no-op unless the parent set
/// `ZERO_MCP_STDIO_HELPER=1`, so the normal test run skips it.
#[test]
fn stdio_helper_process() {
    if std::env::var_os(HELPER_ENV).as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }
    let mut stdout = std::io::stdout();
    // libtest prints `test <name> ... ` without a newline before the body runs.
    // Terminate that prefix so it cannot merge with the first JSON-RPC line.
    let _ = writeln!(stdout);
    let _ = stdout.flush();

    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let Ok(request) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let Some(id) = request.get("id").cloned() else {
            continue;
        };
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let reply = match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2026-07-28",
                    "capabilities": {},
                    "serverInfo": {"name": "stdio-helper", "version": "0.1.0"}
                }
            }),
            "tools/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"resultType": "complete", "tools": []}
            }),
            "tools/call" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"content": [], "isError": false}
            }),
            "env/probe" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "openai_key_present": env_present("OPENAI_API_KEY"),
                    "test_secret_present": env_present("ZERO_MCP_TEST_SECRET"),
                    "ssh_auth_sock_present": env_present("SSH_AUTH_SOCK")
                }
            }),
            "noisy" => {
                // A notification and a plain log line that precede the answer.
                let _ = writeln!(
                    stdout,
                    "{}",
                    json!({
                        "jsonrpc": "2.0",
                        "method": "notifications/message",
                        "params": {"level": "info", "data": "helper starting"}
                    })
                );
                let _ = writeln!(
                    stdout,
                    "2026-01-01T00:00:00Z INFO stdio helper handles noisy"
                );
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {"noise_skipped": true}
                })
            }
            "hang" => continue,
            other => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": format!("method not found: {other}")}
            }),
        };
        let _ = writeln!(stdout, "{reply}");
        let _ = stdout.flush();
    }
}

fn helper_config() -> StdioConfig {
    let exe = std::env::current_exe().expect("current test executable");
    StdioConfig::new(exe)
        .args(vec![
            "--exact".to_string(),
            HELPER_TEST.to_string(),
            "--nocapture".to_string(),
            "--test-threads=1".to_string(),
        ])
        .env(HELPER_ENV, "1")
        .with_timeout(Duration::from_secs(20))
}

#[test]
fn stdio_launches_scrubbed_ignores_noise_and_reports_stderr() {
    std::env::set_var("OPENAI_API_KEY", "sk-stdio-test-should-not-leak");
    let transport = StdioTransport::spawn(
        helper_config()
            .env("ZERO_MCP_TEST_SECRET", "s3cret-value")
            .env("SSH_AUTH_SOCK", "/tmp/zero-stdio-test.sock"),
    )
    .expect("spawn stdio helper");

    {
        let mut client = Client::new("stdio-helper", &transport);
        let initialized = client.initialize().expect("initialize over stdio");
        assert_eq!(initialized.protocol_version, McpRevision::V2026_07_28);
        assert_eq!(
            initialized.server_info.expect("server info").name,
            "stdio-helper"
        );
    }

    let probe = transport
        .exchange(&json!({"jsonrpc": "2.0", "id": 42, "method": "env/probe"}))
        .expect("env probe");
    assert_eq!(
        probe["result"]["openai_key_present"], false,
        "an inherited `OPENAI_API_KEY` must not reach the child"
    );
    assert_eq!(
        probe["result"]["test_secret_present"], false,
        "an explicitly configured secret variable must be scrubbed too"
    );
    assert_eq!(
        probe["result"]["ssh_auth_sock_present"], true,
        "the agent socket is exempt from the scrub policy"
    );

    let noisy = transport
        .exchange(&json!({"jsonrpc": "2.0", "id": 43, "method": "noisy"}))
        .expect("noise before the response must be skipped");
    assert_eq!(noisy["result"]["noise_skipped"], true);

    assert!(transport.is_running());
    std::env::remove_var("OPENAI_API_KEY");
}

#[test]
fn stdio_timeout_kills_the_child_and_later_calls_fail_cleanly() {
    let transport = StdioTransport::spawn(helper_config().with_timeout(Duration::from_millis(400)))
        .expect("spawn stdio helper");
    let error = transport
        .exchange(&json!({"jsonrpc": "2.0", "id": 1, "method": "hang"}))
        .expect_err("the helper never answers `hang`");
    assert_eq!(error.code(), ErrorCode::Timeout);
    assert!(
        !transport.is_running(),
        "a timeout must kill and reap the child"
    );

    let after = transport
        .exchange(&json!({"jsonrpc": "2.0", "id": 2, "method": "initialize"}))
        .expect_err("a killed child cannot answer");
    assert_eq!(after.code(), ErrorCode::Unavailable);
}

#[test]
fn stdio_shutdown_closes_the_child_and_drop_is_safe() {
    let transport = StdioTransport::spawn(helper_config()).expect("spawn stdio helper");
    transport
        .exchange(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}))
        .expect("initialize");
    assert!(transport.is_running());
    assert_ne!(transport.pid(), 0);
    transport.shutdown();
    assert!(!transport.is_running());
    drop(transport);
}

#[derive(Clone)]
struct TestResponse {
    status: &'static str,
    content_type: &'static str,
    headers: Vec<(String, String)>,
    body: String,
}

impl TestResponse {
    fn json(body: impl Into<String>) -> Self {
        Self {
            status: "200 OK",
            content_type: "application/json",
            headers: Vec::new(),
            body: body.into(),
        }
    }

    fn sse(body: impl Into<String>) -> Self {
        Self {
            status: "200 OK",
            content_type: "text/event-stream",
            headers: Vec::new(),
            body: body.into(),
        }
    }

    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

struct RecordedRequest {
    request_line: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl RecordedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str())
    }
}

struct TestServer {
    url: String,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    handle: Option<JoinHandle<()>>,
}

impl TestServer {
    fn start(responses: Vec<TestResponse>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let address = listener.local_addr().expect("local address");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&requests);
        let handle = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut served = 0usize;
            while served < responses.len() && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        serve_one(&mut stream, &responses[served], &sink);
                        served += 1;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            url: format!("http://{address}/mcp"),
            requests,
            handle: Some(handle),
        }
    }

    fn url(&self) -> &str {
        &self.url
    }

    fn requests(&self) -> MutexGuard<'_, Vec<RecordedRequest>> {
        self.requests.lock().expect("requests lock")
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn serve_one(stream: &mut TcpStream, response: &TestResponse, sink: &Mutex<Vec<RecordedRequest>>) {
    let Ok(clone) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(clone);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let mut headers = Vec::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if name == "content-length" {
                content_length = value.parse().unwrap_or(0);
            }
            headers.push((name, value));
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 && reader.read_exact(&mut body).is_err() {
        return;
    }
    sink.lock().expect("requests lock").push(RecordedRequest {
        request_line: request_line.trim().to_string(),
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    });

    let mut wire = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        response.content_type,
        response.body.len()
    );
    for (name, value) in &response.headers {
        wire.push_str(name);
        wire.push_str(": ");
        wire.push_str(value);
        wire.push_str("\r\n");
    }
    wire.push_str("\r\n");
    wire.push_str(&response.body);
    let _ = stream.write_all(wire.as_bytes());
    let _ = stream.flush();
}

#[test]
fn streamable_http_posts_json_and_returns_the_matching_envelope() {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": "2026-07-28",
            "capabilities": {},
            "serverInfo": {"name": "http-helper", "version": "0.1.0"}
        }
    })
    .to_string();
    let server = TestServer::start(vec![TestResponse::json(body)]);
    let transport = connect(TransportConfig::StreamableHttp(HttpConfig::new(
        server.url(),
    )))
    .expect("connect streamable http");

    let mut client = Client::new("http-helper", transport);
    let initialized = client.initialize().expect("initialize over HTTP");
    assert_eq!(initialized.protocol_version, McpRevision::V2026_07_28);

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.request_line, "POST /mcp HTTP/1.1");
    assert_eq!(request.header("content-type"), Some("application/json"));
    assert_eq!(
        request.header("accept"),
        Some("application/json, text/event-stream")
    );
    assert_eq!(request.header("mcp-method"), Some("initialize"));
    assert!(request.header("mcp-session-id").is_none());
    let sent: Value = serde_json::from_str(&request.body).expect("request body is JSON");
    assert_eq!(sent["method"], "initialize");
    assert_eq!(sent["id"], 1);
}

#[test]
fn streamable_http_reads_sse_and_ignores_non_response_events() {
    let sse = concat!(
        "event: message\n",
        "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{}}\n",
        "\n",
        "data: this event is not json\n",
        "\n",
        "event: message\n",
        "data: {\"jsonrpc\":\"2.0\",\n",
        "data: \"id\":5,\n",
        "data: \"result\":{\"protocolVersion\":\"2026-07-28\",\"capabilities\":{}}}\n",
        "\n",
    );
    let server = TestServer::start(vec![TestResponse::sse(sse)]);
    let transport = HttpTransport::new(HttpConfig::new(server.url())).expect("HTTP transport");

    let response = transport
        .exchange(&json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "initialize",
            "params": {}
        }))
        .expect("SSE response");
    assert_eq!(response["result"]["protocolVersion"], "2026-07-28");

    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].header("mcp-method"), Some("initialize"));
}

#[test]
fn streamable_http_propagates_the_server_session_id() {
    let first = TestResponse::json(
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"protocolVersion": "2026-07-28", "capabilities": {}}
        })
        .to_string(),
    )
    .with_header("Mcp-Session-Id", "session-abc");
    let second =
        TestResponse::json(json!({"jsonrpc": "2.0", "id": 2, "result": {"tools": []}}).to_string());
    let server = TestServer::start(vec![first, second]);

    let mut headers = Headers::new();
    headers.insert(HEADER_SESSION_ID, "preset-1");
    let transport = HttpTransport::new(HttpConfig::new(server.url()).with_headers(headers))
        .expect("HTTP transport");

    transport
        .exchange(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}))
        .expect("first exchange");
    assert_eq!(transport.session_id().as_deref(), Some("session-abc"));

    let second_response = transport
        .exchange(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}))
        .expect("second exchange");
    assert_eq!(second_response["id"], 2);

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].header("mcp-session-id"), Some("preset-1"));
    assert_eq!(
        requests[1].header("mcp-session-id"),
        Some("session-abc"),
        "the transport must echo the server-assigned session id"
    );
    assert_eq!(requests[1].header("mcp-method"), Some("tools/list"));
}

#[test]
fn streamable_http_reports_status_without_the_body() {
    let mut response = TestResponse::json("do-not-leak this body");
    response.status = "503 Service Unavailable";
    response.content_type = "text/plain";
    let server = TestServer::start(vec![response]);
    let transport = HttpTransport::new(HttpConfig::new(server.url())).expect("HTTP transport");

    let error = transport
        .exchange(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        .expect_err("503 must fail");
    assert_eq!(error.code(), ErrorCode::ProviderProtocol);
    assert!(error.message().contains("503"), "{}", error.message());
    assert!(
        !error.message().contains("do-not-leak"),
        "the response body must never be echoed: {}",
        error.message()
    );
}

#[test]
fn legacy_http_sse_is_off_by_default() {
    assert_eq!(TransportMode::default(), TransportMode::StreamableHttp);
    assert!(!TransportMode::LegacyHttpSse.is_supported());

    let error = match connect(TransportConfig::LegacyHttpSse {
        url: "http://127.0.0.1:1/mcp".to_string(),
    }) {
        Ok(_) => panic!("the legacy shim must be refused"),
        Err(error) => error,
    };
    assert_eq!(error.code(), ErrorCode::Unsupported);
    assert!(
        error.message().to_ascii_lowercase().contains("legacy"),
        "{}",
        error.message()
    );
    assert!(
        error.message().contains("off by default"),
        "{}",
        error.message()
    );
}

#[test]
fn http_rejects_a_non_http_url() {
    let error = HttpTransport::new(HttpConfig::new("file:///tmp/mcp.json"))
        .expect_err("file URLs are not an MCP endpoint");
    assert_eq!(error.code(), ErrorCode::InvalidInput);
}
