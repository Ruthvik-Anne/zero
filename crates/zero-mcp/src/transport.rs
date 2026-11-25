//! Production MCP transports (T-MCP-02, MCP-06, MCP-17).
//!
//! Two transports are implemented: a stdio child process with newline-delimited
//! JSON-RPC and a Streamable HTTP POST that accepts either a JSON body or a
//! server-sent-events body. The legacy HTTP+SSE transport is a documented
//! compatibility shim that is **off by default**; [`connect`] refuses it with
//! [`ErrorCode::Unsupported`] and T-MCP-02 ships only that switch.
//!
//! Both transports implement [`crate::client::Transport`] and return the whole
//! JSON-RPC response envelope, so id matching and envelope validation stay in
//! one place ([`crate::jsonrpc::expect_result`]).

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::Value;
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::client::Transport;
use crate::headers::{Headers, HEADER_METHOD, HEADER_NAME, HEADER_SESSION_ID};

/// Default per-request timeout for both transports.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Default bound on one stdio response line.
pub const DEFAULT_MAX_LINE_BYTES: usize = 8 * 1024 * 1024;
/// Default bound on the captured stderr tail.
pub const DEFAULT_STDERR_TAIL_BYTES: usize = 8 * 1024;
/// Default bound on one HTTP response body.
pub const DEFAULT_MAX_HTTP_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Variables whose names contain one of these markers are removed before a
/// stdio server is launched (MCP-17).
///
/// This duplicates the small policy in `zero-secrets::scrubbed_env` on purpose:
/// `zero-mcp` sits below `zero-secrets` in the dependency graph and must not
/// depend upward on it. Keep the two lists in sync; the policy is part of the
/// MCP-17 contract, not an implementation detail of the secrets crate.
const SECRET_MARKERS: &[&str] = &["KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"];
/// Agent sockets are kept even though some names could match a marker.
const SECRET_EXEMPT: &[&str] = &["SSH_AUTH_SOCK", "GPG_AGENT_INFO"];
/// Shortest removed value that is redacted from stderr diagnostics.
const MIN_REDACTED_VALUE_BYTES: usize = 4;
/// Longest removed value that is redacted from stderr diagnostics.
const MAX_REDACTED_VALUE_BYTES: usize = 4096;
/// Maximum number of removed values tracked for stderr redaction.
const MAX_REDACTIONS: usize = 64;

/// Whether a variable name looks credential-bearing under the MCP-17 policy.
pub fn is_secret_variable(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    SECRET_MARKERS.iter().any(|marker| upper.contains(marker))
        && !SECRET_EXEMPT.contains(&upper.as_str())
}

fn partition_env(
    base: impl IntoIterator<Item = (String, String)>,
) -> (BTreeMap<String, String>, Vec<String>) {
    let mut kept = BTreeMap::new();
    let mut removed = Vec::new();
    for (name, value) in base {
        if is_secret_variable(&name) {
            if !value.is_empty() {
                removed.push(value);
            }
        } else {
            kept.insert(name, value);
        }
    }
    (kept, removed)
}

/// Remove credential-bearing variables from a child environment.
///
/// Names containing `KEY`, `TOKEN`, `SECRET`, `PASSWORD`, or `CREDENTIAL` are
/// dropped, except `SSH_AUTH_SOCK` and `GPG_AGENT_INFO`. The returned map is the
/// environment a stdio server is allowed to inherit.
pub fn scrubbed_env(base: impl IntoIterator<Item = (String, String)>) -> BTreeMap<String, String> {
    partition_env(base).0
}

/// Bounded, redacting tail of a stdio server's stderr.
#[derive(Debug)]
struct StderrTail {
    bytes: VecDeque<u8>,
    capacity: usize,
    redactions: Vec<String>,
}

impl StderrTail {
    fn new(capacity: usize, mut redactions: Vec<String>) -> Self {
        redactions.retain(|value| {
            value.len() >= MIN_REDACTED_VALUE_BYTES && value.len() <= MAX_REDACTED_VALUE_BYTES
        });
        redactions.sort();
        redactions.dedup();
        // Longest first so a shorter value cannot partially mask a longer one.
        redactions.sort_by_key(|value| std::cmp::Reverse(value.len()));
        redactions.truncate(MAX_REDACTIONS);
        Self {
            bytes: VecDeque::new(),
            capacity,
            redactions,
        }
    }

    fn push(&mut self, chunk: &[u8]) {
        if self.capacity == 0 {
            return;
        }
        for &byte in chunk {
            if self.bytes.len() == self.capacity {
                self.bytes.pop_front();
            }
            self.bytes.push_back(byte);
        }
    }

    fn render(&self) -> String {
        let bytes: Vec<u8> = self.bytes.iter().copied().collect();
        let mut text = String::from_utf8_lossy(&bytes).into_owned();
        for secret in &self.redactions {
            if text.contains(secret.as_str()) {
                text = text.replace(secret.as_str(), "[redacted]");
            }
        }
        text
    }
}

/// Launch settings for a stdio MCP server.
#[derive(Debug, Clone)]
pub struct StdioConfig {
    /// Executable to launch.
    pub program: PathBuf,
    /// Arguments, in order.
    pub args: Vec<String>,
    /// Extra environment entries. They are merged over the inherited
    /// environment and then scrubbed under the same MCP-17 policy.
    pub env: BTreeMap<String, String>,
    /// Working directory, when it should differ from the parent's.
    pub cwd: Option<PathBuf>,
    /// Per-request timeout. The child is killed when it expires.
    pub timeout: Duration,
    /// Bound on one response line.
    pub max_line_bytes: usize,
    /// Bound on the retained stderr tail.
    pub stderr_tail_bytes: usize,
}

impl StdioConfig {
    /// Settings for `program`, inheriting the scrubbed parent environment.
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
            cwd: None,
            timeout: DEFAULT_REQUEST_TIMEOUT,
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
            stderr_tail_bytes: DEFAULT_STDERR_TAIL_BYTES,
        }
    }

    /// Append one argument.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append several arguments.
    pub fn args(mut self, args: impl IntoIterator<Item = String>) -> Self {
        self.args.extend(args);
        self
    }

    /// Add an environment entry. It is scrubbed like the inherited environment.
    pub fn env(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(name.into(), value.into());
        self
    }

    /// Set the working directory.
    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Set the per-request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the response-line bound.
    pub fn with_max_line_bytes(mut self, bytes: usize) -> Self {
        self.max_line_bytes = bytes;
        self
    }
}

#[derive(Debug)]
enum StdioEvent {
    Line(String),
    Oversized,
    ReadError(String),
    Closed,
}

enum BoundedLine {
    Line(Vec<u8>),
    Oversized,
    Eof,
}

fn read_bounded_line<R: BufRead>(reader: &mut R, max: usize) -> io::Result<BoundedLine> {
    let mut bytes = Vec::new();
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    let read = reader.by_ref().take(limit).read_until(b'\n', &mut bytes)?;
    if read == 0 {
        return Ok(BoundedLine::Eof);
    }
    if bytes.len() > max && !bytes.ends_with(b"\n") {
        return Ok(BoundedLine::Oversized);
    }
    Ok(BoundedLine::Line(bytes))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn matching_envelope(value: Value, id: &Value) -> Option<Value> {
    match value {
        Value::Array(items) => items
            .into_iter()
            .find_map(|item| matching_envelope(item, id)),
        Value::Object(ref object) => (object.get("id") == Some(id)).then_some(value),
        _ => None,
    }
}

fn response_from_json(body: &str, id: &Value) -> Option<Value> {
    let value: Value = serde_json::from_str(body.trim()).ok()?;
    matching_envelope(value, id)
}

fn response_from_sse(body: &str, id: &Value) -> Option<Value> {
    let mut data: Vec<String> = Vec::new();
    let mut events: Vec<String> = Vec::new();
    for line in body.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            if !data.is_empty() {
                events.push(data.join("\n"));
                data.clear();
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("data:") {
            data.push(rest.strip_prefix(' ').unwrap_or(rest).to_string());
        }
    }
    if !data.is_empty() {
        events.push(data.join("\n"));
    }
    events.into_iter().find_map(|event| {
        let value: Value = serde_json::from_str(&event).ok()?;
        matching_envelope(value, id)
    })
}

struct StdioInner {
    child: Child,
    stdin: Option<ChildStdin>,
    dead: bool,
}

/// A stdio MCP server: newline-delimited JSON-RPC over a child process.
///
/// The child environment is scrubbed on launch (MCP-17). A reader thread turns
/// stdout lines into events, so one request cannot block forever: the caller
/// waits with a timeout and kills the child on expiry. Notification and log
/// lines are skipped until a response with the request id arrives.
pub struct StdioTransport {
    program: PathBuf,
    timeout: Duration,
    max_line_bytes: usize,
    pid: u32,
    inner: Mutex<StdioInner>,
    events: Option<Receiver<StdioEvent>>,
    reader: Option<JoinHandle<()>>,
    stderr: Arc<Mutex<StderrTail>>,
    stderr_reader: Option<JoinHandle<()>>,
}

impl fmt::Debug for StdioTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StdioTransport")
            .field("program", &self.program)
            .field("pid", &self.pid)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl StdioTransport {
    /// Launch the configured child and start its stdout and stderr readers.
    ///
    /// The inherited environment and [`StdioConfig::env`] are merged, scrubbed,
    /// and applied with `env_clear`, so a credential-bearing variable cannot
    /// reach the server by either route.
    pub fn spawn(config: StdioConfig) -> Result<Self> {
        let mut inherited = BTreeMap::new();
        for (name, value) in std::env::vars_os() {
            let (Ok(name), Ok(value)) = (name.into_string(), value.into_string()) else {
                // A non-Unicode entry cannot be forwarded safely; drop it.
                continue;
            };
            inherited.insert(name, value);
        }
        inherited.extend(config.env.iter().map(|(k, v)| (k.clone(), v.clone())));
        let (environment, removed_values) = partition_env(inherited);

        let mut command = Command::new(&config.program);
        command
            .args(&config.args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in &environment {
            command.env(name, value);
        }
        if let Some(cwd) = &config.cwd {
            command.current_dir(cwd);
        }

        let mut child = command.spawn().map_err(|error| {
            ZeroError::new(
                ErrorCode::Unavailable,
                format!(
                    "failed to launch MCP stdio server `{}`: {error}",
                    config.program.display()
                ),
            )
        })?;
        let pid = child.id();

        let (Some(stdin), Some(stdout), Some(stderr_pipe)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ZeroError::new(
                ErrorCode::Internal,
                "MCP stdio child pipes were not created",
            ));
        };

        let (sender, events) = mpsc::channel();
        let line_limit = config.max_line_bytes;
        let reader = std::thread::Builder::new()
            .name("zero-mcp-stdio-reader".to_string())
            .spawn(move || {
                let mut stdout = BufReader::new(stdout);
                loop {
                    let event = match read_bounded_line(&mut stdout, line_limit) {
                        Ok(BoundedLine::Eof) => {
                            let _ = sender.send(StdioEvent::Closed);
                            break;
                        }
                        Ok(BoundedLine::Line(bytes)) => {
                            let text = String::from_utf8_lossy(&bytes);
                            let text = text.trim();
                            if text.is_empty() {
                                continue;
                            }
                            StdioEvent::Line(text.to_string())
                        }
                        Ok(BoundedLine::Oversized) => {
                            let _ = sender.send(StdioEvent::Oversized);
                            break;
                        }
                        Err(error) => {
                            let _ = sender.send(StdioEvent::ReadError(error.to_string()));
                            break;
                        }
                    };
                    if sender.send(event).is_err() {
                        break;
                    }
                }
            });
        let reader = match reader {
            Ok(handle) => handle,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ZeroError::new(
                    ErrorCode::Internal,
                    format!("failed to start the MCP stdio reader thread: {error}"),
                ));
            }
        };

        let stderr = Arc::new(Mutex::new(StderrTail::new(
            config.stderr_tail_bytes,
            removed_values,
        )));
        let tail = Arc::clone(&stderr);
        let stderr_reader = std::thread::Builder::new()
            .name("zero-mcp-stdio-stderr".to_string())
            .spawn(move || {
                let mut pipe = BufReader::new(stderr_pipe);
                let mut chunk = [0u8; 4096];
                loop {
                    match pipe.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(read) => lock(&tail).push(&chunk[..read]),
                    }
                }
            });
        let stderr_reader = match stderr_reader {
            Ok(handle) => handle,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ZeroError::new(
                    ErrorCode::Internal,
                    format!("failed to start the MCP stdio stderr thread: {error}"),
                ));
            }
        };

        Ok(Self {
            program: config.program,
            timeout: config.timeout,
            max_line_bytes: config.max_line_bytes,
            pid,
            inner: Mutex::new(StdioInner {
                child,
                stdin: Some(stdin),
                dead: false,
            }),
            events: Some(events),
            reader: Some(reader),
            stderr,
            stderr_reader: Some(stderr_reader),
        })
    }

    /// Operating-system process id of the child.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Configured executable path, for diagnostics.
    pub fn program(&self) -> &std::path::Path {
        &self.program
    }

    /// Whether the child is still running.
    ///
    /// An already-exited child is reaped here and the transport is marked dead.
    pub fn is_running(&self) -> bool {
        let mut inner = lock(&self.inner);
        if inner.dead {
            return false;
        }
        match inner.child.try_wait() {
            Ok(None) => true,
            Ok(Some(_)) | Err(_) => {
                inner.dead = true;
                false
            }
        }
    }

    /// The captured stderr tail, with known removed secret values redacted.
    ///
    /// This is child output and therefore untrusted diagnostic data: never feed
    /// it back to a model as instructions. It is also deliberately excluded from
    /// every [`ZeroError`] message.
    pub fn stderr_tail(&self) -> String {
        lock(&self.stderr).render()
    }

    /// Close stdin, then kill and reap the child.
    ///
    /// Calling this more than once is harmless. [`Drop`] does the same.
    pub fn shutdown(&self) {
        let mut inner = lock(&self.inner);
        inner.stdin.take();
        if !inner.dead {
            let _ = inner.child.kill();
            let _ = inner.child.wait();
            inner.dead = true;
        }
    }

    fn terminated(&self) -> ZeroError {
        ZeroError::new(
            ErrorCode::Unavailable,
            format!(
                "MCP stdio server `{}` has terminated",
                self.program.display()
            ),
        )
    }

    fn timed_out(&self) -> ZeroError {
        ZeroError::new(
            ErrorCode::Timeout,
            format!(
                "MCP stdio server `{}` did not answer within {:?}; the child was killed",
                self.program.display(),
                self.timeout
            ),
        )
    }

    fn write_request(&self, line: &str) -> io::Result<()> {
        let mut inner = lock(&self.inner);
        if inner.dead {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "server has terminated",
            ));
        }
        match inner.stdin.as_mut() {
            Some(stdin) => stdin
                .write_all(line.as_bytes())
                .and_then(|()| stdin.write_all(b"\n"))
                .and_then(|()| stdin.flush()),
            None => Err(io::Error::new(io::ErrorKind::BrokenPipe, "stdin is closed")),
        }
    }
}

impl Transport for StdioTransport {
    fn exchange(&self, request: &Value) -> Result<Value> {
        let id = request.get("id").cloned().ok_or_else(|| {
            ZeroError::new(
                ErrorCode::InvalidInput,
                "JSON-RPC request must include an `id`",
            )
        })?;
        let line = serde_json::to_string(request)?;
        if line.len() > self.max_line_bytes {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "MCP stdio request is {} bytes, above the {}-byte line bound",
                    line.len(),
                    self.max_line_bytes
                ),
            ));
        }
        if let Err(error) = self.write_request(&line) {
            self.shutdown();
            return Err(ZeroError::new(
                ErrorCode::Unavailable,
                format!(
                    "MCP stdio server `{}` is not accepting requests: {error}",
                    self.program.display()
                ),
            ));
        }

        let deadline = Instant::now() + self.timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.shutdown();
                return Err(self.timed_out());
            }
            let Some(events) = self.events.as_ref() else {
                return Err(self.terminated());
            };
            match events.recv_timeout(remaining) {
                Ok(StdioEvent::Line(line)) => {
                    if let Ok(value) = serde_json::from_str::<Value>(&line) {
                        if let Some(response) = matching_envelope(value, &id) {
                            return Ok(response);
                        }
                    }
                    // A notification, a log line, or a response for another id.
                }
                Ok(StdioEvent::Closed) => {
                    return Err(ZeroError::new(
                        ErrorCode::Unavailable,
                        format!(
                            "MCP stdio server `{}` closed its output before responding",
                            self.program.display()
                        ),
                    ))
                }
                Ok(StdioEvent::Oversized) => {
                    self.shutdown();
                    return Err(ZeroError::new(
                        ErrorCode::LimitExceeded,
                        format!(
                            "MCP stdio server `{}` sent a line above the {}-byte bound",
                            self.program.display(),
                            self.max_line_bytes
                        ),
                    ));
                }
                Ok(StdioEvent::ReadError(detail)) => {
                    self.shutdown();
                    return Err(ZeroError::new(
                        ErrorCode::Unavailable,
                        format!(
                            "MCP stdio server `{}` stream failed: {detail}",
                            self.program.display()
                        ),
                    ));
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.shutdown();
                    return Err(self.timed_out());
                }
                Err(RecvTimeoutError::Disconnected) => return Err(self.terminated()),
            }
        }
    }
}

impl Drop for StdioTransport {
    fn drop(&mut self) {
        {
            let mut inner = lock(&self.inner);
            inner.stdin.take();
            if !inner.dead {
                let _ = inner.child.kill();
                let _ = inner.child.wait();
                inner.dead = true;
            }
        }
        // Unblock the reader before joining it: a blocked `send` fails once the
        // receiver is gone.
        if let Some(events) = self.events.take() {
            drop(events);
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
    }
}

/// Settings for the Streamable HTTP transport.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Endpoint the JSON-RPC request is POSTed to.
    pub url: String,
    /// Extra request headers, such as `MCP-Protocol-Version` and a pre-assigned
    /// `Mcp-Session-Id`.
    pub headers: Headers,
    /// Per-request timeout, covering the response body.
    pub timeout: Duration,
    /// Bound on the response body.
    pub max_body_bytes: usize,
}

impl HttpConfig {
    /// Settings for `url` with a 30-second timeout.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            headers: Headers::new(),
            timeout: DEFAULT_REQUEST_TIMEOUT,
            max_body_bytes: DEFAULT_MAX_HTTP_BODY_BYTES,
        }
    }

    /// Replace the extra request headers.
    pub fn with_headers(mut self, headers: Headers) -> Self {
        self.headers = headers;
        self
    }

    /// Add one request header.
    pub fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.insert(name, value);
        self
    }

    /// Set the per-request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the response-body bound.
    pub fn with_max_body_bytes(mut self, bytes: usize) -> Self {
        self.max_body_bytes = bytes;
        self
    }
}

/// A Streamable HTTP MCP transport.
///
/// Each [`Transport::exchange`] sends one POST. `Content-Type` and `Accept` are
/// fixed; `Mcp-Method` and `Mcp-Name` are derived from the request, and the
/// session id returned by the server is echoed on later requests. A response may
/// be a JSON body or an SSE stream; the JSON-RPC envelope with the request id is
/// selected from either shape.
pub struct HttpTransport {
    url: String,
    client: reqwest::blocking::Client,
    headers: Headers,
    session: Mutex<Option<String>>,
    max_body_bytes: usize,
}

impl fmt::Debug for HttpTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpTransport")
            .field("url", &self.url)
            .field("has_session", &self.session_id().is_some())
            .finish_non_exhaustive()
    }
}

impl HttpTransport {
    /// Build the client. The URL must be `http` or `https`.
    pub fn new(config: HttpConfig) -> Result<Self> {
        let url = reqwest::Url::parse(&config.url).map_err(|error| {
            ZeroError::new(
                ErrorCode::InvalidInput,
                format!("MCP HTTP endpoint is not a valid URL: {error}"),
            )
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                format!(
                    "MCP HTTP endpoint must use http or https, got `{}`",
                    url.scheme()
                ),
            ));
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|error| {
                ZeroError::new(
                    ErrorCode::Internal,
                    format!("failed to build the MCP HTTP client: {error}"),
                )
            })?;
        Ok(Self {
            url: url.to_string(),
            client,
            headers: config.headers,
            session: Mutex::new(None),
            max_body_bytes: config.max_body_bytes,
        })
    }

    /// The endpoint this transport posts to.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The session id assigned by the server, when one has been seen.
    pub fn session_id(&self) -> Option<String> {
        lock(&self.session).clone()
    }
}

impl Transport for HttpTransport {
    fn exchange(&self, request: &Value) -> Result<Value> {
        let id = request.get("id").cloned().ok_or_else(|| {
            ZeroError::new(
                ErrorCode::InvalidInput,
                "JSON-RPC request must include an `id`",
            )
        })?;
        let body = serde_json::to_vec(request)?;

        let mut builder = self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(
                reqwest::header::ACCEPT,
                "application/json, text/event-stream",
            );
        let session = self
            .session_id()
            .or_else(|| self.headers.get(HEADER_SESSION_ID).map(str::to_string));
        for (name, value) in self.headers.iter() {
            if name.eq_ignore_ascii_case(HEADER_SESSION_ID) {
                continue;
            }
            builder = builder.header(name, value);
        }
        if let Some(method) = request.get("method").and_then(Value::as_str) {
            builder = builder.header(HEADER_METHOD, method);
        }
        if let Some(name) = request.pointer("/params/name").and_then(Value::as_str) {
            builder = builder.header(HEADER_NAME, name);
        }
        if let Some(session) = session {
            builder = builder.header(HEADER_SESSION_ID, session);
        }

        let response = builder.body(body).send().map_err(map_reqwest)?;
        let status = response.status();
        if !status.is_success() {
            // The body is deliberately not read or echoed: it can carry
            // attacker-controlled or sensitive data and belongs to no protocol.
            return Err(ZeroError::new(
                ErrorCode::ProviderProtocol,
                format!("MCP HTTP transport returned HTTP {status}"),
            ));
        }
        if let Some(session) = header_value(response.headers(), HEADER_SESSION_ID) {
            *lock(&self.session) = Some(session);
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let text = read_bounded_body(response, self.max_body_bytes)?;
        let envelope = if content_type.contains("text/event-stream") {
            response_from_sse(&text, &id)
        } else {
            response_from_json(&text, &id)
        };
        envelope.ok_or_else(|| {
            ZeroError::new(
                ErrorCode::ProviderProtocol,
                format!("MCP HTTP response did not contain a JSON-RPC response with id {id}"),
            )
        })
    }
}

fn map_reqwest(error: reqwest::Error) -> ZeroError {
    if error.is_timeout() {
        ZeroError::new(
            ErrorCode::Timeout,
            format!("MCP HTTP request timed out: {error}"),
        )
    } else if error.is_connect() {
        ZeroError::new(
            ErrorCode::Offline,
            format!("MCP HTTP endpoint is unreachable: {error}"),
        )
    } else {
        ZeroError::new(
            ErrorCode::ProviderProtocol,
            format!("MCP HTTP request failed: {error}"),
        )
    }
}

fn header_value(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn read_bounded_body(response: reqwest::blocking::Response, max: usize) -> Result<String> {
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    let mut reader = response.take(limit);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).map_err(|error| {
        if error.kind() == io::ErrorKind::TimedOut {
            ZeroError::new(
                ErrorCode::Timeout,
                format!("MCP HTTP response body timed out: {error}"),
            )
        } else {
            ZeroError::new(
                ErrorCode::ProviderProtocol,
                format!("MCP HTTP response body could not be read: {error}"),
            )
        }
    })?;
    if bytes.len() > max {
        return Err(ZeroError::new(
            ErrorCode::LimitExceeded,
            format!("MCP HTTP response body is above the {max}-byte bound"),
        ));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Which transport a server configuration selects.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TransportMode {
    /// A child process speaking newline-delimited JSON-RPC.
    Stdio,
    /// Streamable HTTP, the default.
    #[default]
    StreamableHttp,
    /// Legacy HTTP+SSE. Off by default and not implemented in T-MCP-02.
    LegacyHttpSse,
}

impl TransportMode {
    /// Whether this mode can be opened today.
    pub const fn is_supported(self) -> bool {
        !matches!(self, TransportMode::LegacyHttpSse)
    }
}

/// Transport selection plus its connection settings.
#[derive(Debug, Clone)]
pub enum TransportConfig {
    /// Launch a stdio server.
    Stdio(StdioConfig),
    /// Post to a Streamable HTTP endpoint.
    StreamableHttp(HttpConfig),
    /// Legacy HTTP+SSE. Off by default; [`connect`] refuses it (T-MCP-02).
    LegacyHttpSse {
        /// Endpoint that would serve the legacy SSE stream.
        url: String,
    },
}

impl TransportConfig {
    /// The mode this config selects.
    pub fn mode(&self) -> TransportMode {
        match self {
            TransportConfig::Stdio(_) => TransportMode::Stdio,
            TransportConfig::StreamableHttp(_) => TransportMode::StreamableHttp,
            TransportConfig::LegacyHttpSse { .. } => TransportMode::LegacyHttpSse,
        }
    }
}

/// Open the transport selected by `config`.
///
/// Streamable HTTP is the default. Stdio is opt-in by configuration. The legacy
/// HTTP+SSE shim is off by default and refused here with
/// [`ErrorCode::Unsupported`] until a later task ships it; T-MCP-02 deliberately
/// provides only the default-off switch.
pub fn connect(config: TransportConfig) -> Result<Box<dyn Transport>> {
    match config {
        TransportConfig::Stdio(config) => Ok(Box::new(StdioTransport::spawn(config)?)),
        TransportConfig::StreamableHttp(config) => Ok(Box::new(HttpTransport::new(config)?)),
        TransportConfig::LegacyHttpSse { url: _ } => Err(ZeroError::new(
            ErrorCode::Unsupported,
            "the legacy MCP HTTP+SSE transport is off by default and is not shipped in T-MCP-02; \
             use Streamable HTTP, or enable the documented compatibility shim when a later task \
             provides it",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scrub_policy_keeps_agent_sockets_and_drops_secrets() {
        let env = scrubbed_env([
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("OPENAI_API_KEY".to_string(), "sk-leak".to_string()),
            ("my_token".to_string(), "t".to_string()),
            ("DB_PASSWORD".to_string(), "p".to_string()),
            ("CREDENTIAL_FILE".to_string(), "c".to_string()),
            ("SSH_AUTH_SOCK".to_string(), "/tmp/agent".to_string()),
            ("GPG_AGENT_INFO".to_string(), "/tmp/gpg".to_string()),
            ("MONKEY".to_string(), "kept? no".to_string()),
        ]);
        assert_eq!(env.get("PATH"), Some(&"/usr/bin".to_string()));
        assert_eq!(env.get("SSH_AUTH_SOCK"), Some(&"/tmp/agent".to_string()));
        assert_eq!(env.get("GPG_AGENT_INFO"), Some(&"/tmp/gpg".to_string()));
        assert!(!env.contains_key("OPENAI_API_KEY"));
        assert!(!env.contains_key("my_token"));
        assert!(!env.contains_key("DB_PASSWORD"));
        assert!(!env.contains_key("CREDENTIAL_FILE"));
        assert!(!env.contains_key("MONKEY"));
        assert!(is_secret_variable("X-API-KEY"));
        assert!(!is_secret_variable("SSH_AUTH_SOCK"));
    }

    #[test]
    fn sse_skips_noise_and_joins_multiline_data() {
        let body = concat!(
            "event: message\n",
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}\n",
            "\n",
            "data: not-json\n",
            "\n",
            "event: message\n",
            "data: {\"jsonrpc\":\"2.0\",\n",
            "data: \"id\":7,\n",
            "data: \"result\":{\"ok\":true}}\n",
        );
        let response = response_from_sse(body, &json!(7)).expect("response");
        assert_eq!(response["result"]["ok"], true);
        assert!(response_from_sse(body, &json!(8)).is_none());
    }

    #[test]
    fn json_body_and_batch_are_matched_by_id() {
        let single = r#"{"jsonrpc":"2.0","id":3,"result":{"ok":true}}"#;
        assert_eq!(response_from_json(single, &json!(3)).unwrap()["id"], 3);
        assert!(response_from_json(single, &json!(4)).is_none());

        let batch = r#"[{"jsonrpc":"2.0","id":1,"result":{}},{"jsonrpc":"2.0","id":2,"result":{"ok":true}}]"#;
        assert_eq!(
            response_from_json(batch, &json!(2)).unwrap()["result"]["ok"],
            true
        );
    }

    #[test]
    fn stderr_tail_is_bounded_and_redacts_removed_values() {
        let mut tail = StderrTail::new(48, vec!["hunter2-secret".to_string()]);
        tail.push(b"hunter2-secret\n");
        let rendered = tail.render();
        assert!(!rendered.contains("hunter2-secret"));
        assert!(rendered.contains("[redacted]"));

        tail.push(&[b'x'; 200]);
        assert!(tail.bytes.len() <= 48);
    }

    #[test]
    fn overlong_lines_are_reported_without_buffering_them() {
        let mut reader = BufReader::new(&b"0123456789abcdef\n"[..]);
        assert!(matches!(
            read_bounded_line(&mut reader, 8).unwrap(),
            BoundedLine::Oversized
        ));

        let mut reader = BufReader::new(&b"01234567\n"[..]);
        assert!(matches!(
            read_bounded_line(&mut reader, 8).unwrap(),
            BoundedLine::Line(_)
        ));

        let mut reader = BufReader::new(&b""[..]);
        assert!(matches!(
            read_bounded_line(&mut reader, 8).unwrap(),
            BoundedLine::Eof
        ));
    }

    #[test]
    fn streamable_http_is_the_default_mode() {
        assert_eq!(TransportMode::default(), TransportMode::StreamableHttp);
        assert!(TransportMode::Stdio.is_supported());
        assert!(!TransportMode::LegacyHttpSse.is_supported());
    }
}
