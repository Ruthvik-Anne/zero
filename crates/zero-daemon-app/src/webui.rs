//! Local web surface (ACT-16, T-WEBUI-01).
//!
//! The same action registry the TUI and the desktop app render is served from a
//! listener that is pinned to loopback and opened by a one-time token. The
//! server is deliberately small: one connection at a time, `GET` only, a fixed
//! document, one JSON snapshot, no external assets, no telemetry, no filesystem
//! access, and no public listener. See `docs/webui.md`.
//!
//! Invariants:
//!
//! - [`WebUiConfig::validate`] refuses every non-loopback bind with
//!   `zero.pol.denied`; [`LocalWebUi::start`] validates the bound address again
//!   after `bind`, so a reconstructed config cannot widen the listener.
//! - The token is generated from OS entropy, compared without an early exit,
//!   expires after `token_ttl_ms`, and is consumed by the first authorized
//!   request. It appears in `url()` and nowhere else: no `Display`, no logging,
//!   `Debug` prints `<redacted>`, and it is never serialised.
//! - Requests and responses are size-capped and the router only knows the two
//!   fixed paths, so there is no path that can reach a file.

use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zero_actions::ActionRecord;
use zero_types::error::{ErrorCode, Result, ZeroError};

/// Default one-time token lifetime: five minutes.
pub const DEFAULT_TOKEN_TTL_MS: u64 = 5 * 60 * 1000;

/// Cap on the request head (request line plus headers). A larger head is
/// refused with `413` before the token is consulted.
pub const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// Cap on a response body. A larger action snapshot is refused with `500`
/// instead of being written.
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// How long `run_until` sleeps between non-blocking accepts.
const POLL_INTERVAL: Duration = Duration::from_millis(2);

/// How long `handle_once` waits for a connection before failing with
/// `zero.fnd.timeout`.
const DEFAULT_ACCEPT_TIMEOUT: Duration = Duration::from_secs(5);

/// Read and write timeout applied to one accepted connection.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Number of OS-entropy bytes behind one token.
const TOKEN_BYTES: usize = 32;

const HTML_CSP: &str =
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; \
     base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const ACTION_PLACEHOLDER: &str = "__ZERO_ACTION_SNAPSHOT__";

// A fixed document with one substitution: the action snapshot. Everything else
// (styles, the renderer) is inline, so the page needs no second request and the
// one-time token can stay single use.
const INDEX_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Zero</title>
<style>
:root { color-scheme: light dark; --fg: #16181d; --muted: #5b6270; --bg: #fbfbfc; --line: #e3e5ea; --chip: #eef0f4; }
@media (prefers-color-scheme: dark) { :root { --fg: #e8eaf0; --muted: #9aa1af; --bg: #14161a; --line: #2a2d34; --chip: #1e2127; } }
* { box-sizing: border-box; }
body { margin: 0; padding: 2rem 1.25rem 3rem; background: var(--bg); color: var(--fg);
  font: 15px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; }
main, header { max-width: 46rem; margin: 0 auto; }
header { display: flex; align-items: baseline; gap: .75rem; flex-wrap: wrap; margin-bottom: 1.75rem; }
h1 { font-size: 1.25rem; margin: 0; letter-spacing: -.01em; }
.badge { font-size: .75rem; padding: .1rem .5rem; border: 1px solid var(--line); border-radius: 999px; background: var(--chip); color: var(--muted); }
p { margin: .35rem 0; }
.hint { color: var(--muted); font-size: .875rem; }
ul { list-style: none; margin: 0; padding: 0; border-top: 1px solid var(--line); }
li { padding: .8rem 0; border-bottom: 1px solid var(--line); }
.title { font-weight: 600; }
.id { color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .8125rem; }
.desc { color: var(--muted); font-size: .875rem; }
</style>
</head>
<body>
<header>
  <h1>Zero</h1>
  <span class="badge">local web UI</span>
  <span class="badge" id="action-count">actions</span>
</header>
<main>
  <p class="hint">Served once from the loopback core behind a single-use token. Reloading this
  address fails; reopen the web UI from the app for a new link.</p>
  <ul id="actions"></ul>
</main>
<script type="application/json" id="zero-action-snapshot">__ZERO_ACTION_SNAPSHOT__</script>
<script>
(function () {
  var list = document.getElementById('actions');
  var count = document.getElementById('action-count');
  var actions = [];
  try {
    actions = JSON.parse(document.getElementById('zero-action-snapshot').textContent) || [];
  } catch (err) {
    actions = [];
  }
  count.textContent = actions.length + (actions.length === 1 ? ' action' : ' actions');
  if (!actions.length) {
    var empty = document.createElement('li');
    empty.className = 'desc';
    empty.textContent = 'No actions are registered on this surface.';
    list.appendChild(empty);
    return;
  }
  actions.forEach(function (action) {
    var item = document.createElement('li');
    var title = document.createElement('div');
    title.className = 'title';
    title.textContent = action.title;
    var id = document.createElement('div');
    id.className = 'id';
    id.textContent = action.id;
    var desc = document.createElement('div');
    desc.className = 'desc';
    desc.textContent = action.description;
    item.appendChild(title);
    item.appendChild(id);
    item.appendChild(desc);
    list.appendChild(item);
  });
})();
</script>
</body>
</html>
"##;

/// How the web UI may be bound.
///
/// `bind` must be a loopback socket address. `0.0.0.0`, `::`, a LAN address, or
/// a hostname is refused by [`WebUiConfig::validate`] with `zero.pol.denied`.
/// Port `0` asks the operating system for an ephemeral port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebUiConfig {
    pub bind: SocketAddr,
    pub token_ttl_ms: u64,
    /// The only browser origin allowed to call the UI. `None` means same-origin
    /// requests only. A wildcard is refused.
    pub allowed_origin: Option<String>,
}

impl WebUiConfig {
    /// Loopback on `port` with the default token lifetime.
    pub fn loopback(port: u16) -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], port)),
            token_ttl_ms: DEFAULT_TOKEN_TTL_MS,
            allowed_origin: None,
        }
    }

    /// Refuse anything that could expose a public listener.
    pub fn validate(&self) -> Result<()> {
        validate_bind(self.bind)?;
        if let Some(origin) = &self.allowed_origin {
            validate_origin(origin)?;
        }
        Ok(())
    }
}

impl Default for WebUiConfig {
    fn default() -> Self {
        Self::loopback(0)
    }
}

/// Parse a `host:port` bind string, refusing hostnames and non-loopback
/// addresses. A hostname cannot reach [`validate_bind`], so this is the entry
/// point that refuses `example.com:8080` and friends.
pub fn parse_bind(text: &str) -> Result<SocketAddr> {
    let addr: SocketAddr = text.parse().map_err(|_| {
        ZeroError::new(
            ErrorCode::PolicyDenied,
            format!(
                "web UI bind `{text}` is not a loopback socket address; use 127.0.0.1:<port>"
            ),
        )
    })?;
    validate_bind(addr)?;
    Ok(addr)
}

/// Refuse every non-loopback address. Loopback means the IPv4 loopback range or
/// `::1`; `0.0.0.0`, `::`, LAN addresses, and IPv4-mapped IPv6 loopback are all
/// refused.
pub fn validate_bind(bind: SocketAddr) -> Result<()> {
    if !bind.ip().is_loopback() {
        return Err(ZeroError::new(
            ErrorCode::PolicyDenied,
            format!(
                "refusing to bind the local web UI to {bind}: only loopback (127.0.0.1 or ::1) is allowed"
            ),
        ));
    }
    Ok(())
}

fn validate_origin(origin: &str) -> Result<()> {
    let trimmed = origin.trim();
    let scheme_ok = trimmed.starts_with("http://") || trimmed.starts_with("https://");
    let refused = trimmed.is_empty()
        || trimmed == "*"
        || trimmed.eq_ignore_ascii_case("null")
        || !scheme_ok
        || trimmed.contains('*')
        || trimmed.contains(' ')
        || trimmed.ends_with('/');
    if refused {
        return Err(ZeroError::new(
            ErrorCode::PolicyDenied,
            format!(
                "allowed_origin `{origin}` is not one exact origin; use e.g. http://127.0.0.1:7777 and never a wildcard"
            ),
        ));
    }
    Ok(())
}

/// Lifecycle of the one-time token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenState {
    Active,
    Used,
    Expired,
}

/// The single-use token that opens the local web UI.
///
/// The value is 32 OS-entropy bytes rendered as hex. It is never serialisable,
/// never printed by `Debug`, and accepted at most once, before `expires_ms`.
/// `expires_ms` is inclusive: a request at or after it is refused.
#[derive(Clone, PartialEq, Eq)]
pub struct OneTimeToken {
    value: String,
    issued_ms: u64,
    expires_ms: u64,
    used: bool,
}

impl fmt::Debug for OneTimeToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OneTimeToken")
            .field("value", &"<redacted>")
            .field("issued_ms", &self.issued_ms)
            .field("expires_ms", &self.expires_ms)
            .field("used", &self.used)
            .finish()
    }
}

impl OneTimeToken {
    /// Mint a token at `issued_ms` that expires after `ttl_ms`. A `ttl_ms` of
    /// zero produces a token that is already expired.
    ///
    /// Entropy comes from `zero_secrets::signin::random_bytes`, the same OS
    /// source the credential and mesh code use. A failed entropy read aborts the
    /// process there rather than returning a predictable value, so there is no
    /// partial success to report and this function is infallible.
    pub fn generate(issued_ms: u64, ttl_ms: u64) -> Self {
        let bytes = zero_secrets::signin::random_bytes(TOKEN_BYTES);
        Self {
            value: hex(&bytes),
            issued_ms,
            expires_ms: issued_ms.saturating_add(ttl_ms),
            used: false,
        }
    }

    pub fn issued_ms(&self) -> u64 {
        self.issued_ms
    }

    pub fn expires_ms(&self) -> u64 {
        self.expires_ms
    }

    pub fn used(&self) -> bool {
        self.used
    }

    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_ms
    }

    pub fn state(&self, now_ms: u64) -> TokenState {
        if self.used {
            TokenState::Used
        } else if self.is_expired(now_ms) {
            TokenState::Expired
        } else {
            TokenState::Active
        }
    }

    /// Spend the token. Every later call fails, as does a call after expiry.
    pub fn invalidate(&mut self) {
        self.used = true;
    }

    /// Accept one request target carrying this token, before `now_ms`, once.
    ///
    /// The presented value is compared without an early exit and without
    /// branching on the position of the first difference. The comparison is
    /// length-agnostic too, so a short or long value costs the same as a
    /// correct-length one. Length itself is public: tokens are always
    /// [`TOKEN_BYTES`] hex characters.
    pub fn authorize(&mut self, request_target: &str, now_ms: u64) -> bool {
        let presented = match query_token(request_target) {
            Some(value) => value,
            None => return false,
        };
        let matched = constant_time_eq(presented.as_bytes(), self.value.as_bytes());
        if !matched || self.used || self.is_expired(now_ms) {
            return false;
        }
        self.used = true;
        true
    }
}

/// One response produced by [`LocalWebUi`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebUiOutcome {
    pub status: u16,
    pub reason: &'static str,
    pub content_type: &'static str,
    pub body: String,
    /// Set only when `allowed_origin` is configured and the request matched it.
    /// It is never `*`.
    pub allow_origin: Option<String>,
}

impl WebUiOutcome {
    pub fn is_ok(&self) -> bool {
        self.status == 200
    }
}

/// A loopback listener serving the action registry behind a one-time token.
pub struct LocalWebUi {
    config: WebUiConfig,
    listener: TcpListener,
    addr: SocketAddr,
    token: OneTimeToken,
    actions: Vec<ActionRecord>,
    shutdown: Arc<AtomicBool>,
    accept_timeout: Duration,
    served: u64,
}

impl fmt::Debug for LocalWebUi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `token`'s own Debug redacts the value; the URL with a token is never
        // part of this or any other log line.
        f.debug_struct("LocalWebUi")
            .field("bind_url", &self.bind_url())
            .field("token", &self.token)
            .field("actions", &self.actions.len())
            .field("shutdown", &self.shutdown.load(Ordering::Relaxed))
            .field("served", &self.served)
            .finish()
    }
}

impl LocalWebUi {
    /// Bind a loopback listener with an empty action registry.
    pub fn start(config: WebUiConfig) -> Result<Self> {
        Self::start_with_actions(config, Vec::new())
    }

    /// Bind a loopback listener and serve `actions` as the registry snapshot.
    pub fn start_with_actions(config: WebUiConfig, actions: Vec<ActionRecord>) -> Result<Self> {
        config.validate()?;
        let listener = TcpListener::bind(config.bind).map_err(|e| {
            ZeroError::new(
                ErrorCode::Unavailable,
                format!("cannot bind the local web UI to {}: {e}", config.bind),
            )
        })?;
        listener.set_nonblocking(true).map_err(ZeroError::from)?;
        let addr = listener.local_addr().map_err(ZeroError::from)?;
        // Belt and braces: the address the OS actually gave us must also be
        // loopback, so a config built from a struct literal cannot widen it.
        validate_bind(addr)?;
        let token = OneTimeToken::generate(now_ms(), config.token_ttl_ms);
        Ok(Self {
            config,
            listener,
            addr,
            token,
            actions,
            shutdown: Arc::new(AtomicBool::new(false)),
            accept_timeout: DEFAULT_ACCEPT_TIMEOUT,
            served: 0,
        })
    }

    pub fn config(&self) -> &WebUiConfig {
        &self.config
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The address as a URL, never with a token. Safe to log.
    pub fn bind_url(&self) -> String {
        format!("http://{}/", self.addr)
    }

    /// The one-time URL. This is the only place the token value appears; do not
    /// log it.
    pub fn url(&self) -> String {
        format!("http://{}/?token={}", self.addr, self.token.value)
    }

    pub fn token_state(&self, now_ms: u64) -> TokenState {
        self.token.state(now_ms)
    }

    /// A snapshot of the token that was issued for this listener. Hosts that
    /// hand the URL and the token to a webview separately use this; the
    /// listener's own copy is the one `authorize` spends.
    ///
    /// The value stays private: `Debug` prints `<redacted>` and this is never
    /// serialised.
    pub fn token(&self) -> OneTimeToken {
        self.token.clone()
    }

    pub fn token_expires_ms(&self) -> u64 {
        self.token.expires_ms()
    }

    /// Mint a fresh token, e.g. for the next page load after this one is used.
    pub fn issue_token(&mut self) {
        self.token = OneTimeToken::generate(now_ms(), self.config.token_ttl_ms);
    }

    pub fn set_actions(&mut self, actions: Vec<ActionRecord>) {
        self.actions = actions;
    }

    /// The registry snapshot as it is served at `/api/actions`.
    pub fn actions_json(&self) -> Result<String> {
        Ok(serde_json::to_string(&self.actions)?)
    }

    /// Ask a running [`LocalWebUi::run_until`] loop to stop.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// A handle a test or host thread can set to stop the loop.
    pub fn shutdown_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    pub fn served(&self) -> u64 {
        self.served
    }

    /// Accept one connection, answer it, and return the outcome. Bounded by the
    /// accept timeout and by per-connection read/write timeouts.
    pub fn handle_once(&mut self) -> Result<WebUiOutcome> {
        let mut stream = self.accept_within(self.accept_timeout)?;
        self.serve_stream(&mut stream)
    }

    /// Serve until `shutdown` or [`LocalWebUi::shutdown`] is set. One connection
    /// at a time; returns the number of responses written.
    pub fn run_until(&mut self, shutdown: Arc<AtomicBool>) -> Result<u64> {
        while !shutdown.load(Ordering::Relaxed) && !self.shutdown.load(Ordering::Relaxed) {
            match self.accept_now() {
                Ok(Some(mut stream)) => {
                    // A single failed connection must not kill the loop; the
                    // outcome is still counted only when it was written.
                    let _ = self.serve_stream(&mut stream);
                }
                Ok(None) => std::thread::sleep(POLL_INTERVAL),
                Err(e) => return Err(e),
            }
        }
        Ok(self.served)
    }

    fn accept_now(&self) -> Result<Option<TcpStream>> {
        match self.listener.accept() {
            Ok((stream, _peer)) => Ok(Some(stream)),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(ZeroError::from(e)),
        }
    }

    fn accept_within(&self, timeout: Duration) -> Result<TcpStream> {
        let started = Instant::now();
        loop {
            if let Some(stream) = self.accept_now()? {
                return Ok(stream);
            }
            if started.elapsed() >= timeout {
                return Err(ZeroError::new(
                    ErrorCode::Timeout,
                    "no local web UI connection arrived before the accept deadline",
                ));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    fn serve_stream(&mut self, stream: &mut TcpStream) -> Result<WebUiOutcome> {
        // A socket accepted from a non-blocking listener can inherit that mode
        // on Windows, where a read would then return `WouldBlock` instead of
        // waiting for the request head.
        stream.set_nonblocking(false).map_err(ZeroError::from)?;
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .map_err(ZeroError::from)?;
        stream
            .set_write_timeout(Some(IO_TIMEOUT))
            .map_err(ZeroError::from)?;
        let outcome = match read_head(stream) {
            Ok(head) => self.route(&head, now_ms()),
            Err(RequestFailure::TooLarge) => {
                // Leaving bytes unread would turn the close into a reset and
                // could drop the 413 on the floor.
                drain_best_effort(stream);
                error_outcome(413, "Payload Too Large", "request_too_large")
            }
            Err(RequestFailure::Malformed) => error_outcome(400, "Bad Request", "bad_request"),
        };
        write_response(stream, &outcome)?;
        self.served += 1;
        Ok(outcome)
    }

    fn route(&mut self, head: &RequestHead, now_ms: u64) -> WebUiOutcome {
        if !self.origin_allowed(head) {
            return error_outcome(403, "Forbidden", "origin_denied");
        }
        if head.method != "GET" {
            return error_outcome(405, "Method Not Allowed", "method_not_allowed");
        }
        let path = path_of(&head.target);
        if path.contains("..") || path.contains('\\') {
            return error_outcome(400, "Bad Request", "bad_request");
        }
        if !self.token.authorize(&head.target, now_ms) {
            // Same answer for a missing, foreign, reused, and expired token: the
            // body never echoes what was presented.
            return error_outcome(401, "Unauthorized", "unauthorized");
        }
        match path {
            "/" | "/index.html" => self.index_outcome(header(head, "origin")),
            "/api/actions" => self.actions_outcome(header(head, "origin")),
            _ => error_outcome(404, "Not Found", "not_found"),
        }
    }

    fn origin_allowed(&self, head: &RequestHead) -> bool {
        let Some(origin) = header(head, "origin") else {
            // No Origin header: a non-browser client, which is same-origin by
            // construction because the listener is loopback-only.
            return true;
        };
        if origin.eq_ignore_ascii_case("null") {
            return false;
        }
        match &self.config.allowed_origin {
            Some(allowed) => origin == allowed,
            None => match header(head, "host") {
                Some(host) => origin == format!("http://{host}"),
                None => false,
            },
        }
    }

    fn index_outcome(&self, request_origin: Option<&str>) -> WebUiOutcome {
        let snapshot = match self.actions_json() {
            Ok(json) => json,
            Err(_) => return error_outcome(500, "Internal Server Error", "internal_error"),
        };
        // Keep the snapshot inside the script element: no `</script>` can end it
        // early, and the renderer only ever uses textContent.
        let safe = snapshot.replace("</", "<\\/");
        let body = INDEX_HTML.replace(ACTION_PLACEHOLDER, &safe);
        if body.len() > MAX_RESPONSE_BYTES {
            return error_outcome(500, "Internal Server Error", "response_too_large");
        }
        WebUiOutcome {
            status: 200,
            reason: "OK",
            content_type: "text/html; charset=utf-8",
            body,
            allow_origin: self.matched_origin(request_origin),
        }
    }

    fn actions_outcome(&self, request_origin: Option<&str>) -> WebUiOutcome {
        let body = match self.actions_json() {
            Ok(body) => body,
            Err(_) => return error_outcome(500, "Internal Server Error", "internal_error"),
        };
        if body.len() > MAX_RESPONSE_BYTES {
            return error_outcome(500, "Internal Server Error", "response_too_large");
        }
        WebUiOutcome {
            status: 200,
            reason: "OK",
            content_type: "application/json; charset=utf-8",
            body,
            allow_origin: self.matched_origin(request_origin),
        }
    }

    fn matched_origin(&self, request_origin: Option<&str>) -> Option<String> {
        let allowed = self.config.allowed_origin.as_ref()?;
        match request_origin {
            Some(origin) if origin == allowed => Some(allowed.clone()),
            _ => None,
        }
    }
}

enum RequestFailure {
    TooLarge,
    Malformed,
}

struct RequestHead {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

fn read_head(stream: &mut TcpStream) -> std::result::Result<RequestHead, RequestFailure> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    loop {
        if buf.len() > MAX_REQUEST_BYTES {
            return Err(RequestFailure::TooLarge);
        }
        let n = stream.read(&mut chunk).map_err(|_| RequestFailure::Malformed)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if find_head_end(&buf).is_some() {
            break;
        }
    }
    let end = match find_head_end(&buf) {
        Some(end) => end,
        None if buf.len() > MAX_REQUEST_BYTES => return Err(RequestFailure::TooLarge),
        None => return Err(RequestFailure::Malformed),
    };
    parse_head(&buf[..end])
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn parse_head(bytes: &[u8]) -> std::result::Result<RequestHead, RequestFailure> {
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text.split("\r\n").filter(|line| !line.is_empty());
    let request_line = lines.next().ok_or(RequestFailure::Malformed)?;
    let mut parts = request_line.split(' ');
    let method = parts.next().ok_or(RequestFailure::Malformed)?;
    let target = parts.next().ok_or(RequestFailure::Malformed)?;
    let version = parts.next().ok_or(RequestFailure::Malformed)?;
    if parts.next().is_some()
        || method.is_empty()
        || target.is_empty()
        || !version.starts_with("HTTP/1.")
    {
        return Err(RequestFailure::Malformed);
    }
    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    Ok(RequestHead {
        method: method.to_string(),
        target: target.to_string(),
        headers,
    })
}

fn header<'a>(head: &'a RequestHead, name: &str) -> Option<&'a str> {
    head.headers
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

fn path_of(target: &str) -> &str {
    let end = target.find(['?', '#']).unwrap_or(target.len());
    &target[..end]
}

fn query_token(target: &str) -> Option<&str> {
    let (_, query) = target.split_once('?')?;
    let query = query.split('#').next().unwrap_or(query);
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix("token=") {
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

/// Length-agnostic, early-exit-free comparison (documented at
/// [`OneTimeToken::authorize`]).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {    let mut acc: usize = a.len() ^ b.len();
    for (i, byte) in a.iter().enumerate() {
        let other = b.get(i).copied().unwrap_or(0);
        acc |= usize::from(byte ^ other);
    }
    for byte in b.iter().skip(a.len()) {
        acc |= usize::from(*byte);
    }
    acc == 0
}

/// Consume a bounded amount of input so closing does not reset the connection
/// before a refusal has been read. Best effort: a timeout ends it.
fn drain_best_effort(stream: &mut TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
    let mut sink = [0u8; 1024];
    let mut total = 0usize;
    while total < 64 * 1024 {
        match stream.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn error_outcome(status: u16, reason: &'static str, code: &str) -> WebUiOutcome {
    WebUiOutcome {
        status,
        reason,
        content_type: "application/json; charset=utf-8",
        body: serde_json::json!({ "error": code }).to_string(),
        allow_origin: None,
    }
}

fn write_response(stream: &mut TcpStream, outcome: &WebUiOutcome) -> Result<()> {
    let mut head = String::with_capacity(256);
    head.push_str(&format!("HTTP/1.1 {} {}\r\n", outcome.status, outcome.reason));
    head.push_str(&format!("Content-Type: {}\r\n", outcome.content_type));
    head.push_str(&format!("Content-Length: {}\r\n", outcome.body.len()));
    head.push_str("Cache-Control: no-store\r\n");
    head.push_str("X-Content-Type-Options: nosniff\r\n");
    head.push_str("Referrer-Policy: no-referrer\r\n");
    head.push_str("Vary: Origin\r\n");
    head.push_str("Connection: close\r\n");
    if outcome.content_type.starts_with("text/html") {
        head.push_str(&format!("Content-Security-Policy: {HTML_CSP}\r\n"));
    }
    if let Some(origin) = &outcome.allow_origin {
        head.push_str(&format!("Access-Control-Allow-Origin: {origin}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).map_err(ZeroError::from)?;
    stream
        .write_all(outcome.body.as_bytes())
        .map_err(ZeroError::from)?;
    stream.flush().map_err(ZeroError::from)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn config() -> WebUiConfig {
        WebUiConfig::loopback(0)
    }

    fn action(id: &str) -> ActionRecord {
        ActionRecord::from_json(
            &serde_json::json!({
                "id": id,
                "title": format!("Open {id}"),
                "description": "test action for the local web UI",
                "category": "test",
                "aliases": [],
                "arguments": {"type": "object"},
                "capabilities": [],
                "mutating": false,
                "deterministic": true,
                "policy_class": "read",
                "approval": "never",
                "agent_invocable": true,
                "unattended": false,
                "idempotency": "none",
                "audit": {"redact_arguments": false},
                "implicit": false,
                "ui_control": true
            })
            .to_string(),
        )
        .expect("test action must validate")
    }

    fn token_value(ui: &LocalWebUi) -> String {
        ui.url()
            .split_once("token=")
            .expect("url carries the token")
            .1
            .to_string()
    }

    fn target_with_token(ui: &LocalWebUi) -> String {
        format!("/?token={}", token_value(ui))
    }

    /// Connect, send one request, let the server answer it, and return the raw
    /// response with the parsed outcome.
    fn fetch(ui: &mut LocalWebUi, target: &str, headers: &[(&str, &str)]) -> (WebUiOutcome, String) {
        let addr = ui.local_addr();
        let mut client = TcpStream::connect(addr).expect("connect to loopback listener");
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = format!("GET {target} HTTP/1.1\r\nHost: {addr}\r\n");
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("Connection: close\r\n\r\n");
        client.write_all(request.as_bytes()).unwrap();
        let outcome = ui.handle_once().expect("handle one connection");
        let mut raw = String::new();
        client.read_to_string(&mut raw).unwrap();
        (outcome, raw)
    }

    fn fetch_raw(ui: &mut LocalWebUi, request: &[u8]) -> (WebUiOutcome, String) {
        let mut client = TcpStream::connect(ui.local_addr()).expect("connect to loopback listener");
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.write_all(request).unwrap();
        let outcome = ui.handle_once().expect("handle one connection");
        let mut raw = String::new();
        client.read_to_string(&mut raw).unwrap();
        (outcome, raw)
    }

    #[test]
    fn every_non_loopback_bind_is_refused() {
        for bind in [
            "0.0.0.0:0",
            "0.0.0.0:8080",
            "[::]:0",
            "192.168.1.20:8080",
            "10.0.0.5:1",
            "8.8.8.8:53",
            "[::ffff:127.0.0.1]:80",
        ] {
            let addr: SocketAddr = bind.parse().unwrap();
            let config = WebUiConfig {
                bind: addr,
                token_ttl_ms: DEFAULT_TOKEN_TTL_MS,
                allowed_origin: None,
            };
            let err = config.validate().expect_err(bind);
            assert_eq!(err.code(), ErrorCode::PolicyDenied);
            assert_eq!(err.code().as_str(), "zero.pol.denied");
            assert!(err.message().contains("loopback"));
            assert!(LocalWebUi::start(config).is_err(), "{bind} must not bind");
        }
    }

    #[test]
    fn hostnames_are_refused_at_parse_time() {
        for host in ["example.com:8080", "localhost:8080", "zero.local:443"] {
            let err = parse_bind(host).expect_err(host);
            assert_eq!(err.code().as_str(), "zero.pol.denied");
        }
        assert_eq!(
            parse_bind("127.0.0.1:0").unwrap().ip().to_string(),
            "127.0.0.1"
        );
        assert_eq!(parse_bind("[::1]:0").unwrap().ip().to_string(), "::1");
    }

    #[test]
    fn wildcard_origins_are_refused() {
        for origin in ["*", "null", "http://*", "127.0.0.1:7777", "http://a.example/"] {
            let mut config = config();
            config.allowed_origin = Some(origin.to_string());
            let err = config.validate().expect_err(origin);
            assert_eq!(err.code(), ErrorCode::PolicyDenied, "{origin}");
        }
        let mut ok = config();
        ok.allowed_origin = Some("http://127.0.0.1:7777".into());
        ok.validate().unwrap();
    }

    #[test]
    fn loopback_binds_and_the_url_uses_the_ephemeral_port() {
        let ui = LocalWebUi::start(config()).unwrap();
        let addr = ui.local_addr();
        assert!(addr.ip().is_loopback());
        assert_ne!(addr.port(), 0, "port 0 must resolve to an ephemeral port");
        assert_eq!(ui.bind_url(), format!("http://127.0.0.1:{}/", addr.port()));
        assert!(ui.url().starts_with(&format!("http://127.0.0.1:{}/?token=", addr.port())));
        assert_eq!(ui.served(), 0);
    }

    #[test]
    fn the_token_opens_the_page_exactly_once() {
        let mut ui = LocalWebUi::start_with_actions(config(), vec![action("actions.list")]).unwrap();
        let target = target_with_token(&ui);
        let (first, raw) = fetch(&mut ui, &target, &[]);
        assert_eq!(first.status, 200);
        assert!(raw.starts_with("HTTP/1.1 200 OK\r\n"), "{raw}");
        assert!(first.body.contains("<!doctype html>"));
        assert!(first.body.contains("actions.list"));
        assert_eq!(ui.token_state(now_ms()), TokenState::Used);

        let (second, raw) = fetch(&mut ui, &target, &[]);
        assert_eq!(second.status, 401);
        assert!(raw.starts_with("HTTP/1.1 401 Unauthorized\r\n"), "{raw}");
        assert!(!second.body.contains("<!doctype html>"));
        assert_eq!(ui.served(), 2);
    }

    #[test]
    fn an_expired_or_foreign_token_is_refused() {
        let issued = 1_000;
        let mut expired = OneTimeToken::generate(issued, 500);
        let value = expired.value.clone();
        let target = format!("/?token={value}");
        assert!(!expired.authorize(&target, issued + 500), "expiry is inclusive");
        assert_eq!(expired.state(issued + 500), TokenState::Expired);

        // A refused attempt does not consume a live token.
        let mut fresh = OneTimeToken::generate(issued, 500);
        let fresh_target = format!("/?token={}", fresh.value);
        assert!(fresh.authorize(&fresh_target, issued + 499));
        assert!(!fresh.authorize(&fresh_target, issued + 499), "second use");
        assert_eq!(fresh.state(issued + 499), TokenState::Used);

        // A token from another instance is a foreign token.
        let mut mine = OneTimeToken::generate(issued, 10_000);
        let other = OneTimeToken::generate(issued, 10_000);
        let foreign_target = format!("/?token={}", other.value);
        assert!(!mine.authorize(&foreign_target, issued));
        assert_eq!(mine.state(issued), TokenState::Active);
        let own_target = format!("/?token={}", mine.value);
        assert!(mine.authorize(&own_target, issued));

        // A target without a token is refused.
        assert!(!mine.authorize("/api/actions", issued));
        assert!(!OneTimeToken::generate(issued, 10).authorize("/?token=", issued));
    }

    #[test]
    fn an_expired_wire_token_is_a_401() {
        let mut config = config();
        config.token_ttl_ms = 0;
        let mut ui = LocalWebUi::start(config).unwrap();
        let target = target_with_token(&ui);
        let (outcome, raw) = fetch(&mut ui, &target, &[]);
        assert_eq!(outcome.status, 401);
        assert!(raw.contains("401 Unauthorized"));
        assert!(!outcome.body.contains("<!doctype html>"));
        assert_eq!(ui.token_state(now_ms()), TokenState::Expired);
    }

    #[test]
    fn html_and_the_action_snapshot_are_served() {
        let actions = vec![action("actions.list"), action("mode.set")];
        let mut ui = LocalWebUi::start_with_actions(config(), actions).unwrap();
        let target = target_with_token(&ui);
        let (page, _) = fetch(&mut ui, &target, &[]);
        assert_eq!(page.status, 200);
        assert!(page.content_type.starts_with("text/html"));
        assert!(page.body.contains("actions.list"));
        assert!(page.body.contains("mode.set"));
        assert!(page.body.contains("id=\"zero-action-snapshot\""));
        // No external assets, no CDN, no telemetry.
        assert!(!page.body.contains("http://"));
        assert!(!page.body.contains("https://"));
        assert!(!page.body.contains("src="));
        assert!(!page.body.contains("<iframe"));

        let mut ui = LocalWebUi::start_with_actions(config(), vec![action("actions.list")]).unwrap();
        let target = format!("/api/actions?token={}", token_value(&ui));
        let (json, raw) = fetch(&mut ui, &target, &[]);
        assert_eq!(json.status, 200);
        assert!(raw.starts_with("HTTP/1.1 200 OK\r\n"), "{raw}");
        assert!(json.content_type.starts_with("application/json"));
        let parsed: serde_json::Value = serde_json::from_str(&json.body).unwrap();
        let list = parsed.as_array().expect("snapshot is an array");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["id"], "actions.list");
    }

    #[test]
    fn registry_text_cannot_end_the_snapshot_element() {
        let title = "</script><script>alert(1)</script>";
        let record = ActionRecord::from_json(
            &serde_json::json!({
                "id": "actions.evil",
                "title": title,
                "description": "attempts to close the JSON script element",
                "category": "test",
                "arguments": {"type": "object"},
                "mutating": false,
                "deterministic": true,
                "policy_class": "read",
                "approval": "never",
                "agent_invocable": false,
                "unattended": false,
                "idempotency": "none",
                "audit": {"redact_arguments": false},
                "implicit": false,
                "ui_control": true
            })
            .to_string(),
        )
        .unwrap();
        let mut ui = LocalWebUi::start_with_actions(config(), vec![record]).unwrap();
        let target = target_with_token(&ui);
        let (page, _) = fetch(&mut ui, &target, &[]);
        assert_eq!(page.status, 200);
        assert!(!page.body.contains("</script><script>alert(1)"));
        assert_eq!(
            page.body.matches("</script>").count(),
            2,
            "only the template's own two closing tags may remain"
        );
        assert!(page.body.contains("<\\/script>"));
    }

    #[test]
    fn only_the_two_paths_exist() {
        let mut ui = LocalWebUi::start(config()).unwrap();
        let target = format!("/etc/passwd?token={}", token_value(&ui));
        let (missing, _) = fetch(&mut ui, &target, &[]);
        assert_eq!(missing.status, 404);

        let mut ui = LocalWebUi::start(config()).unwrap();
        let traversal = format!("/../../docs/secrets.md?token={}", token_value(&ui));
        let (bad, _) = fetch(&mut ui, &traversal, &[]);
        assert_eq!(bad.status, 400);

        let mut ui = LocalWebUi::start(config()).unwrap();
        let mut client = TcpStream::connect(ui.local_addr()).unwrap();
        client
            .write_all(
                format!(
                    "POST /api/actions?token={} HTTP/1.1\r\nHost: x\r\n\r\n",
                    token_value(&ui)
                )
                .as_bytes(),
            )
            .unwrap();
        let outcome = ui.handle_once().unwrap();
        assert_eq!(outcome.status, 405);
        assert_eq!(
            ui.token_state(now_ms()),
            TokenState::Active,
            "a refused method must not spend the token"
        );
    }

    #[test]
    fn origin_rules_refuse_foreign_pages() {
        // Same-origin only: a cross-origin Origin is refused and does not spend
        // the token.
        let mut ui = LocalWebUi::start(config()).unwrap();
        let target = target_with_token(&ui);
        let (denied, _) = fetch(&mut ui, &target, &[("Origin", "http://evil.example")]);
        assert_eq!(denied.status, 403);
        assert_eq!(ui.token_state(now_ms()), TokenState::Active);
        let same_origin = format!("http://{}", ui.local_addr());
        let (same, _) = fetch(&mut ui, &target, &[("Origin", same_origin.as_str())]);
        assert_eq!(same.status, 200);

        // An explicit allowed origin: only that exact origin passes, and the
        // response echoes it instead of a wildcard.
        let mut config = config();
        config.allowed_origin = Some("http://127.0.0.1:7777".into());
        let mut ui = LocalWebUi::start(config).unwrap();
        let target = format!("/api/actions?token={}", token_value(&ui));
        let (denied, _) = fetch(&mut ui, &target, &[("Origin", "http://127.0.0.1:7778")]);
        assert_eq!(denied.status, 403);
        let (allowed, raw) = fetch(&mut ui, &target, &[("Origin", "http://127.0.0.1:7777")]);
        assert_eq!(allowed.status, 200);
        assert_eq!(
            allowed.allow_origin.as_deref(),
            Some("http://127.0.0.1:7777")
        );
        assert!(raw.contains("Access-Control-Allow-Origin: http://127.0.0.1:7777\r\n"));
        assert!(!raw.contains("Access-Control-Allow-Origin: *"));
    }

    #[test]
    fn oversized_requests_are_refused_without_spending_the_token() {
        let mut ui = LocalWebUi::start(config()).unwrap();
        let mut request = String::from("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n");
        while request.len() <= MAX_REQUEST_BYTES + 1024 {
            request.push_str("X-Padding: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        }
        let (too_large, raw) = fetch_raw(&mut ui, request.as_bytes());
        assert_eq!(too_large.status, 413);
        assert!(raw.contains("413 Payload Too Large"));
        assert_eq!(ui.token_state(now_ms()), TokenState::Active);

        let target = target_with_token(&ui);
        let (ok, _) = fetch(&mut ui, &target, &[]);
        assert_eq!(ok.status, 200);
    }

    #[test]
    fn shutdown_stops_the_loop() {
        let mut ui = LocalWebUi::start_with_actions(config(), vec![action("actions.list")]).unwrap();
        let addr = ui.local_addr();
        let target = target_with_token(&ui);
        let flag = ui.shutdown_flag();
        let stop = Arc::clone(&flag);
        let server = std::thread::spawn(move || ui.run_until(stop));

        let mut client = TcpStream::connect(addr).expect("connect while the loop runs");
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        client
            .write_all(
                format!("GET {target} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .unwrap();
        let mut raw = String::new();
        client.read_to_string(&mut raw).unwrap();
        assert!(raw.starts_with("HTTP/1.1 200 OK\r\n"), "{raw}");

        flag.store(true, Ordering::Relaxed);
        let served = server.join().expect("server thread").expect("loop result");
        assert_eq!(served, 1);
    }

    #[test]
    fn the_token_never_reaches_debug_or_a_log_safe_url() {
        let ui = LocalWebUi::start(config()).unwrap();
        let value = token_value(&ui);
        assert_eq!(value.len(), TOKEN_BYTES * 2);
        assert!(value.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(ui.url().contains(&value));
        assert!(!ui.bind_url().contains(&value));
        assert!(!format!("{ui:?}").contains(&value));
        assert!(!format!("{:?}", ui.token).contains(&value));
        assert!(format!("{:?}", ui.token).contains("<redacted>"));
        assert!(format!("{ui:?}").contains("bind_url"));

        // A refused request never echoes the token back.
        let mut ui = LocalWebUi::start(config()).unwrap();
        let presented = token_value(&ui);
        let (outcome, raw) = fetch(&mut ui, "/api/actions?token=deadbeef", &[]);
        assert_eq!(outcome.status, 401);
        assert!(!raw.contains(&presented));
        assert!(!outcome.body.contains("deadbeef"));
    }

    #[test]
    fn token_generation_uses_fresh_entropy_and_expiry_is_inclusive() {
        let a = OneTimeToken::generate(0, 10);
        let b = OneTimeToken::generate(0, 10);
        assert_ne!(a.value, b.value, "two tokens must not share a value");
        assert_eq!(a.issued_ms(), 0);
        assert_eq!(a.expires_ms(), 10);
        assert_eq!(a.state(9), TokenState::Active);
        assert_eq!(a.state(10), TokenState::Expired);
        assert!(!a.used());
        let mut a = a;
        let target = format!("/?token={}", a.value);
        a.invalidate();
        assert_eq!(a.state(0), TokenState::Used);
        assert!(!a.authorize(&target, 0));
    }
}
