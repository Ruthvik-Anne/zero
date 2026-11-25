//! Browser automation over the DevTools protocol (WEB-15, T-WEB-08).
//!
//! [`BrowserSession`] drives a Chrome DevTools Protocol (CDP) browser through a
//! narrow [`CdpTransport`] seam. The session owns the policy: request ids,
//! egress checks, timeouts, result caps, and destination confinement. The
//! transport owns the socket and the byte transfer.
//!
//! The production WebSocket transport is deferred. That transport will carry
//! `{"id": n, "method": ..., "params": ...}` frames over a loopback-only
//! DevTools endpoint and feed responses and events back through the same
//! trait. Until then callers supply their own transport, and every test in this
//! module uses a scripted one, so no test opens a browser or a socket.
//!
//! Choices worth knowing:
//!
//! - **Click** locates the node with `Runtime.evaluate` (which also scrolls it
//!   into view and returns the centre of its bounding box), then sends a real
//!   `Input.dispatchMouseEvent` press and release. Using trusted input events
//!   avoids the `isTrusted == false` difference of a synthetic DOM `.click()`,
//!   and a missing node is a typed not-found error before any input is sent.
//! - **Typing** focuses the node with `Runtime.evaluate` and then uses
//!   `Input.insertText`, which inserts text without synthesising key events.
//! - **Navigation** validates the URL with [`EgressGuard::check_url`] before
//!   `Page.navigate`, then waits for `Page.loadEventFired` with a bounded poll.
//! - **Downloads** validate the URL (and every reported redirect hop) with the
//!   egress guard, confine the destination to a configured root, refuse
//!   overwrites with `create_new`, and enforce a size cap. The actual byte
//!   transfer is the transport's job; the default implementation returns
//!   `zero.fnd.unsupported`.
//!
//! Every action is typed: CDP error objects become `zero.prv.protocol`, a
//! missing node is `zero.fnd.not_found`, an expired wait is `zero.fnd.timeout`,
//! and every cap is `zero.fnd.limit_exceeded`. Polling loops are bounded by a
//! deadline and a hard probe ceiling; nothing here can spin forever.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::egress::{EgressGuard, PinnedDestination, Resolver, SystemResolver};

/// Default bound for the navigation load-event wait (30 s).
pub const DEFAULT_BROWSER_TIMEOUT_MS: u64 = 30_000;
/// Default decoded screenshot ceiling (8 MiB).
pub const DEFAULT_MAX_SCREENSHOT_BYTES: usize = 8 * 1024 * 1024;
/// Default JSON result ceiling for [`BrowserSession::evaluate`] (256 KiB).
pub const DEFAULT_MAX_EVALUATE_BYTES: usize = 256 * 1024;
/// Default download ceiling (64 MiB).
pub const DEFAULT_MAX_DOWNLOAD_BYTES: usize = 64 * 1024 * 1024;
/// Default pause between polls for load events and selectors.
pub const DEFAULT_POLL_INTERVAL_MS: u64 = 10;
/// Maximum characters kept from an untrusted CDP error message.
pub const MAX_CDP_ERROR_CHARS: usize = 200;
/// Hard ceiling on poll iterations, independent of the wall clock.
pub const MAX_POLL_PROBES: usize = 1_000;

/// CDP method that signals a completed page load.
const LOAD_EVENT: &str = "Page.loadEventFired";

fn denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyDenied, message)
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn unavailable(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Unavailable, message)
}

fn timeout(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Timeout, message)
}

fn limit(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

fn corrupt(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Corrupt, message)
}

fn protocol(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::ProviderProtocol, message)
}

/// One DevTools event delivered between responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdpEvent {
    /// CDP method name, for example `Page.loadEventFired`.
    pub method: String,
    /// Event parameters as sent by the browser.
    pub params: Value,
}

/// Bytes obtained by [`CdpTransport::download`] plus the redirect chain.
///
/// The session re-checks every hop in `redirects` with
/// [`EgressGuard::check_redirect`] after the transfer. A transport should also
/// check live redirects *before* following them; this list is the
/// defence-in-depth check the scripted seam can exercise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdpDownload {
    /// Downloaded body.
    pub bytes: Vec<u8>,
    /// Redirect targets in the order they were followed.
    pub redirects: Vec<String>,
}

/// The seam between [`BrowserSession`] and a real CDP connection.
///
/// The transport is synchronous. Every `call` must return the full response
/// envelope (`id` plus one of `result` or `error`); the session assigns the
/// id and rejects a response that does not echo it. A transport must apply its
/// own socket read/write deadline because the session cannot interrupt a
/// blocking call.
///
/// `drain_events` is drained by the navigation wait and by tests. Events are
/// independent of response framing, so a `Page.loadEventFired` that arrives
/// before the response to `Page.navigate` is still consumed correctly.
pub trait CdpTransport: Send + Sync {
    /// Send one command and return the CDP response envelope.
    fn call(&self, method: &str, params: Value) -> Result<Value>;

    /// Remove and return every event queued since the last drain.
    fn drain_events(&self) -> Vec<CdpEvent> {
        Vec::new()
    }

    /// Send one command with the session-assigned request id.
    ///
    /// The default forwards to [`Self::call`] and is suitable for transports
    /// that do not need to place the id on the wire. A WebSocket transport
    /// overrides this method so the id appears in the JSON frame, and the
    /// session still validates the echoed id.
    fn call_with_id(&self, id: u64, method: &str, params: Value) -> Result<Value> {
        let _ = id;
        self.call(method, params)
    }

    /// Transfer the body of an already validated destination.
    ///
    /// The default refuses because the sealed session has no byte source. The
    /// real transport will either drive the browser's download behaviour or
    /// perform a fetch pinned to [`PinnedDestination::addresses`].
    fn download(&self, destination: &PinnedDestination) -> Result<CdpDownload> {
        let _ = destination;
        Err(unavailable(
            "this CDP transport has no download source; the live transport is deferred",
        ))
    }
}

/// Configuration for [`BrowserSession::connect`].
#[derive(Debug, Clone)]
pub struct BrowserConfig<R = SystemResolver> {
    /// Egress guard applied to every navigation and download.
    pub egress: EgressGuard<R>,
    /// Deadline for the navigation load-event wait.
    pub default_timeout_ms: u64,
    /// Decoded screenshot ceiling.
    pub max_screenshot_bytes: usize,
}

impl<R: Resolver> BrowserConfig<R> {
    /// Build a configuration with the documented defaults for the optional
    /// caps; the session-level builders replace them.
    pub fn new(
        egress: EgressGuard<R>,
        default_timeout_ms: u64,
        max_screenshot_bytes: usize,
    ) -> Self {
        Self {
            egress,
            default_timeout_ms,
            max_screenshot_bytes,
        }
    }
}

/// A policy-enforcing browser automation session.
///
/// `T` is the transport; `R` is the resolver used by the egress guard, so
/// tests can script DNS without opening a socket.
pub struct BrowserSession<T, R = SystemResolver> {
    transport: T,
    egress: EgressGuard<R>,
    default_timeout_ms: u64,
    max_screenshot_bytes: usize,
    max_evaluate_bytes: usize,
    max_download_bytes: usize,
    poll_interval_ms: u64,
    download_root: Option<PathBuf>,
    next_id: u64,
    closed: bool,
}

impl<T: CdpTransport, R: Resolver> BrowserSession<T, R> {
    /// Open a session over `transport`.
    pub fn connect(transport: T, config: BrowserConfig<R>) -> Self {
        Self {
            transport,
            egress: config.egress,
            default_timeout_ms: config.default_timeout_ms,
            max_screenshot_bytes: config.max_screenshot_bytes,
            max_evaluate_bytes: DEFAULT_MAX_EVALUATE_BYTES,
            max_download_bytes: DEFAULT_MAX_DOWNLOAD_BYTES,
            poll_interval_ms: DEFAULT_POLL_INTERVAL_MS,
            download_root: None,
            next_id: 1,
            closed: false,
        }
    }

    /// Replace the pause between polls. `0` polls without sleeping, which the
    /// scripted tests use to keep the suite free of real waits.
    pub fn with_poll_interval_ms(mut self, poll_interval_ms: u64) -> Self {
        self.poll_interval_ms = poll_interval_ms;
        self
    }

    /// Replace the evaluate result ceiling.
    pub fn with_max_evaluate_bytes(mut self, max_evaluate_bytes: usize) -> Self {
        self.max_evaluate_bytes = max_evaluate_bytes;
        self
    }

    /// Replace the download ceiling.
    pub fn with_max_download_bytes(mut self, max_download_bytes: usize) -> Self {
        self.max_download_bytes = max_download_bytes;
        self
    }

    /// Set the root every download destination must stay under.
    ///
    /// Without a root, [`Self::download`] is refused. The root must already
    /// exist; it is canonicalized on first use.
    pub fn with_download_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.download_root = Some(root.into());
        self
    }

    /// Navigate and wait for the load event.
    ///
    /// The URL passes [`EgressGuard::check_url`] before `Page.navigate`, so a
    /// metadata, loopback, private, or non-HTTP(S) target is refused without a
    /// CDP call. Returns the canonical URL sent to the browser. A navigation
    /// that CDP reports through `errorText` is `zero.fnd.unavailable`; a load
    /// event that does not arrive before the deadline is `zero.fnd.timeout`.
    ///
    /// The browser follows redirects internally. A production transport must
    /// intercept them (CDP `Fetch` or `Network` events) and re-check each hop
    /// with [`EgressGuard::check_redirect`]; this synchronous seam only sees
    /// the requested URL.
    pub fn navigate(&mut self, url: &str) -> Result<String> {
        self.ensure_open()?;
        let destination = self.egress.check_url(url)?;
        let target = destination.url().to_string();
        let response = self.dispatch("Page.navigate", json!({ "url": target }))?;
        if let Some(error_text) = response.get("errorText").and_then(Value::as_str) {
            return Err(unavailable(format!(
                "browser navigation failed: {}",
                truncate_untrusted(error_text, MAX_CDP_ERROR_CHARS)
            )));
        }
        self.wait_for_load()?;
        Ok(target)
    }

    /// Click the first node matching `selector`.
    ///
    /// `Runtime.evaluate` locates the node, scrolls it to the centre, and
    /// returns the centre of its bounding box. A missing node is
    /// `zero.fnd.not_found`; a node whose coordinates are missing or not finite
    /// is `zero.prv.protocol`. The press and release use
    /// `Input.dispatchMouseEvent`, so the page sees trusted input.
    pub fn click(&mut self, selector: &str) -> Result<()> {
        self.ensure_open()?;
        let expression = click_expression(selector);
        let payload = self.dispatch("Runtime.evaluate", evaluate_params(&expression))?;
        let value = evaluated_value(&payload)?;
        if value.is_null() {
            return Err(ZeroError::new(
                ErrorCode::NotFound,
                "browser click target was not found",
            ));
        }
        let x = value
            .get("x")
            .and_then(Value::as_f64)
            .ok_or_else(|| protocol("click locator returned no x coordinate"))?;
        let y = value
            .get("y")
            .and_then(Value::as_f64)
            .ok_or_else(|| protocol("click locator returned no y coordinate"))?;
        if !x.is_finite() || !y.is_finite() {
            return Err(protocol("click locator returned a non-finite coordinate"));
        }
        self.dispatch(
            "Input.dispatchMouseEvent",
            mouse_params("mousePressed", x, y),
        )?;
        self.dispatch(
            "Input.dispatchMouseEvent",
            mouse_params("mouseReleased", x, y),
        )?;
        Ok(())
    }

    /// Focus `selector` and insert `text`.
    ///
    /// The focus step uses `Runtime.evaluate`; a missing node is
    /// `zero.fnd.not_found`. Text insertion uses `Input.insertText`, which does
    /// not fire per-character key events.
    pub fn type_text(&mut self, selector: &str, text: &str) -> Result<()> {
        self.ensure_open()?;
        let expression = focus_expression(selector);
        let payload = self.dispatch("Runtime.evaluate", evaluate_params(&expression))?;
        match evaluated_value(&payload)? {
            Value::Bool(true) => {}
            Value::Bool(false) | Value::Null => {
                return Err(ZeroError::new(
                    ErrorCode::NotFound,
                    "browser typing target was not found",
                ));
            }
            _ => return Err(protocol("focus returned a non-boolean value")),
        }
        self.dispatch("Input.insertText", json!({ "text": text }))?;
        Ok(())
    }

    /// Poll until `selector` matches a node.
    ///
    /// `timeout_ms` is the budget; `0` uses the session's default timeout. The
    /// poll sleeps for the configured interval between probes, and is also
    /// bounded by [`MAX_POLL_PROBES`]. Timeout is `zero.fnd.timeout`.
    pub fn wait_for(&mut self, selector: &str, timeout_ms: u64) -> Result<()> {
        self.ensure_open()?;
        let budget_ms = if timeout_ms == 0 {
            self.default_timeout_ms
        } else {
            timeout_ms
        };
        let budget = Duration::from_millis(budget_ms);
        let expression = wait_expression(selector);
        let start = Instant::now();
        let mut probes = 0usize;
        loop {
            let payload = self.dispatch("Runtime.evaluate", evaluate_params(&expression))?;
            match evaluated_value(&payload)? {
                Value::Bool(true) => return Ok(()),
                Value::Bool(false) | Value::Null => {}
                _ => {
                    return Err(protocol(
                        "wait_for returned a non-boolean querySelector result",
                    ))
                }
            }
            probes += 1;
            if start.elapsed() >= budget {
                return Err(timeout(format!(
                    "browser selector did not appear within {budget_ms} ms"
                )));
            }
            if probes >= MAX_POLL_PROBES {
                return Err(timeout(
                    "browser selector poll reached the probe ceiling before the deadline",
                ));
            }
            if self.poll_interval_ms > 0 {
                std::thread::sleep(Duration::from_millis(self.poll_interval_ms));
            }
        }
    }

    /// Evaluate an expression and return the remote object's JSON value.
    ///
    /// Results are requested with `returnByValue` and bounded to
    /// [`Self::with_max_evaluate_bytes`]. The expression and the serialized
    /// result are scanned for configured secrets; a match is
    /// `zero.pol.denied` and the secret is never echoed. An expression that
    /// yields `undefined` returns `Null`.
    pub fn evaluate(&mut self, expression: &str) -> Result<Value> {
        self.ensure_open()?;
        self.egress
            .assert_no_secrets(expression, &[])
            .map_err(|_| {
                denied("refusing browser evaluate: a configured secret appears in the expression")
            })?;
        let payload = self.dispatch("Runtime.evaluate", evaluate_params(expression))?;
        let encoded = serde_json::to_vec(&payload)?;
        if encoded.len() > self.max_evaluate_bytes {
            return Err(limit(format!(
                "browser evaluate result is {} bytes, limit is {}",
                encoded.len(),
                self.max_evaluate_bytes
            )));
        }
        self.egress
            .assert_no_secrets(&String::from_utf8_lossy(&encoded), &[])
            .map_err(|_| {
                denied(
                    "refusing browser evaluate result: a configured secret appears in the output",
                )
            })?;
        evaluated_value(&payload)
    }

    /// Capture a PNG screenshot and return the decoded bytes.
    ///
    /// The base64 payload is refused before decoding when it is clearly larger
    /// than the cap, and the decoded bytes are refused when they exceed
    /// [`BrowserConfig::max_screenshot_bytes`]. Invalid base64 is
    /// `zero.fnd.corrupt`, not a partial image.
    pub fn screenshot(&mut self) -> Result<Vec<u8>> {
        self.ensure_open()?;
        let payload = self.dispatch("Page.captureScreenshot", json!({ "format": "png" }))?;
        let data = payload
            .get("data")
            .and_then(Value::as_str)
            .ok_or_else(|| protocol("Page.captureScreenshot returned no data"))?;
        // Every four encoded bytes carry at most three decoded bytes. Refuse
        // before allocating a decoded buffer for an oversized answer.
        let encoded_cap = self
            .max_screenshot_bytes
            .saturating_mul(4)
            .saturating_div(3)
            .saturating_add(8);
        if data.len() > encoded_cap {
            return Err(limit(format!(
                "browser screenshot payload is {} bytes, limit is {} decoded bytes",
                data.len(),
                self.max_screenshot_bytes
            )));
        }
        let bytes = STANDARD
            .decode(data)
            .map_err(|_| corrupt("Page.captureScreenshot returned invalid base64"))?;
        if bytes.len() > self.max_screenshot_bytes {
            return Err(limit(format!(
                "browser screenshot is {} bytes, limit is {}",
                bytes.len(),
                self.max_screenshot_bytes
            )));
        }
        Ok(bytes)
    }

    /// Download `url` to `dest` under the configured download root.
    ///
    /// The URL is checked by [`EgressGuard::check_url`] before the transport is
    /// called, and every hop in [`CdpDownload::redirects`] is re-checked. The
    /// body must fit [`Self::with_max_download_bytes`]. `dest` must be a
    /// relative path made only of normal components: absolute paths, drive or
    /// UNC prefixes, `.` and `..` are refused, as is an existing file. Parent
    /// directories are created one component at a time and a symbolic link on
    /// the way is refused. The file is opened with `create_new`, so a race
    /// cannot overwrite it either.
    pub fn download(&mut self, url: &str, dest: &Path) -> Result<PathBuf> {
        self.ensure_open()?;
        let root = self
            .download_root
            .as_ref()
            .ok_or_else(|| denied("no browser download root is configured"))?;
        let mut pinned = self.egress.check_url(url)?;
        let payload = self.transport.download(&pinned)?;
        for hop in &payload.redirects {
            pinned = self.egress.check_redirect(&pinned, hop)?;
        }
        if payload.bytes.len() > self.max_download_bytes {
            return Err(limit(format!(
                "browser download is {} bytes, limit is {}",
                payload.bytes.len(),
                self.max_download_bytes
            )));
        }
        write_under_root(root, dest, &payload.bytes)
    }

    /// Close the browser and refuse further actions.
    ///
    /// `close` is idempotent. A transport error from `Browser.close` is
    /// returned, but the session is still marked closed so a failed teardown
    /// cannot leave actions running against a half-closed browser.
    pub fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        let result = self.dispatch("Browser.close", json!({}));
        self.closed = true;
        result.map(|_| ())
    }

    fn ensure_open(&self) -> Result<()> {
        if self.closed {
            return Err(unavailable("the browser session is closed"));
        }
        Ok(())
    }

    fn wait_for_load(&mut self) -> Result<()> {
        let budget = Duration::from_millis(self.default_timeout_ms);
        let start = Instant::now();
        let mut probes = 0usize;
        loop {
            for event in self.transport.drain_events() {
                if event.method == LOAD_EVENT {
                    return Ok(());
                }
            }
            if start.elapsed() >= budget {
                return Err(timeout(
                    "browser did not report Page.loadEventFired before the timeout",
                ));
            }
            probes += 1;
            if probes >= MAX_POLL_PROBES {
                return Err(timeout(
                    "browser load wait reached the probe ceiling before the deadline",
                ));
            }
            if self.poll_interval_ms > 0 {
                std::thread::sleep(Duration::from_millis(self.poll_interval_ms));
            }
        }
    }

    fn dispatch(&mut self, method: &str, params: Value) -> Result<Value> {
        self.ensure_open()?;
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| protocol("CDP request id space exhausted"))?;
        let response = self.transport.call_with_id(id, method, params)?;
        let response_id = response.get("id").and_then(Value::as_u64);
        match response_id {
            Some(actual) if actual == id => {}
            Some(actual) => {
                return Err(protocol(format!(
                    "CDP response id {actual} does not match request id {id}"
                )));
            }
            None => return Err(protocol("CDP response has no integer id")),
        }
        if let Some(error) = response.get("error") {
            if !error.is_null() {
                return Err(cdp_error(error));
            }
        }
        Ok(response.get("result").cloned().unwrap_or(Value::Null))
    }
}

fn cdp_error(error: &Value) -> ZeroError {
    let code = error.get("code").and_then(Value::as_i64);
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("no message");
    let message = truncate_untrusted(message, MAX_CDP_ERROR_CHARS);
    match code {
        Some(code) => protocol(format!("CDP error {code}: {message}")),
        None => protocol(format!("CDP error: {message}")),
    }
}

fn truncate_untrusted(text: &str, limit: usize) -> String {
    let mut kept = String::new();
    let mut truncated = false;
    for (count, ch) in text.chars().enumerate() {
        if count >= limit {
            truncated = true;
            break;
        }
        kept.push(if ch.is_control() { ' ' } else { ch });
    }
    if truncated {
        kept.push_str("...");
    }
    kept
}

fn evaluate_params(expression: &str) -> Value {
    json!({ "expression": expression, "returnByValue": true })
}

fn evaluated_value(payload: &Value) -> Result<Value> {
    let remote = payload
        .get("result")
        .ok_or_else(|| protocol("Runtime.evaluate response has no result object"))?;
    Ok(remote.get("value").cloned().unwrap_or(Value::Null))
}

fn mouse_params(kind: &str, x: f64, y: f64) -> Value {
    json!({
        "type": kind,
        "x": x,
        "y": y,
        "button": "left",
        "clickCount": 1,
    })
}

fn selector_literal(selector: &str) -> String {
    Value::String(selector.to_string()).to_string()
}

fn click_expression(selector: &str) -> String {
    let selector = selector_literal(selector);
    format!(
        "(() => {{ const el = document.querySelector({selector}); if (!el) return null; \
         el.scrollIntoView({{ block: 'center', inline: 'center' }}); \
         const rect = el.getBoundingClientRect(); \
         return {{ x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 }}; }})()"
    )
}

fn focus_expression(selector: &str) -> String {
    let selector = selector_literal(selector);
    format!(
        "(() => {{ const el = document.querySelector({selector}); \
         if (!el) return false; el.focus(); return true; }})()"
    )
}

fn wait_expression(selector: &str) -> String {
    let selector = selector_literal(selector);
    format!("document.querySelector({selector}) !== null")
}

fn write_under_root(root: &Path, dest: &Path, bytes: &[u8]) -> Result<PathBuf> {
    if dest.as_os_str().is_empty() {
        return Err(invalid("browser download destination is empty"));
    }
    if dest.is_absolute() {
        return Err(denied(
            "browser download destination must be relative to the download root",
        ));
    }
    let mut parts = Vec::new();
    for component in dest.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_os_string()),
            _ => {
                return Err(denied(
                    "browser download destination contains an absolute, drive, or parent component",
                ));
            }
        }
    }
    if parts.is_empty() {
        return Err(invalid("browser download destination is empty"));
    }

    let root = root
        .canonicalize()
        .map_err(|error| denied(format!("browser download root is unusable: {error}")))?;
    let mut current = root.clone();
    for part in &parts[..parts.len() - 1] {
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(denied(
                        "browser download path crosses a symbolic link; refusing to write through it",
                    ));
                }
                if !metadata.is_dir() {
                    return Err(denied("browser download path component is not a directory"));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|error| {
                    ZeroError::new(
                        ErrorCode::Io,
                        format!("could not create download directory: {error}"),
                    )
                })?;
            }
            Err(error) => {
                return Err(ZeroError::new(
                    ErrorCode::Io,
                    format!("could not inspect the download path: {error}"),
                ));
            }
        }
    }

    let path = current.join(&parts[parts.len() - 1]);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            return Err(ZeroError::new(
                ErrorCode::AlreadyExists,
                "browser download destination already exists",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(ZeroError::new(
                ErrorCode::Io,
                format!("could not inspect the download destination: {error}"),
            ));
        }
    }

    let parent = path
        .parent()
        .ok_or_else(|| denied("browser download destination has no parent"))?;
    let canonical_parent = parent.canonicalize().map_err(|error| {
        ZeroError::new(
            ErrorCode::Io,
            format!("could not resolve the download destination: {error}"),
        )
    })?;
    if !canonical_parent.starts_with(&root) {
        return Err(denied(
            "browser download destination escapes the download root",
        ));
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                ZeroError::new(
                    ErrorCode::AlreadyExists,
                    "browser download destination already exists",
                )
            } else {
                ZeroError::new(
                    ErrorCode::Io,
                    format!("could not create the download destination: {error}"),
                )
            }
        })?;
    if let Err(error) = file.write_all(bytes) {
        drop(file);
        let _ = fs::remove_file(&path);
        return Err(ZeroError::new(
            ErrorCode::Io,
            format!("could not write the download: {error}"),
        ));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};

    use crate::egress::NetworkPolicy;

    const PUBLIC_V4: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
    const PNG: &[u8] = b"\x89PNG\r\n\x1a\nzero";

    #[derive(Debug, Clone, Default)]
    struct ScriptedResolver;

    impl ScriptedResolver {
        fn new() -> Self {
            Self
        }
    }

    impl Resolver for ScriptedResolver {
        fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<IpAddr>> {
            Ok(vec![IpAddr::V4(PUBLIC_V4)])
        }
    }

    #[derive(Debug, Clone)]
    enum Reply {
        Result(Value),
        Error { code: i64, message: String },
        WrongId,
        MissingId,
    }

    #[derive(Default)]
    struct Inner {
        calls: Mutex<Vec<(String, Value)>>,
        replies: Mutex<VecDeque<Reply>>,
        fallback: Mutex<Option<Reply>>,
        events: Mutex<VecDeque<CdpEvent>>,
        downloads: Mutex<VecDeque<CdpDownload>>,
        download_calls: Mutex<Vec<String>>,
    }

    #[derive(Clone, Default)]
    struct ScriptedTransport {
        inner: Arc<Inner>,
    }

    impl ScriptedTransport {
        fn new() -> Self {
            Self::default()
        }

        fn push(&self, reply: Reply) {
            self.inner.replies.lock().unwrap().push_back(reply);
        }

        fn set_fallback(&self, reply: Reply) {
            *self.inner.fallback.lock().unwrap() = Some(reply);
        }

        fn push_event(&self, event: CdpEvent) {
            self.inner.events.lock().unwrap().push_back(event);
        }

        fn push_download(&self, download: CdpDownload) {
            self.inner.downloads.lock().unwrap().push_back(download);
        }

        fn calls(&self) -> Vec<(String, Value)> {
            self.inner.calls.lock().unwrap().clone()
        }

        fn download_calls(&self) -> Vec<String> {
            self.inner.download_calls.lock().unwrap().clone()
        }

        fn load_event() -> CdpEvent {
            CdpEvent {
                method: "Page.loadEventFired".to_string(),
                params: json!({ "timestamp": 1.0 }),
            }
        }
    }

    impl CdpTransport for ScriptedTransport {
        fn call(&self, method: &str, params: Value) -> Result<Value> {
            self.call_with_id(0, method, params)
        }

        fn drain_events(&self) -> Vec<CdpEvent> {
            self.inner.events.lock().unwrap().drain(..).collect()
        }

        fn call_with_id(&self, id: u64, method: &str, params: Value) -> Result<Value> {
            self.inner
                .calls
                .lock()
                .unwrap()
                .push((method.to_string(), params));
            let reply = self
                .inner
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .or_else(|| self.inner.fallback.lock().unwrap().clone())
                .ok_or_else(|| {
                    ZeroError::new(ErrorCode::Internal, "the scripted transport has no reply")
                })?;
            Ok(match reply {
                Reply::Result(result) => json!({ "id": id, "result": result }),
                Reply::Error { code, message } => {
                    json!({ "id": id, "error": { "code": code, "message": message } })
                }
                Reply::WrongId => json!({ "id": id + 1, "result": {} }),
                Reply::MissingId => json!({ "result": {} }),
            })
        }

        fn download(&self, destination: &PinnedDestination) -> Result<CdpDownload> {
            self.inner
                .download_calls
                .lock()
                .unwrap()
                .push(destination.url().to_string());
            self.inner
                .downloads
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| {
                    ZeroError::new(
                        ErrorCode::Internal,
                        "the scripted transport has no download",
                    )
                })
        }
    }

    fn session(
        transport: ScriptedTransport,
        policy: NetworkPolicy,
    ) -> BrowserSession<ScriptedTransport, ScriptedResolver> {
        BrowserSession::connect(
            transport,
            BrowserConfig {
                egress: EgressGuard::new(policy, ScriptedResolver::new()),
                default_timeout_ms: 50,
                max_screenshot_bytes: 4_096,
            },
        )
        .with_poll_interval_ms(0)
    }

    fn clicked(x: f64, y: f64) -> Reply {
        Reply::Result(json!({
            "result": { "type": "object", "value": { "x": x, "y": y } }
        }))
    }

    fn boolean(value: bool) -> Reply {
        Reply::Result(json!({ "result": { "type": "boolean", "value": value } }))
    }

    #[test]
    fn scripted_flow_runs_the_documented_cdp_sequence() {
        let transport = ScriptedTransport::new();
        transport.push_event(ScriptedTransport::load_event());
        transport.push(Reply::Result(json!({ "frameId": "F1", "loaderId": "L1" })));
        transport.push(clicked(12.5, 24.0));
        transport.push(Reply::Result(json!({})));
        transport.push(Reply::Result(json!({})));
        transport.push(boolean(true));
        transport.push(Reply::Result(json!({})));
        transport.push(boolean(true));
        transport.push(Reply::Result(json!({ "data": STANDARD.encode(PNG) })));

        let mut session = session(transport.clone(), NetworkPolicy::Restricted);
        assert_eq!(
            session.navigate("https://example.com/start").unwrap(),
            "https://example.com/start"
        );
        session.click("#go").unwrap();
        session.type_text("#name", "hello").unwrap();
        session.wait_for("#done", 50).unwrap();
        assert_eq!(session.screenshot().unwrap(), PNG);

        let calls = transport.calls();
        let methods: Vec<&str> = calls.iter().map(|(method, _)| method.as_str()).collect();
        assert_eq!(
            methods,
            [
                "Page.navigate",
                "Runtime.evaluate",
                "Input.dispatchMouseEvent",
                "Input.dispatchMouseEvent",
                "Runtime.evaluate",
                "Input.insertText",
                "Runtime.evaluate",
                "Page.captureScreenshot",
            ]
        );
        assert_eq!(calls[0].1, json!({ "url": "https://example.com/start" }));
        assert_eq!(
            calls[1].1,
            json!({
                "expression": "(() => { const el = document.querySelector(\"#go\"); if (!el) return null; el.scrollIntoView({ block: 'center', inline: 'center' }); const rect = el.getBoundingClientRect(); return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 }; })()",
                "returnByValue": true
            })
        );
        assert_eq!(
            calls[2].1,
            json!({ "type": "mousePressed", "x": 12.5, "y": 24.0, "button": "left", "clickCount": 1 })
        );
        assert_eq!(
            calls[3].1,
            json!({ "type": "mouseReleased", "x": 12.5, "y": 24.0, "button": "left", "clickCount": 1 })
        );
        assert_eq!(
            calls[4].1,
            json!({
                "expression": "(() => { const el = document.querySelector(\"#name\"); if (!el) return false; el.focus(); return true; })()",
                "returnByValue": true
            })
        );
        assert_eq!(calls[5].1, json!({ "text": "hello" }));
        assert_eq!(
            calls[6].1,
            json!({
                "expression": "document.querySelector(\"#done\") !== null",
                "returnByValue": true
            })
        );
        assert_eq!(calls[7].1, json!({ "format": "png" }));
    }

    #[test]
    fn wrong_response_id_is_a_protocol_error() {
        let transport = ScriptedTransport::new();
        transport.push(Reply::WrongId);
        let mut session = session(transport.clone(), NetworkPolicy::Restricted);
        let error = session.navigate("https://example.com/").unwrap_err();
        assert_eq!(error.code(), ErrorCode::ProviderProtocol);
        assert!(
            error.message().contains("does not match"),
            "{}",
            error.message()
        );
        assert_eq!(transport.calls().len(), 1);
    }

    #[test]
    fn response_without_an_integer_id_is_a_protocol_error() {
        let transport = ScriptedTransport::new();
        transport.push(Reply::MissingId);
        let mut session = session(transport, NetworkPolicy::Restricted);
        let error = session.click("#x").unwrap_err();
        assert_eq!(error.code(), ErrorCode::ProviderProtocol);
        assert!(
            error.message().contains("no integer id"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn cdp_error_object_maps_to_provider_protocol() {
        let transport = ScriptedTransport::new();
        transport.push(Reply::Error {
            code: -32601,
            message: "'Foo.bar' wasn't found".to_string(),
        });
        let mut session = session(transport, NetworkPolicy::Restricted);
        let error = session.click("#x").unwrap_err();
        assert_eq!(error.code(), ErrorCode::ProviderProtocol);
        assert!(error.message().contains("-32601"), "{}", error.message());
        assert!(error.message().contains("Foo.bar"), "{}", error.message());
    }

    #[test]
    fn cdp_error_message_is_truncated_and_stripped() {
        let transport = ScriptedTransport::new();
        transport.push(Reply::Error {
            code: -32000,
            message: format!("line\n{}", "x".repeat(1_000)),
        });
        let mut session = session(transport, NetworkPolicy::Restricted);
        let error = session.click("#x").unwrap_err();
        assert_eq!(error.code(), ErrorCode::ProviderProtocol);
        assert!(!error.message().contains('\n'), "{}", error.message());
        assert!(
            error.message().len() < MAX_CDP_ERROR_CHARS + 40,
            "{}",
            error.message()
        );
        assert!(error.message().ends_with("..."), "{}", error.message());
    }

    #[test]
    fn click_on_a_missing_node_is_not_found() {
        let transport = ScriptedTransport::new();
        transport.push(Reply::Result(json!({
            "result": { "type": "object", "subtype": "null", "value": null }
        })));
        let mut session = session(transport.clone(), NetworkPolicy::Restricted);
        let error = session.click("#missing").unwrap_err();
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert_eq!(transport.calls().len(), 1);
    }

    #[test]
    fn typing_into_a_missing_node_is_not_found() {
        let transport = ScriptedTransport::new();
        transport.push(boolean(false));
        let mut session = session(transport.clone(), NetworkPolicy::Restricted);
        let error = session.type_text("#missing", "hello").unwrap_err();
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert_eq!(transport.calls().len(), 1);
    }

    #[test]
    fn wait_for_times_out() {
        let transport = ScriptedTransport::new();
        transport.set_fallback(boolean(false));
        let mut session = session(transport.clone(), NetworkPolicy::Restricted);
        let error = session.wait_for("#never", 1).unwrap_err();
        assert_eq!(error.code(), ErrorCode::Timeout);
        assert!(!transport.calls().is_empty());
        assert!(transport.calls().len() <= MAX_POLL_PROBES);
    }

    #[test]
    fn oversized_screenshot_is_refused() {
        let transport = ScriptedTransport::new();
        transport.push(Reply::Result(json!({
            "data": STANDARD.encode([0u8; 32])
        })));
        let mut session = BrowserSession::connect(
            transport.clone(),
            BrowserConfig {
                egress: EgressGuard::new(NetworkPolicy::Restricted, ScriptedResolver::new()),
                default_timeout_ms: 50,
                max_screenshot_bytes: 8,
            },
        )
        .with_poll_interval_ms(0);
        let error = session.screenshot().unwrap_err();
        assert_eq!(error.code(), ErrorCode::LimitExceeded);
        assert_eq!(transport.calls().len(), 1);
    }

    #[test]
    fn evaluate_oversize_is_refused() {
        let transport = ScriptedTransport::new();
        transport.push(Reply::Result(json!({
            "result": { "type": "string", "value": "x".repeat(128) }
        })));
        let mut session = session(transport, NetworkPolicy::Restricted).with_max_evaluate_bytes(16);
        let error = session.evaluate("1 + 1").unwrap_err();
        assert_eq!(error.code(), ErrorCode::LimitExceeded);
        assert!(
            error.message().contains("limit is 16"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn evaluate_refuses_configured_secrets_in_the_expression_and_result() {
        let transport = ScriptedTransport::new();
        transport.push(Reply::Result(json!({
            "result": { "type": "string", "value": "token sk-test-secret" }
        })));
        let egress = EgressGuard::new(NetworkPolicy::Restricted, ScriptedResolver::new())
            .with_secrets(["sk-test-secret"]);
        let mut session = BrowserSession::connect(
            transport.clone(),
            BrowserConfig {
                egress,
                default_timeout_ms: 50,
                max_screenshot_bytes: 4_096,
            },
        )
        .with_poll_interval_ms(0);

        let error = session.evaluate("fetch('/?k=sk-test-secret')").unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(!error.message().contains("sk-test-secret"));
        assert!(transport.calls().is_empty());

        let error = session.evaluate("document.cookie").unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(!error.message().contains("sk-test-secret"));
        assert_eq!(transport.calls().len(), 1);
    }

    #[test]
    fn navigate_refuses_restricted_destinations_before_any_cdp_call() {
        let transport = ScriptedTransport::new();
        let mut session = session(transport.clone(), NetworkPolicy::Restricted);
        for url in [
            "http://169.254.169.254/latest/meta-data/",
            "http://[fd00:ec2::254]/",
            "http://127.0.0.1:9222/json",
            "http://10.0.0.1/",
            "http://192.168.1.10/",
            "file:///etc/passwd",
        ] {
            let error = session.navigate(url).unwrap_err();
            assert_eq!(error.code(), ErrorCode::PolicyDenied, "{url}");
        }
        assert!(transport.calls().is_empty());
    }

    #[test]
    fn download_refuses_restricted_destinations_before_any_transfer() {
        let transport = ScriptedTransport::new();
        let root = tempfile::tempdir().unwrap();
        let mut session =
            session(transport.clone(), NetworkPolicy::Restricted).with_download_root(root.path());
        for url in [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1/secret",
            "http://10.1.2.3/file",
        ] {
            let error = session.download(url, Path::new("out.bin")).unwrap_err();
            assert_eq!(error.code(), ErrorCode::PolicyDenied, "{url}");
        }
        assert!(transport.calls().is_empty());
        assert!(transport.download_calls().is_empty());
        assert!(!root.path().join("out.bin").exists());
    }

    #[test]
    fn download_redirects_are_rechecked() {
        let transport = ScriptedTransport::new();
        transport.push_download(CdpDownload {
            bytes: b"payload".to_vec(),
            redirects: vec!["http://169.254.169.254/latest/meta-data/".to_string()],
        });
        let root = tempfile::tempdir().unwrap();
        let mut session =
            session(transport.clone(), NetworkPolicy::Restricted).with_download_root(root.path());
        let error = session
            .download("https://public.example/file", Path::new("out.bin"))
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert_eq!(
            transport.download_calls(),
            ["https://public.example/file".to_string()]
        );
        assert!(!root.path().join("out.bin").exists());
    }

    #[test]
    fn download_refuses_parent_and_absolute_destinations() {
        let transport = ScriptedTransport::new();
        transport.push_download(CdpDownload {
            bytes: b"payload".to_vec(),
            redirects: Vec::new(),
        });
        transport.push_download(CdpDownload {
            bytes: b"payload".to_vec(),
            redirects: Vec::new(),
        });
        let root = tempfile::tempdir().unwrap();
        let mut session =
            session(transport, NetworkPolicy::Restricted).with_download_root(root.path());
        for dest in [Path::new("../escape.bin"), Path::new("/etc/passwd")] {
            let error = session
                .download("https://public.example/file", dest)
                .unwrap_err();
            assert_eq!(error.code(), ErrorCode::PolicyDenied, "{dest:?}");
        }
        assert!(!root.path().join("escape.bin").exists());
    }

    #[test]
    fn download_refuses_to_overwrite() {
        let transport = ScriptedTransport::new();
        transport.push_download(CdpDownload {
            bytes: b"new".to_vec(),
            redirects: Vec::new(),
        });
        let root = tempfile::tempdir().unwrap();
        let existing = root.path().join("out.bin");
        fs::write(&existing, b"old").unwrap();
        let mut session =
            session(transport, NetworkPolicy::Restricted).with_download_root(root.path());
        let error = session
            .download("https://public.example/file", Path::new("out.bin"))
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::AlreadyExists);
        assert_eq!(fs::read(&existing).unwrap(), b"old");
    }

    #[test]
    fn download_enforces_the_size_cap() {
        let transport = ScriptedTransport::new();
        transport.push_download(CdpDownload {
            bytes: vec![0u8; 32],
            redirects: Vec::new(),
        });
        let root = tempfile::tempdir().unwrap();
        let mut session = session(transport, NetworkPolicy::Restricted)
            .with_download_root(root.path())
            .with_max_download_bytes(8);
        let error = session
            .download("https://public.example/file", Path::new("out.bin"))
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::LimitExceeded);
        assert!(!root.path().join("out.bin").exists());
    }

    #[test]
    fn download_writes_under_the_configured_root() {
        let transport = ScriptedTransport::new();
        transport.push_download(CdpDownload {
            bytes: b"zero-browser".to_vec(),
            redirects: Vec::new(),
        });
        let root = tempfile::tempdir().unwrap();
        let mut session =
            session(transport.clone(), NetworkPolicy::Restricted).with_download_root(root.path());
        let path = session
            .download("https://public.example/file", Path::new("nested/out.bin"))
            .unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"zero-browser");
        assert!(path.starts_with(root.path().canonicalize().unwrap()));
        assert_eq!(
            transport.download_calls(),
            ["https://public.example/file".to_string()]
        );
    }

    #[test]
    fn load_event_before_the_response_does_not_mis_map_ids() {
        let transport = ScriptedTransport::new();
        transport.push_event(ScriptedTransport::load_event());
        transport.push(Reply::Result(json!({ "frameId": "F1", "loaderId": "L1" })));
        transport.push(clicked(7.0, 8.0));
        transport.push(Reply::Result(json!({})));
        transport.push(Reply::Result(json!({})));
        let mut session = session(transport.clone(), NetworkPolicy::Restricted);

        session.navigate("https://example.com/").unwrap();
        session.click("#go").unwrap();

        let calls = transport.calls();
        let methods: Vec<&str> = calls.iter().map(|(method, _)| method.as_str()).collect();
        assert_eq!(
            methods,
            [
                "Page.navigate",
                "Runtime.evaluate",
                "Input.dispatchMouseEvent",
                "Input.dispatchMouseEvent",
            ]
        );
        assert_eq!(calls[2].1["x"], json!(7.0));
        assert_eq!(calls[2].1["y"], json!(8.0));
        assert!(transport.drain_events().is_empty());
    }

    #[test]
    fn closed_session_refuses_actions_and_close_is_idempotent() {
        let transport = ScriptedTransport::new();
        transport.push(Reply::Result(json!({})));
        let mut session = session(transport.clone(), NetworkPolicy::Restricted);
        session.close().unwrap();
        session.close().unwrap();
        assert_eq!(transport.calls().len(), 1);
        assert_eq!(transport.calls()[0].0, "Browser.close");

        let error = session.navigate("https://example.com/").unwrap_err();
        assert_eq!(error.code(), ErrorCode::Unavailable);
        let error = session.screenshot().unwrap_err();
        assert_eq!(error.code(), ErrorCode::Unavailable);
        assert_eq!(transport.calls().len(), 1);
    }

    #[test]
    fn navigate_surfaces_cdp_error_text() {
        let transport = ScriptedTransport::new();
        transport.push(Reply::Result(json!({
            "frameId": "F1",
            "errorText": "net::ERR_NAME_NOT_RESOLVED"
        })));
        let mut session = session(transport, NetworkPolicy::Restricted);
        let error = session.navigate("https://example.com/").unwrap_err();
        assert_eq!(error.code(), ErrorCode::Unavailable);
        assert!(error.message().contains("ERR_NAME_NOT_RESOLVED"));
    }

    #[test]
    fn selector_literals_are_json_escaped() {
        let expression = click_expression("\"onclick=\"alert(1)");
        assert!(
            expression.contains("document.querySelector(\"\\\"onclick=\\\"alert(1)\")"),
            "{expression}"
        );
    }
}
