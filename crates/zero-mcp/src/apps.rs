//! MCP apps and extension negotiation (T-MCP-06, MCP-11, MCP-12).
//!
//! Source: the MCP Apps extension `io.modelcontextprotocol/ui` and the
//! extensions framework for revision `2026-07-28`. This module implements the
//! host-side, transport-independent half of both:
//!
//! - [`UiResource`] accepts only `ui://` resource identifiers. `javascript:`,
//!   `data:`, `http:`, and `https:` app URIs never reach the renderer.
//! - [`AppFrame::render`] produces a host document that loads the app in a
//!   sandboxed iframe. Scripts run, but the iframe has an opaque origin and no
//!   top navigation, popups, forms, downloads, or modals. The app HTML is
//!   attribute-escaped inside `srcdoc`, so a hostile `"` or `</iframe>` cannot
//!   close the tag and escape into the host document.
//! - [`authorize`] is the host-side navigation gate. Top-level navigation,
//!   popups, and downloads are always refused. Subframe and form navigation is
//!   limited to an exact origin allowlist over `https`.
//! - [`negotiate`] tolerates unknown extensions: they are ignored. A required
//!   unknown extension is reported to the caller instead of failing the
//!   negotiation, and [`Negotiation::ensure_supported`] turns that report into
//!   `zero.fnd.unsupported` when the caller decides it is fatal.
//!
//! Enforcement here is policy and markup generation. A real browser is never
//! involved, so the sandbox and CSP are asserted as strings. Browser-level
//! conformance (including `frame-ancestors`, which browsers ignore in a
//! `<meta>` element) is deferred to T-MCP-11; see `docs/mcp.md`.

use reqwest::Url;
use serde_json::Value;
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::jsonrpc::protocol_error;

/// Scheme reserved for MCP app resources.
pub const UI_SCHEME: &str = "ui://";

/// Maximum accepted length of a `ui://` app URI.
pub const MAX_UI_URI_BYTES: usize = 2048;

/// Maximum accepted length of an extension identifier.
pub const MAX_EXTENSION_ID_BYTES: usize = 256;

/// The only iframe sandbox token this host grants.
///
/// Deliberately absent: `allow-same-origin` (the frame keeps an opaque
/// origin), `allow-top-navigation` and `allow-top-navigation-by-user-activation`
/// (no host navigation), `allow-popups` and
/// `allow-popups-to-escape-sandbox`, `allow-forms`, `allow-downloads`,
/// `allow-modals`, `allow-storage-access-by-user-activation`,
/// `allow-pointer-lock`, and `allow-presentation`.
pub const APP_SANDBOX: &str = "allow-scripts";

/// CSP applied to the app document.
///
/// `default-src 'none'` denies everything not named below. Inline scripts and
/// styles are allowed because an app is a single resource; `'unsafe-eval'` is
/// not, so `eval` and `new Function` stay blocked. There is no network
/// (`connect-src 'none'`), no nested frames, no plugins, no form submission,
/// no base URL rewriting, and no remote images: only `data:` images. The host
/// must also send this policy as a header when it serves the document from an
/// origin, because `frame-ancestors` is ignored in a `<meta>` element.
pub const APP_CSP: &str = "default-src 'none'; script-src 'unsafe-inline'; \
style-src 'unsafe-inline'; img-src data:; font-src 'none'; media-src 'none'; \
connect-src 'none'; frame-src 'none'; worker-src 'none'; object-src 'none'; \
manifest-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// Extension identifier for MCP Apps.
pub const UI_EXTENSION: &str = "io.modelcontextprotocol/ui";

/// Extension identifier for MCP Tasks.
pub const TASKS_EXTENSION_ID: &str = "io.modelcontextprotocol/tasks";

/// A validated `ui://` app resource identifier.
///
/// Accepted shape: `ui://<authority>[/<path>]`. The authority is required; the
/// path is optional. Userinfo, ports, queries, fragments, whitespace, control
/// characters, backslashes, percent-encoded separators, and `.`/`..` path
/// segments are rejected. The URI is treated as a cache key: one spelling maps
/// to one resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiResource {
    uri: String,
    host: String,
    path: String,
}

impl UiResource {
    /// Parse and validate a `ui://` app URI.
    ///
    /// `javascript:`, `data:`, `http:`, and `https:` URIs are rejected by the
    /// scheme check. Every failure is `zero.prv.protocol`.
    pub fn parse(uri: &str) -> Result<Self> {
        if uri.is_empty() {
            return Err(protocol_error("app URI must not be empty"));
        }
        if uri.len() > MAX_UI_URI_BYTES {
            return Err(protocol_error("app URI is longer than the accepted limit"));
        }
        if uri.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(protocol_error(
                "app URI must not contain whitespace or control characters",
            ));
        }
        // Check the raw spelling too: the URL parser normalises literal and
        // percent-encoded dot segments before `path()` can be inspected.
        let raw = uri.to_ascii_lowercase();
        if raw.contains('\\') || raw.contains("%2e") || raw.contains("%2f") || raw.contains("%5c") {
            return Err(protocol_error(
                "app URI must not contain backslashes or percent-encoded separators or dots",
            ));
        }
        if raw.contains("/./")
            || raw.ends_with("/.")
            || raw.contains("/../")
            || raw.ends_with("/..")
        {
            return Err(protocol_error(
                "app URI must not contain `.` or `..` path segments",
            ));
        }
        let parsed = Url::parse(uri)
            .map_err(|_| protocol_error("app URI must be an absolute `ui://` URI"))?;
        if parsed.scheme() != "ui" {
            return Err(protocol_error("app URI scheme must be `ui://`"));
        }
        let host = parsed.host_str().unwrap_or_default();
        if host.is_empty() || parsed.cannot_be_a_base() {
            return Err(protocol_error(
                "app URI must name an authority, as in `ui://<app>/<path>`",
            ));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(protocol_error("app URI must not contain userinfo"));
        }
        if parsed.port().is_some() {
            return Err(protocol_error("app URI must not contain a port"));
        }
        if parsed.query().is_some() {
            return Err(protocol_error("app URI must not contain a query"));
        }
        if parsed.fragment().is_some() {
            return Err(protocol_error("app URI must not contain a fragment"));
        }
        let path = parsed.path();
        if path.contains('\\') {
            return Err(protocol_error("app URI must not contain a backslash"));
        }
        let lowered = path.to_ascii_lowercase();
        if lowered.contains("%2e") || lowered.contains("%2f") || lowered.contains("%5c") {
            return Err(protocol_error(
                "app URI must not percent-encode path separators or dots",
            ));
        }
        if path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
        {
            return Err(protocol_error(
                "app URI must not contain `.` or `..` path segments",
            ));
        }
        Ok(Self {
            uri: parsed.to_string(),
            host: host.to_string(),
            path: path.to_string(),
        })
    }

    /// The canonical URI string.
    pub fn as_str(&self) -> &str {
        &self.uri
    }

    /// The authority (app name) part.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The path, beginning with `/`, or an empty string.
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl std::fmt::Display for UiResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.uri)
    }
}

/// A host-side frame for one app.
///
/// `html` is the complete host document, including the sandboxed `<iframe>`
/// whose `srcdoc` holds the escaped app HTML. `sandbox` and `csp` are exposed
/// separately so a host that serves the app from an origin can put the same
/// values on the element and the response header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppFrame {
    /// Host document containing the sandboxed iframe.
    pub html: String,
    /// The iframe `sandbox` attribute value ([`APP_SANDBOX`]).
    pub sandbox: String,
    /// The CSP value ([`APP_CSP`]).
    pub csp: String,
}

impl AppFrame {
    /// Render `html` (untrusted app content) into a sandboxed host document.
    ///
    /// The app HTML is escaped for an HTML attribute before being placed in
    /// `srcdoc`. Escaping covers `&`, `<`, `>`, `"`, and `'`, so the app cannot
    /// close the attribute, close the `<iframe>` element, or inject a new
    /// element into the host document.
    pub fn render(resource: &UiResource, html: impl AsRef<str>) -> Self {
        let payload = format!(
            "<meta http-equiv=\"Content-Security-Policy\" content=\"{APP_CSP}\">{}",
            html.as_ref()
        );
        let srcdoc = escape_html(&payload);
        let title = escape_html(resource.as_str());
        let html = format!(
            "<!doctype html><html><head><meta charset=\"utf-8\">\
<meta name=\"referrer\" content=\"no-referrer\"><title>{title}</title></head>\
<body><iframe sandbox=\"{APP_SANDBOX}\" referrerpolicy=\"no-referrer\" \
src=\"about:blank\" srcdoc=\"{srcdoc}\"></iframe></body></html>"
        );
        Self {
            html,
            sandbox: APP_SANDBOX.to_string(),
            csp: APP_CSP.to_string(),
        }
    }
}

/// Escape text for use in an HTML attribute or text node.
pub fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

/// How an app asked to navigate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavigationDisposition {
    /// Replace the host's top-level document.
    TopLevel,
    /// Navigate the app's own frame or a nested frame.
    Subframe,
    /// Open a new window.
    Popup,
    /// Submit a form.
    Form,
    /// Save a file.
    Download,
}

impl NavigationDisposition {
    /// Parse the wire spelling used by app messages.
    ///
    /// Accepts `top_level`/`top`/`toplevel`, `subframe`/`iframe`, `popup`,
    /// `form`, and `download`, case-insensitively.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "top_level" | "toplevel" | "top" => Some(Self::TopLevel),
            "subframe" | "iframe" => Some(Self::Subframe),
            "popup" => Some(Self::Popup),
            "form" => Some(Self::Form),
            "download" => Some(Self::Download),
            _ => None,
        }
    }

    /// The wire spelling for a disposition.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TopLevel => "top_level",
            Self::Subframe => "subframe",
            Self::Popup => "popup",
            Self::Form => "form",
            Self::Download => "download",
        }
    }
}

/// One navigation request from an app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationIntent {
    /// Absolute `https` URL, or one of the reserved frame targets.
    pub target: String,
    /// What the app wants to navigate.
    pub disposition: NavigationDisposition,
}

impl NavigationIntent {
    /// Build an intent.
    pub fn new(target: impl Into<String>, disposition: NavigationDisposition) -> Self {
        Self {
            target: target.into(),
            disposition,
        }
    }
}

/// Host navigation policy for app frames.
///
/// `allowed_app_origins` is an exact-origin allowlist. It must never contain
/// the host's own origin: a subframe or form navigation to the host is refused
/// unless the operator explicitly lists it. `allow_same_origin` permits
/// relative references (`/path`, `./path`, `../path`) that stay inside the app
/// frame; it is off by default, and protocol-relative `//host/path` is never
/// treated as same-origin.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NavigationPolicy {
    /// Origins an app may navigate a subframe or form to.
    pub allowed_app_origins: Vec<String>,
    /// Whether relative same-frame references are permitted.
    pub allow_same_origin: bool,
}

impl NavigationPolicy {
    /// Build a policy from a list of exact origins.
    pub fn new<I, S>(origins: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allowed_app_origins: origins.into_iter().map(Into::into).collect(),
            allow_same_origin: false,
        }
    }
}

fn denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PermissionDenied, message)
}

/// Authorize one navigation intent from an app frame.
///
/// Rules, in order:
///
/// 1. `TopLevel`, `Popup`, and `Download` are always refused.
/// 2. The reserved targets `_top`, `_parent`, and `_blank` are always refused.
/// 3. `_self` is accepted for `Subframe` and `Form`; it is a no-op inside the
///    frame.
/// 4. Otherwise the target must be an absolute `https` URL with a host and no
///    userinfo, and its origin must exactly match an entry in
///    `allowed_app_origins`. Ports are part of the origin, so a different port
///    is a different origin.
/// 5. A relative reference is accepted only when `allow_same_origin` is set.
///    An empty, whitespace-only, or control-character target is refused.
///
/// Refusals are `zero.pol.denied` and never echo the untrusted target.
pub fn authorize(policy: &NavigationPolicy, intent: &NavigationIntent) -> Result<()> {
    let target = intent.target.trim();
    if target.is_empty() {
        return Err(denied("app navigation target must not be empty"));
    }
    if target.chars().any(char::is_control) {
        return Err(denied(
            "app navigation target must not contain control characters",
        ));
    }
    match intent.disposition {
        NavigationDisposition::TopLevel => {
            Err(denied("top-level navigation from an app frame is blocked"))
        }
        NavigationDisposition::Popup => Err(denied("popup windows from an app frame are blocked")),
        NavigationDisposition::Download => Err(denied("downloads from an app frame are blocked")),
        NavigationDisposition::Subframe | NavigationDisposition::Form => {
            authorize_frame_navigation(policy, target)
        }
    }
}

fn authorize_frame_navigation(policy: &NavigationPolicy, target: &str) -> Result<()> {
    let lower = target.to_ascii_lowercase();
    if matches!(lower.as_str(), "_top" | "_parent" | "_blank") {
        return Err(denied(format!(
            "app navigation target `{lower}` is not allowed in a frame"
        )));
    }
    if lower == "_self" {
        return Ok(());
    }

    if is_relative_reference(target) {
        return if policy.allow_same_origin {
            Ok(())
        } else {
            Err(denied(
                "relative app navigation requires explicit same-origin approval",
            ))
        };
    }

    let parsed = Url::parse(target)
        .map_err(|_| denied("app navigation target must be an absolute https URL"))?;
    if parsed.scheme() != "https" {
        return Err(denied("app navigation must use https"));
    }
    if parsed.cannot_be_a_base() || parsed.host_str().is_none() {
        return Err(denied("app navigation target must name an https host"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(denied("app navigation target must not contain userinfo"));
    }

    if policy
        .allowed_app_origins
        .iter()
        .any(|allowed| origin_matches(allowed, &parsed))
    {
        Ok(())
    } else {
        Err(denied("app navigation origin is not allowed"))
    }
}

fn is_relative_reference(target: &str) -> bool {
    if target.starts_with('\\') {
        return false;
    }
    if target.starts_with("//") {
        return false;
    }
    target.starts_with('/') || target.starts_with("./") || target.starts_with("../")
}

fn origin_matches(allowed: &str, target: &Url) -> bool {
    let Ok(allowed) = Url::parse(allowed) else {
        return false;
    };
    allowed.scheme() == "https"
        && allowed.host_str().is_some()
        && allowed.username().is_empty()
        && allowed.password().is_none()
        && allowed.origin() == target.origin()
}

/// Message type an app sends for a navigation request.
pub const MESSAGE_NAVIGATE: &str = "navigate";
/// Message type an app sends to open a window; always refused.
pub const MESSAGE_OPEN_WINDOW: &str = "open_window";

/// Authorize a `postMessage` navigation request from an app.
///
/// Only `{"type":"navigate","frame":"self","target":...}` is considered. The
/// frame must be `self`: a request that names `parent`, `top`, or another
/// frame is refused. `open_window`, `window.open`, and every other message
/// type are refused or rejected. An omitted `disposition` defaults to
/// `subframe`; an omitted `frame` defaults to `self`. Unknown fields are
/// ignored, then the intent goes through [`authorize`].
pub fn authorize_message(policy: &NavigationPolicy, message: &Value) -> Result<()> {
    let object = message
        .as_object()
        .ok_or_else(|| protocol_error("app message must be a JSON object"))?;
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| protocol_error("app message is missing a string `type`"))?;
    match kind {
        MESSAGE_NAVIGATE => {}
        MESSAGE_OPEN_WINDOW | "window.open" => {
            return Err(denied("window.open from an app frame is blocked"));
        }
        _ => return Err(protocol_error("unsupported app message type")),
    }
    let frame = match object.get("frame") {
        None => "self",
        Some(Value::String(frame)) => frame.as_str(),
        Some(_) => return Err(protocol_error("app message `frame` must be a string")),
    };
    if frame != "self" {
        return Err(denied(
            "an app may only request navigation of its own frame",
        ));
    }
    let target = object
        .get("target")
        .and_then(Value::as_str)
        .ok_or_else(|| protocol_error("app navigation message is missing a string `target`"))?;
    let disposition = match object.get("disposition") {
        None => NavigationDisposition::Subframe,
        Some(Value::String(value)) => NavigationDisposition::parse(value)
            .ok_or_else(|| protocol_error("app message has an unknown `disposition`"))?,
        Some(_) => return Err(protocol_error("app message `disposition` must be a string")),
    };
    authorize(
        policy,
        &NavigationIntent {
            target: target.to_string(),
            disposition,
        },
    )
}

/// One extension advertised by the other side.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtensionOffer {
    /// Extension identifier in `{prefix}/{name}` form.
    pub id: String,
    /// Extension version; an empty string means the sender did not say.
    pub version: String,
    /// Whether the sender requires the extension for the exchange.
    pub required: bool,
    /// Opaque extension settings. Unknown fields are ignored.
    pub payload: Value,
}

impl ExtensionOffer {
    /// Build an offer.
    pub fn new(
        id: impl Into<String>,
        version: impl Into<String>,
        required: bool,
        payload: Value,
    ) -> Self {
        Self {
            id: id.into(),
            version: version.into(),
            required,
            payload,
        }
    }

    /// Parse one extension entry from capabilities or a discovery result.
    ///
    /// `id` is required and must be `{prefix}/{name}` with both segments
    /// non-empty and limited to ASCII letters, digits, `.`, `_`, and `-`.
    /// `version` is a string, a number, or absent; `required` is a boolean or
    /// absent; `payload` defaults to `null`. Any other unknown field is
    /// ignored. A malformed entry is `zero.prv.protocol`.
    pub fn from_value(value: &Value) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| protocol_error("extension offer must be a JSON object"))?;
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| protocol_error("extension offer is missing a string `id`"))?;
        if !valid_extension_id(id) {
            return Err(protocol_error(
                "extension `id` must be `{prefix}/{name}` with no whitespace",
            ));
        }
        let version = match object.get("version") {
            None | Some(Value::Null) => String::new(),
            Some(Value::String(version)) => version.clone(),
            Some(Value::Number(version)) => version.to_string(),
            Some(_) => {
                return Err(protocol_error(
                    "extension `version` must be a string or number",
                ))
            }
        };
        let required = match object.get("required") {
            None => false,
            Some(Value::Bool(required)) => *required,
            Some(_) => return Err(protocol_error("extension `required` must be a boolean")),
        };
        let payload = object.get("payload").cloned().unwrap_or(Value::Null);
        Ok(Self {
            id: id.to_string(),
            version,
            required,
            payload,
        })
    }
}

fn valid_extension_id(id: &str) -> bool {
    if id.is_empty() || id.len() > MAX_EXTENSION_ID_BYTES {
        return false;
    }
    let mut segments = id.split('/');
    let Some(prefix) = segments.next() else {
        return false;
    };
    let Some(name) = segments.next() else {
        return false;
    };
    if segments.next().is_some() || prefix.is_empty() || name.is_empty() {
        return false;
    }
    id.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
}

/// Outcome of extension negotiation.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Negotiation {
    /// Extensions both sides support, in the order offered.
    pub accepted: Vec<ExtensionOffer>,
    /// Optional extensions this host does not support, in the order offered.
    pub ignored: Vec<String>,
    /// Required extensions this host does not support, in offered order.
    pub unsupported_required: Vec<String>,
}

impl Negotiation {
    /// Whether every required extension was accepted.
    pub fn is_complete(&self) -> bool {
        self.unsupported_required.is_empty()
    }

    /// Turn an unsatisfied required extension into `zero.fnd.unsupported`.
    ///
    /// [`negotiate`] itself never fails: the caller decides whether a required
    /// unknown extension is fatal, which is the graceful-degradation rule.
    pub fn ensure_supported(&self) -> Result<()> {
        match self.unsupported_required.first() {
            Some(id) => Err(ZeroError::new(
                ErrorCode::Unsupported,
                format!("required MCP extension `{id}` is not supported"),
            )),
            None => Ok(()),
        }
    }
}

/// Negotiate extensions without failing on unknown ones.
///
/// Supported identifiers are accepted, optional unknown identifiers are
/// ignored, and required unknown identifiers are collected in
/// [`Negotiation::unsupported_required`] for the caller to act on. The first
/// offer of a given identifier wins; later duplicates are skipped. Nothing is
/// inferred from an extension's payload, so unknown payload fields are
/// harmless.
pub fn negotiate(supported: &[&str], offered: &[ExtensionOffer]) -> Negotiation {
    let mut negotiation = Negotiation::default();
    for offer in offered {
        if negotiation
            .accepted
            .iter()
            .any(|accepted| accepted.id == offer.id)
        {
            continue;
        }
        if supported.contains(&offer.id.as_str()) {
            negotiation.accepted.push(offer.clone());
        } else if offer.required {
            if !negotiation.unsupported_required.contains(&offer.id) {
                negotiation.unsupported_required.push(offer.id.clone());
            }
        } else if !negotiation.ignored.contains(&offer.id) {
            negotiation.ignored.push(offer.id.clone());
        }
    }
    negotiation
}

/// Parse extension entries and negotiate them.
///
/// A malformed entry is a protocol error, which makes the whole negotiation
/// fail. Unknown but well-formed entries are still tolerated.
pub fn negotiate_values(supported: &[&str], offered: &[Value]) -> Result<Negotiation> {
    let offers = offered
        .iter()
        .map(ExtensionOffer::from_value)
        .collect::<Result<Vec<_>>>()?;
    Ok(negotiate(supported, &offers))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn policy() -> NavigationPolicy {
        NavigationPolicy::new(["https://apps.example.com"])
    }

    #[test]
    fn ui_uri_accepts_authority_and_path() {
        let authority = UiResource::parse("ui://dashboard").unwrap();
        assert_eq!(authority.host(), "dashboard");
        assert_eq!(authority.path(), "");

        let path = UiResource::parse("ui://dashboard/view.html").unwrap();
        assert_eq!(path.host(), "dashboard");
        assert_eq!(path.path(), "/view.html");
        assert_eq!(path.to_string(), "ui://dashboard/view.html");
    }

    #[test]
    fn ui_uri_rejects_unsafe_and_ambiguous_shapes() {
        for uri in [
            "",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "http://app.example.com/view",
            "https://app.example.com/view",
            "file:///C:/view.html",
            "ui://",
            "ui:///view.html",
            "ui://user@app/view",
            "ui://app:8080/view",
            "ui://app/view?x=1",
            "ui://app/view#fragment",
            "ui://app/../secret",
            "ui://app/%2e%2e/secret",
            "ui://app\\view",
            "ui://app/ view",
        ] {
            assert!(
                UiResource::parse(uri).is_err(),
                "`{uri}` must not parse as an app resource"
            );
        }
    }

    #[test]
    fn hostile_html_is_escaped_inside_srcdoc() {
        let resource = UiResource::parse("ui://hostile/view.html").unwrap();
        let frame = AppFrame::render(
            &resource,
            "</iframe><script>parent.location='https://evil.example'</script>\" onload=\"x",
        );
        assert_eq!(frame.html.matches("</iframe>").count(), 1);
        assert!(!frame.html.contains("</iframe><script>"));
        assert!(!frame.html.contains("\" onload=\"x"));
        assert!(frame.html.contains("&lt;/iframe&gt;&lt;script&gt;"));
        assert!(frame.html.contains("&quot; onload=&quot;x"));
        assert!(!frame.html.contains("<script>parent.location"));

        assert_eq!(
            escape_html("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&#39;f"
        );
    }

    #[test]
    fn sandbox_denies_same_origin_and_powers() {
        let frame = AppFrame::render(&UiResource::parse("ui://app").unwrap(), "<p>hi</p>");
        assert_eq!(frame.sandbox, "allow-scripts");
        assert!(frame.html.contains("sandbox=\"allow-scripts\""));
        for token in [
            "allow-same-origin",
            "allow-top-navigation",
            "allow-popups",
            "allow-forms",
            "allow-downloads",
            "allow-modals",
            "allow-storage-access-by-user-activation",
        ] {
            assert!(
                !frame.sandbox.contains(token),
                "sandbox must not grant `{token}`"
            );
            assert!(
                !frame.html.contains(token),
                "host document must not grant `{token}`"
            );
        }
    }

    #[test]
    fn csp_is_strict() {
        let frame = AppFrame::render(&UiResource::parse("ui://app").unwrap(), "<p>hi</p>");
        assert_eq!(frame.csp, APP_CSP);
        for directive in [
            "default-src 'none'",
            "script-src 'unsafe-inline'",
            "style-src 'unsafe-inline'",
            "img-src data:",
            "connect-src 'none'",
            "frame-src 'none'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "form-action 'none'",
            "object-src 'none'",
        ] {
            assert!(
                frame.csp.contains(directive),
                "CSP is missing `{directive}`"
            );
        }
        assert!(!frame.csp.contains("unsafe-eval"));
        assert!(!frame.csp.contains("https:"));
        assert!(!frame.csp.contains('*'));
    }

    #[test]
    fn top_level_popup_and_download_are_blocked() {
        for disposition in [
            NavigationDisposition::TopLevel,
            NavigationDisposition::Popup,
            NavigationDisposition::Download,
        ] {
            let intent = NavigationIntent::new("https://apps.example.com/view", disposition);
            let error = authorize(&policy(), &intent).unwrap_err();
            assert_eq!(error.code(), ErrorCode::PermissionDenied);
        }
    }

    #[test]
    fn dangerous_schemes_are_refused() {
        for target in [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "file:///C:/secret.txt",
            "http://apps.example.com/view",
            "ftp://apps.example.com/view",
            "blob:https://apps.example.com/id",
        ] {
            let intent = NavigationIntent::new(target, NavigationDisposition::Subframe);
            let error = authorize(&policy(), &intent).unwrap_err();
            assert_eq!(
                error.code(),
                ErrorCode::PermissionDenied,
                "`{target}` must be refused"
            );
        }
    }

    #[test]
    fn origin_mismatch_is_refused() {
        for target in [
            "https://evil.example.com/view",
            "https://apps.example.com.evil.example/view",
            "https://zero.example.com/view",
            "https://apps.example.com:8443/view",
            "https://user:pass@apps.example.com/view",
            "https://apps.example.com@evil.example.com/view",
        ] {
            let intent = NavigationIntent::new(target, NavigationDisposition::Subframe);
            assert!(
                authorize(&policy(), &intent).is_err(),
                "`{target}` must not match the allowed origin"
            );
        }
    }

    #[test]
    fn allowed_subframe_and_form_are_accepted() {
        let subframe = NavigationIntent::new(
            "https://apps.example.com/frame",
            NavigationDisposition::Subframe,
        );
        authorize(&policy(), &subframe).unwrap();

        let form = NavigationIntent::new(
            "https://apps.example.com/submit",
            NavigationDisposition::Form,
        );
        authorize(&policy(), &form).unwrap();

        let same_origin_self = NavigationIntent::new("_self", NavigationDisposition::Subframe);
        authorize(&policy(), &same_origin_self).unwrap();

        let empty = NavigationPolicy::default();
        assert!(authorize(&empty, &subframe).is_err());
    }

    #[test]
    fn reserved_targets_are_refused() {
        for target in ["_top", "_parent", "_blank", " _TOP "] {
            let intent = NavigationIntent::new(target, NavigationDisposition::Subframe);
            let error = authorize(&policy(), &intent).unwrap_err();
            assert_eq!(
                error.code(),
                ErrorCode::PermissionDenied,
                "`{target}` must be refused"
            );
        }
    }

    #[test]
    fn relative_navigation_requires_same_origin_approval() {
        let relative = NavigationIntent::new("/frame", NavigationDisposition::Subframe);
        assert!(authorize(&policy(), &relative).is_err());

        let mut open = policy();
        open.allow_same_origin = true;
        authorize(&open, &relative).unwrap();
        authorize(
            &open,
            &NavigationIntent::new("./frame", NavigationDisposition::Subframe),
        )
        .unwrap();

        let protocol_relative =
            NavigationIntent::new("//evil.example/frame", NavigationDisposition::Subframe);
        assert!(authorize(&open, &protocol_relative).is_err());

        let traversal = NavigationIntent::new("../../etc/passwd", NavigationDisposition::Subframe);
        assert!(authorize(&policy(), &traversal).is_err());
    }

    #[test]
    fn post_message_only_allows_same_frame_navigation() {
        authorize_message(
            &policy(),
            &json!({
                "type": "navigate",
                "frame": "self",
                "target": "https://apps.example.com/view",
                "disposition": "subframe",
                "extra": {"ignored": true}
            }),
        )
        .unwrap();

        for message in [
            json!({"type": "open_window", "frame": "self", "target": "https://apps.example.com"}),
            json!({"type": "window.open", "frame": "self", "target": "https://apps.example.com"}),
            json!({"type": "navigate", "frame": "parent", "target": "https://apps.example.com"}),
            json!({"type": "navigate", "frame": "top", "target": "https://apps.example.com"}),
            json!({"type": "navigate", "frame": "self", "target": "javascript:alert(1)"}),
            json!({"type": "navigate", "frame": "self", "target": "https://apps.example.com", "disposition": "top_level"}),
            json!({"type": "navigate", "frame": "self", "target": "https://apps.example.com", "disposition": "unknown"}),
            json!({"type": "navigate", "frame": 7, "target": "https://apps.example.com"}),
            json!({"type": "navigate", "frame": "self"}),
            json!({"type": "call_tool", "frame": "self"}),
            json!("not an object"),
        ] {
            assert!(
                authorize_message(&policy(), &message).is_err(),
                "message `{message}` must be refused"
            );
        }
    }

    #[test]
    fn unknown_extensions_are_ignored() {
        let offered = vec![
            ExtensionOffer::new(
                UI_EXTENSION,
                "2026-01-26",
                false,
                json!({"mimeTypes": ["text/html;profile=mcp-app"]}),
            ),
            ExtensionOffer::new("com.example/unknown", "1", false, json!({"future": true})),
        ];
        let negotiation = negotiate(&[UI_EXTENSION], &offered);
        assert_eq!(negotiation.accepted.len(), 1);
        assert_eq!(negotiation.accepted[0].id, UI_EXTENSION);
        assert_eq!(negotiation.ignored, vec!["com.example/unknown"]);
        assert!(negotiation.is_complete());
        negotiation.ensure_supported().unwrap();
    }

    #[test]
    fn required_unknown_extension_is_reported_but_not_fatal() {
        let offered = vec![ExtensionOffer::new(
            "com.example/managed-auth",
            "1",
            true,
            json!({}),
        )];
        let negotiation = negotiate(&[], &offered);
        assert!(negotiation.accepted.is_empty());
        assert!(negotiation.ignored.is_empty());
        assert_eq!(
            negotiation.unsupported_required,
            vec!["com.example/managed-auth"]
        );
        assert!(!negotiation.is_complete());

        let error = negotiation.ensure_supported().unwrap_err();
        assert_eq!(error.code(), ErrorCode::Unsupported);
        assert_eq!(error.code().as_str(), "zero.fnd.unsupported");
    }

    #[test]
    fn unknown_payload_fields_are_ignored() {
        let value = json!({
            "id": "io.modelcontextprotocol/ui",
            "version": 2,
            "required": false,
            "payload": {"futureField": {"nested": [1, 2, 3]}},
            "futureTopLevelField": true
        });
        let offer = ExtensionOffer::from_value(&value).unwrap();
        assert_eq!(offer.id, UI_EXTENSION);
        assert_eq!(offer.version, "2");
        assert!(!offer.required);
        assert_eq!(offer.payload, json!({"futureField": {"nested": [1, 2, 3]}}));

        let negotiation = negotiate_values(&[UI_EXTENSION], &[value]).unwrap();
        assert_eq!(negotiation.accepted.len(), 1);
    }

    #[test]
    fn malformed_extension_entries_are_rejected() {
        for value in [
            json!("not an object"),
            json!({}),
            json!({"id": 7}),
            json!({"id": "no-slash"}),
            json!({"id": "/name"}),
            json!({"id": "prefix/"}),
            json!({"id": "a/b/c"}),
            json!({"id": "io.modelcontextprotocol/ui", "required": "yes"}),
            json!({"id": "io.modelcontextprotocol/ui", "version": {}}),
        ] {
            let error = ExtensionOffer::from_value(&value).unwrap_err();
            assert_eq!(error.code(), ErrorCode::ProviderProtocol);
        }
        assert!(negotiate_values(&[UI_EXTENSION], &[json!({"id": 7})]).is_err());
    }

    #[test]
    fn duplicate_offers_keep_the_first() {
        let offered = vec![
            ExtensionOffer::new(UI_EXTENSION, "1", false, json!({})),
            ExtensionOffer::new(UI_EXTENSION, "2", false, json!({})),
        ];
        let negotiation = negotiate(&[UI_EXTENSION], &offered);
        assert_eq!(negotiation.accepted.len(), 1);
        assert_eq!(negotiation.accepted[0].version, "1");
        assert!(negotiation.ignored.is_empty());
    }
}
