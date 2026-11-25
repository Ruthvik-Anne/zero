//! Android share intake and routing (T-AND-05; AND-05, AND-07, AND-09, AND-10,
//! AND-11, MM-12).
//!
//! A shared image, text, file, or link arrives from the Android share sheet,
//! becomes one bounded attachment, and is delivered into a session over the
//! mesh. This module is the phone-side policy for that path: intake and
//! validation ([`SharePayload`], [`ShareIntent`]), the sheet the user picks from
//! ([`share_sheet`]), and the delivered report ([`ShareReport`]).
//!
//! # Intake
//!
//! [`ShareKind`] is closed: image, text, file, link. [`SharePayload`] carries
//! the bytes (bounded per kind), the mime type, an optional name, and, for a
//! link, the URL. [`SharePayload::validate`] enforces the rules before anything
//! reaches a sink:
//!
//! - The mime type must exist (`type/subtype`) and must match the kind: an
//!   image is `image/*`, text is `text/*` or JSON/XML/YAML, a file is any valid
//!   type, and a link is `text/uri-list` or `text/plain`.
//! - Bytes are non-empty and capped ([`MAX_SHARE_IMAGE_BYTES`],
//!   [`MAX_SHARE_TEXT_BYTES`], [`MAX_SHARE_FILE_BYTES`]). A link carries no
//!   bytes.
//! - A link must be `http` or `https`, must have a host, must be at most
//!   [`MAX_SHARE_URL_CHARS`], and must not carry userinfo (`user:pass@host`).
//!   Error messages never echo a refused URL.
//! - A name, when present, is non-blank, free of control characters, and at
//!   most [`MAX_SHARE_NAME_CHARS`] characters.
//!
//! [`ShareAttachment`] is the validated, delivery-ready form. Its id is derived
//! from the kind, mime, name, bytes, and URL, so the same share always has the
//! same id and a changed byte changes it.
//!
//! # The sheet
//!
//! [`share_sheet`] turns the host's sessions into at most
//! [`MAX_SHEET_ENTRIES`] rows. The list is deterministic: rows are ordered by
//! newest activity then id, duplicates collapse, malformed ids are skipped, and
//! labels are flattened and bounded. Each row targets one session; the mesh
//! chooses direct or relay at delivery time.
//!
//! # Routing and reporting
//!
//! [`ShareSink`] is the one transport seam: `deliver(session, attachment)`
//! returns a [`DeliveryReceipt`] naming the session, the attachment, the path
//! that was used ([`Route`]), when the session received it, and the bytes
//! moved. [`ShareRouter`] holds a sink and, for the direct and relay targets,
//! the session those targets apply to. [`share`] validates the intent and the
//! target, delivers, checks the receipt, and returns a [`ShareReport`] that
//! names the path (`direct`, or `relay via <node>`), whether the session
//! received it, the attachment id, the bytes, and — on failure — the reason.
//! A failed delivery is a report, not a lost share: `received` is false and
//! `failure` carries the stable code and message.
//!
//! # No VPN eviction
//!
//! Zero never owns the system VPN (AND-09, MESH-01). A share rides the app-level
//! userspace mesh, or loopback when both processes are on one machine. There is
//! no target shape, field, or constructor that asks to establish, disable,
//! replace, or evict a VPN; [`ShareTarget::requires_vpn_change`] is false for
//! every variant, [`VpnState`] has the single variant [`VpnState::Untouched`],
//! and every report carries it. [`refuse_vpn_change`] is the typed refusal for
//! any future surface that tries to route a share through a VPN change. See
//! `docs/android.md`.
//!
//! The module opens no socket and names no endpoint ([`SHARE_TRANSPORT`]); a
//! source-scanning test fails the build if network code appears here.

use std::fmt;

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::android_session::SessionSummary;

/// The transport a share uses. There is no public endpoint: the attachment
/// travels over the authenticated mesh, or over loopback when both processes
/// run on one machine. This module holds a sink seam and opens no socket.
pub const SHARE_TRANSPORT: &str =
    "mesh or loopback only; a share rides the userspace mesh and this module opens no socket";

/// The VPN rule in one sentence. Zero never owns or changes the system VPN.
pub const VPN_POLICY: &str = "Zero never owns or changes the system VPN: a share rides the \
     app-level userspace mesh with no platform VPN service, no tunnel, and no VPN eviction";

/// Byte cap for a shared image: 20 MiB, matching the multimodal image cap.
pub const MAX_SHARE_IMAGE_BYTES: usize = 20 * 1024 * 1024;

/// Byte cap for shared text: 64 KiB.
pub const MAX_SHARE_TEXT_BYTES: usize = 64 * 1024;

/// Byte cap for an arbitrary shared file: 64 MiB, matching the document cap.
pub const MAX_SHARE_FILE_BYTES: usize = 64 * 1024 * 1024;

/// Cap on a shared file's name, in characters.
pub const MAX_SHARE_NAME_CHARS: usize = 128;

/// Cap on the source app label, in characters.
pub const MAX_SHARE_SOURCE_APP_CHARS: usize = 128;

/// Cap on a link, in characters.
pub const MAX_SHARE_URL_CHARS: usize = 2_048;

/// Cap on the sessions one share sheet may show.
pub const MAX_SHEET_ENTRIES: usize = 20;

/// Cap on a share-sheet label, in characters.
pub const MAX_SHEET_LABEL_CHARS: usize = 80;

/// Cap on a session id or relay node name, in characters.
const MAX_TARGET_ID_CHARS: usize = 128;

/// Cap on a mime type, in characters.
const MAX_MIME_CHARS: usize = 255;

/// Marker appended to a truncated label.
const TRUNCATION_MARKER: &str = "…";

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// What the user shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareKind {
    Image,
    Text,
    File,
    Url,
}

impl ShareKind {
    /// Every kind in deterministic order.
    pub const ALL: [ShareKind; 4] = [
        ShareKind::Image,
        ShareKind::Text,
        ShareKind::File,
        ShareKind::Url,
    ];

    /// Stable lowercase name used in JSON and error messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            ShareKind::Image => "image",
            ShareKind::Text => "text",
            ShareKind::File => "file",
            ShareKind::Url => "url",
        }
    }

    /// The byte cap for one payload of this kind. A link carries no bytes.
    pub const fn byte_cap(self) -> usize {
        match self {
            ShareKind::Image => MAX_SHARE_IMAGE_BYTES,
            ShareKind::Text => MAX_SHARE_TEXT_BYTES,
            ShareKind::File => MAX_SHARE_FILE_BYTES,
            ShareKind::Url => 0,
        }
    }
}

impl fmt::Display for ShareKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One shared payload, as the share sheet handed it over.
///
/// The fields are public so a host can decode an intent, but every field is
/// validated again by [`Self::validate`] (and by [`ShareIntent::new`]) before
/// delivery. `Debug` prints the byte length and whether a URL is present, not
/// the bytes or the link.
#[derive(Clone, PartialEq, Eq)]
pub struct SharePayload {
    pub kind: ShareKind,
    pub mime: String,
    pub name: Option<String>,
    pub bytes: Vec<u8>,
    pub url: Option<String>,
}

impl fmt::Debug for SharePayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharePayload")
            .field("kind", &self.kind)
            .field("mime", &self.mime)
            .field("name", &self.name)
            .field("bytes_len", &self.bytes.len())
            .field("url_present", &self.url.is_some())
            .finish()
    }
}

impl SharePayload {
    /// Build and validate a payload.
    pub fn new(
        kind: ShareKind,
        mime: impl Into<String>,
        name: Option<impl Into<String>>,
        bytes: Vec<u8>,
        url: Option<impl Into<String>>,
    ) -> Result<Self> {
        let payload = Self {
            kind,
            mime: mime.into(),
            name: name.map(Into::into),
            bytes,
            url: url.map(Into::into),
        };
        payload.validate()?;
        Ok(payload)
    }

    /// A shared image with an explicit mime type and optional name.
    pub fn image(mime: &str, name: Option<&str>, bytes: &[u8]) -> Result<Self> {
        Self::new(
            ShareKind::Image,
            mime,
            name.map(str::to_string),
            bytes.to_vec(),
            Option::<String>::None,
        )
    }

    /// Shared plain text. The text is the payload's bytes.
    pub fn text(text: &str) -> Result<Self> {
        Self::new(
            ShareKind::Text,
            "text/plain",
            Option::<String>::None,
            text.as_bytes().to_vec(),
            Option::<String>::None,
        )
    }

    /// A shared file with an explicit mime type and name.
    pub fn file(mime: &str, name: &str, bytes: &[u8]) -> Result<Self> {
        Self::new(
            ShareKind::File,
            mime,
            Some(name.to_string()),
            bytes.to_vec(),
            Option::<String>::None,
        )
    }

    /// A shared link. It carries the URL and no bytes.
    pub fn url(url: &str) -> Result<Self> {
        Self::new(
            ShareKind::Url,
            "text/uri-list",
            Option::<String>::None,
            Vec::new(),
            Some(url.to_string()),
        )
    }

    /// Validate the payload against the intake rules.
    pub fn validate(&self) -> Result<()> {
        if let Some(name) = &self.name {
            validate_name(name)?;
        }
        let essence = validate_mime(&self.mime)?;
        match self.kind {
            ShareKind::Image => {
                if !essence.starts_with("image/") {
                    return Err(invalid(format!(
                        "mime `{}` is not valid for an image share; send an image/* type",
                        self.mime
                    )));
                }
                refuse_url(self)?;
                require_bytes(self)?;
            }
            ShareKind::Text => {
                if !is_text_mime(&essence) {
                    return Err(invalid(format!(
                        "mime `{}` is not valid for a text share; send text/plain or a text type",
                        self.mime
                    )));
                }
                refuse_url(self)?;
                require_bytes(self)?;
            }
            ShareKind::File => {
                refuse_url(self)?;
                require_bytes(self)?;
            }
            ShareKind::Url => {
                if !self.bytes.is_empty() {
                    return Err(invalid(
                        "a link share carries the URL only and must not carry bytes",
                    ));
                }
                if essence != "text/uri-list" && essence != "text/plain" {
                    return Err(invalid(format!(
                        "mime `{}` is not valid for a link share; send text/uri-list",
                        self.mime
                    )));
                }
                let url = self
                    .url
                    .as_deref()
                    .ok_or_else(|| invalid("a link share needs a URL"))?;
                validate_http_url(url)?;
            }
        }
        Ok(())
    }

    /// The stable attachment id for this payload: FNV-1a over kind, mime,
    /// name, bytes, and URL. The same share always has the same id.
    pub fn attachment_id(&self) -> String {
        let mut state = FNV_OFFSET;
        hash_bytes(&mut state, self.kind.as_str().as_bytes());
        hash_bytes(&mut state, &[0]);
        hash_bytes(&mut state, self.mime.as_bytes());
        hash_bytes(&mut state, &[0]);
        match &self.name {
            Some(name) => {
                hash_bytes(&mut state, &[1]);
                hash_bytes(&mut state, name.as_bytes());
            }
            None => hash_bytes(&mut state, &[0]),
        }
        hash_bytes(&mut state, &(self.bytes.len() as u64).to_le_bytes());
        hash_bytes(&mut state, &self.bytes);
        match &self.url {
            Some(url) => {
                hash_bytes(&mut state, &[1]);
                hash_bytes(&mut state, url.as_bytes());
            }
            None => hash_bytes(&mut state, &[0]),
        }
        format!("att-{state:016x}")
    }
}

/// One share as it arrived: the payload, the app it came from, and the phone's
/// clock.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareIntent {
    pub payload: SharePayload,
    pub source_app: String,
    pub created_ms: u64,
}

impl fmt::Debug for ShareIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareIntent")
            .field("payload", &self.payload)
            .field("source_app", &self.source_app)
            .field("created_ms", &self.created_ms)
            .finish()
    }
}

impl ShareIntent {
    /// Validate the payload and the source-app label.
    pub fn new(payload: SharePayload, source_app: impl Into<String>, created_ms: u64) -> Result<Self> {
        let intent = Self {
            payload,
            source_app: source_app.into(),
            created_ms,
        };
        intent.validate()?;
        Ok(intent)
    }

    /// Validate the intent: a well-formed payload and a bounded, single-line
    /// source-app label.
    pub fn validate(&self) -> Result<()> {
        self.payload.validate()?;
        validate_label("source app", &self.source_app, MAX_SHARE_SOURCE_APP_CHARS)?;
        Ok(())
    }
}

/// One validated, delivery-ready attachment.
///
/// The bytes and URL are bounded by the payload rules. `Debug` prints the id,
/// kind, mime, name, byte length, and whether a URL is present; it never prints
/// the bytes or the link.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareAttachment {
    pub id: String,
    pub kind: ShareKind,
    pub mime: String,
    pub name: Option<String>,
    pub bytes: Vec<u8>,
    pub url: Option<String>,
}

impl fmt::Debug for ShareAttachment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareAttachment")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("mime", &self.mime)
            .field("name", &self.name)
            .field("bytes_len", &self.bytes.len())
            .field("url_present", &self.url.is_some())
            .finish()
    }
}

impl ShareAttachment {
    /// Validate the intent and derive the attachment. Nothing is copied that
    /// has not passed [`ShareIntent::validate`].
    pub fn from_intent(intent: &ShareIntent) -> Result<Self> {
        intent.validate()?;
        let payload = &intent.payload;
        Ok(Self {
            id: payload.attachment_id(),
            kind: payload.kind,
            mime: payload.mime.clone(),
            name: payload.name.clone(),
            bytes: payload.bytes.clone(),
            url: payload.url.clone(),
        })
    }

    /// The number of bytes this attachment moves. A link moves none.
    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }
}

/// A row in the Android share sheet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareSheetEntry {
    /// Stable row id. It is the session id for a session row.
    pub id: String,
    /// Bounded, single-line label.
    pub label: String,
    pub target: ShareTarget,
}

/// Where a share goes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShareTarget {
    /// Deliver into one session. The mesh chooses direct or relay.
    Session(String),
    /// Prefer a named relay node. [`ShareRouter`] supplies the session.
    Relay { node: String },
    /// Prefer a direct peer path. [`ShareRouter`] supplies the session.
    Direct,
}

impl ShareTarget {
    /// No share target asks to establish, disable, replace, or evict a VPN.
    /// This is the structural guarantee behind AND-09: the enum has no such
    /// shape, so this is false for every variant.
    pub fn requires_vpn_change(&self) -> bool {
        false
    }
}

/// The path a share actually took.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Route {
    /// The peers reached each other without a relay.
    Direct,
    /// An approved relay node carried the attachment.
    Relay { node: String },
}

impl Route {
    /// Stable name: `direct` or `relay`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Route::Direct => "direct",
            Route::Relay { .. } => "relay",
        }
    }

    /// The relay node, when the path was relayed.
    pub fn node(&self) -> Option<&str> {
        match self {
            Route::Direct => None,
            Route::Relay { node } => Some(node),
        }
    }

    /// A display label: `direct`, or `relay via <node>`.
    pub fn label(&self) -> String {
        match self {
            Route::Direct => "direct".into(),
            Route::Relay { node } => format!("relay via {node}"),
        }
    }
}

/// The VPN state of a share. The single variant is the guarantee: a share
/// never touches the system VPN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VpnState {
    /// The share neither established, disabled, replaced, nor evicted a VPN.
    Untouched,
}

impl VpnState {
    /// Every state, in deterministic order.
    pub const ALL: [VpnState; 1] = [VpnState::Untouched];

    /// Stable lowercase name.
    pub const fn as_str(self) -> &'static str {
        "untouched"
    }
}

impl fmt::Display for VpnState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The typed refusal for a future surface that tries to route a share through
/// a VPN change. No current target can reach it; it exists so the refusal is
/// explicit, stable, and tested.
pub fn refuse_vpn_change() -> ZeroError {
    ZeroError::new(
        ErrorCode::PolicyDenied,
        format!("{VPN_POLICY}; a share that needs a VPN change is refused"),
    )
}

/// The host's acknowledgement of one delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryReceipt {
    /// The session that received the attachment.
    pub session: String,
    /// The attachment id the session received.
    pub attachment_id: String,
    /// The path the mesh used.
    pub route: Route,
    /// When the session received it, in milliseconds since the Unix epoch.
    pub received_ms: u64,
    /// Bytes moved. A link moves none.
    pub bytes: u64,
}

/// The mesh (or loopback) share transport.
///
/// Implementors do one round trip per delivery. One sink belongs to one host;
/// the attachment is opaque bytes plus its bounded metadata.
pub trait ShareSink {
    /// Deliver one attachment into one session.
    fn deliver(&self, session: &str, attachment: &ShareAttachment) -> Result<DeliveryReceipt>;

    /// The path the sink expects for a session, used only to name a route in a
    /// failed report. The receipt is authoritative after a delivery.
    fn route_for(&self, session: &str) -> Route {
        let _ = session;
        Route::Direct
    }
}

/// A sink plus the session that [`ShareTarget::Direct`] and
/// [`ShareTarget::Relay`] apply to.
pub struct ShareRouter<'a> {
    sink: &'a dyn ShareSink,
    session: Option<String>,
}

impl fmt::Debug for ShareRouter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareRouter")
            .field("session", &self.session)
            .finish_non_exhaustive()
    }
}

impl<'a> ShareRouter<'a> {
    /// A router with no bound session. A [`ShareTarget::Session`] needs none; a
    /// direct or relay target is refused until [`Self::with_session`] binds one.
    pub fn new(sink: &'a dyn ShareSink) -> Self {
        Self { sink, session: None }
    }

    /// Bind the session that direct and relay targets deliver into.
    pub fn with_session(mut self, session: impl Into<String>) -> Result<Self> {
        let session = session.into();
        validate_target_id("session id", &session)?;
        self.session = Some(session);
        Ok(self)
    }

    /// The VPN state of every share this router performs.
    pub fn vpn_state(&self) -> VpnState {
        VpnState::Untouched
    }

    /// Resolve the path a target names, before or without delivery.
    pub fn route_for(&self, target: &ShareTarget) -> Result<Route> {
        match target {
            ShareTarget::Direct => Ok(Route::Direct),
            ShareTarget::Relay { node } => {
                validate_target_id("relay node", node)?;
                Ok(Route::Relay { node: node.clone() })
            }
            ShareTarget::Session(id) => {
                validate_target_id("session id", id)?;
                validate_route(self.sink.route_for(id))
            }
        }
    }

    fn session_for(&self, target: &ShareTarget) -> Result<String> {
        match target {
            ShareTarget::Session(id) => {
                validate_target_id("session id", id)?;
                Ok(id.clone())
            }
            ShareTarget::Relay { node } => {
                validate_target_id("relay node", node)?;
                self.require_bound_session()
            }
            ShareTarget::Direct => self.require_bound_session(),
        }
    }

    fn require_bound_session(&self) -> Result<String> {
        self.session.clone().ok_or_else(|| {
            invalid(
                "a direct or relay share needs the router bound to a session; \
                 use ShareRouter::with_session",
            )
        })
    }
}

/// One reason a delivery did not reach a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareFailure {
    /// Stable error code from the sink, the target validation, or the receipt
    /// check.
    pub code: ErrorCode,
    /// Human-readable reason.
    pub message: String,
}

impl Serialize for ShareFailure {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ShareFailure", 2)?;
        state.serialize_field("code", self.code.as_str())?;
        state.serialize_field("message", &self.message)?;
        state.end()
    }
}

/// What happened to one share.
///
/// `route` is the path that was used after a delivery and the path the target
/// named (or the direct default) when delivery failed before a path existed.
/// `received` is true only when the session acknowledged the exact attachment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShareReport {
    pub target: ShareTarget,
    pub attachment_id: String,
    pub route: Route,
    /// When the session received the share, in milliseconds since the Unix
    /// epoch. `0` when nothing was delivered.
    pub delivered_ms: u64,
    pub vpn_state: VpnState,
    /// True only when the session received this exact attachment.
    pub received: bool,
    /// Data-use estimate in bytes: the bytes moved, or the attachment size when
    /// nothing moved.
    pub bytes: u64,
    /// The reason a delivery failed.
    pub failure: Option<ShareFailure>,
}

impl ShareReport {
    fn refused(target: &ShareTarget) -> Self {
        Self {
            target: target.clone(),
            attachment_id: String::new(),
            route: Route::Direct,
            delivered_ms: 0,
            vpn_state: VpnState::Untouched,
            received: false,
            bytes: 0,
            failure: None,
        }
    }

    fn fail(&mut self, error: ZeroError) {
        self.received = false;
        self.delivered_ms = 0;
        self.failure = Some(ShareFailure {
            code: error.code(),
            message: error.message().to_string(),
        });
    }

    /// True when the session received the attachment.
    pub fn is_delivered(&self) -> bool {
        self.received
    }

    /// A display label for the path: `direct` or `relay via <node>`.
    pub fn route_label(&self) -> String {
        self.route.label()
    }

    /// A one-line report that names the target, the path, and the outcome. It
    /// never contains attachment bytes or a URL.
    pub fn summary(&self) -> String {
        let target = match &self.target {
            ShareTarget::Session(id) => format!("session {id}"),
            ShareTarget::Relay { node } => format!("relay {node}"),
            ShareTarget::Direct => "direct".to_string(),
        };
        let outcome = match &self.failure {
            Some(failure) => format!("failed: {} ({})", failure.code, failure.message),
            None if self.received => "received".to_string(),
            None => "not delivered".to_string(),
        };
        format!(
            "share {} · {} · {} · {} bytes · vpn {} · {}",
            self.attachment_id,
            target,
            self.route_label(),
            self.bytes,
            self.vpn_state,
            outcome
        )
    }
}

/// Share one intent at one target. This always returns a report: a refused
/// target, a failed delivery, and a mismatched receipt are reported with
/// `received = false` and a typed `failure`.
pub fn share(intent: &ShareIntent, target: &ShareTarget, router: &ShareRouter<'_>) -> ShareReport {
    let mut report = ShareReport::refused(target);
    if let Err(error) = deliver(intent, target, router, &mut report) {
        report.fail(error);
    }
    report
}

fn deliver(
    intent: &ShareIntent,
    target: &ShareTarget,
    router: &ShareRouter<'_>,
    report: &mut ShareReport,
) -> Result<()> {
    // The VPN guard. No target shape can ask for a VPN change; the check is
    // kept so a future variant cannot bypass the rule silently.
    if target.requires_vpn_change() {
        return Err(refuse_vpn_change());
    }

    // Validate the target before anything is built or sent.
    let session = router.session_for(target)?;
    let planned_route = router.route_for(target)?;
    report.route = planned_route;

    let attachment = ShareAttachment::from_intent(intent)?;
    report.attachment_id = attachment.id.clone();
    report.bytes = attachment.byte_len() as u64;

    let receipt = router.sink.deliver(&session, &attachment)?;
    if receipt.session != session {
        return Err(invalid(
            "the mesh acknowledged the share for a different session; refuse this response",
        ));
    }
    if receipt.attachment_id != attachment.id {
        return Err(invalid(
            "the mesh acknowledged a different attachment id; refuse this response",
        ));
    }
    let route = validate_route(receipt.route.clone())?;
    report.route = route;
    report.delivered_ms = receipt.received_ms;
    report.received = true;
    if receipt.bytes > 0 {
        report.bytes = receipt.bytes;
    }
    Ok(())
}

/// Build the deterministic share sheet from the host's sessions.
///
/// Rows are ordered by newest activity then id, duplicates collapse to one row,
/// a session whose id is malformed is skipped, labels are flattened and bounded
/// to [`MAX_SHEET_LABEL_CHARS`], and the list is capped at
/// [`MAX_SHEET_ENTRIES`]. The same sessions in any input order produce the same
/// sheet.
pub fn share_sheet(sessions: &[SessionSummary]) -> Vec<ShareSheetEntry> {
    // One row per id: the newest copy wins, so a duplicate can never appear
    // twice or change the sheet with input order.
    let mut by_id: std::collections::BTreeMap<&str, &SessionSummary> =
        std::collections::BTreeMap::new();
    for summary in sessions {
        if !is_valid_target_id(&summary.id) {
            continue;
        }
        match by_id.get(summary.id.as_str()) {
            Some(existing) if existing.updated_ms >= summary.updated_ms => {}
            _ => {
                by_id.insert(summary.id.as_str(), summary);
            }
        }
    }
    let mut rows: Vec<&SessionSummary> = by_id.into_values().collect();
    rows.sort_by(|a, b| b.updated_ms.cmp(&a.updated_ms).then_with(|| a.id.cmp(&b.id)));
    rows.truncate(MAX_SHEET_ENTRIES);

    rows.into_iter()
        .map(|summary| {
            let mut label = one_line_bounded(&summary.name, MAX_SHEET_LABEL_CHARS);
            if label.is_empty() {
                label = "untitled session".into();
            }
            ShareSheetEntry {
                id: summary.id.clone(),
                label,
                target: ShareTarget::Session(summary.id.clone()),
            }
        })
        .collect()
}

fn is_valid_target_id(value: &str) -> bool {
    !value.trim().is_empty()
        && value.chars().count() <= MAX_TARGET_ID_CHARS
        && !value.chars().any(char::is_control)
}

fn validate_target_id(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(invalid(format!(
            "a {field} must not be empty; pick one from the share sheet"
        )));
    }
    if value.chars().count() > MAX_TARGET_ID_CHARS {
        return Err(limit(format!(
            "a {field} may be at most {MAX_TARGET_ID_CHARS} characters"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid(format!(
            "a {field} must not contain control characters; pick one from the share sheet"
        )));
    }
    Ok(())
}

fn validate_route(route: Route) -> Result<Route> {
    match route {
        Route::Direct => Ok(Route::Direct),
        Route::Relay { node } => {
            validate_target_id("relay node", &node)?;
            Ok(Route::Relay { node })
        }
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(invalid("a share name must not be blank"));
    }
    if name.chars().count() > MAX_SHARE_NAME_CHARS {
        return Err(limit(format!(
            "a share name may be at most {MAX_SHARE_NAME_CHARS} characters"
        )));
    }
    if name.chars().any(char::is_control) {
        return Err(invalid(
            "a share name must not contain control characters; send a plain file name",
        ));
    }
    Ok(())
}

fn validate_label(field: &str, value: &str, max: usize) -> Result<()> {
    if value.trim().is_empty() {
        return Err(invalid(format!("a {field} must not be blank")));
    }
    if value.chars().count() > max {
        return Err(limit(format!("a {field} may be at most {max} characters")));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid(format!(
            "a {field} must not contain control characters"
        )));
    }
    Ok(())
}

/// Validate a mime type and return its lowercase essence (`type/subtype`).
fn validate_mime(mime: &str) -> Result<String> {
    if mime.chars().count() > MAX_MIME_CHARS {
        return Err(limit(format!(
            "a mime type may be at most {MAX_MIME_CHARS} characters"
        )));
    }
    if mime.chars().any(char::is_control) {
        return Err(invalid("a mime type must not contain control characters"));
    }
    let essence = mime.split(';').next().unwrap_or("").trim();
    let Some((category, subtype)) = essence.split_once('/') else {
        return Err(invalid(format!(
            "mime `{mime}` is missing `type/subtype`"
        )));
    };
    if category.is_empty()
        || subtype.is_empty()
        || subtype.contains('/')
        || essence.chars().any(char::is_whitespace)
    {
        return Err(invalid(format!("mime `{mime}` is malformed")));
    }
    Ok(essence.to_ascii_lowercase())
}

fn is_text_mime(essence: &str) -> bool {
    essence.starts_with("text/")
        || matches!(
            essence,
            "application/json" | "application/xml" | "application/yaml" | "application/x-yaml"
        )
}

fn refuse_url(payload: &SharePayload) -> Result<()> {
    if payload.url.is_some() {
        return Err(invalid(
            "a non-link share carries its content in bytes and must not carry a URL",
        ));
    }
    Ok(())
}

fn require_bytes(payload: &SharePayload) -> Result<()> {
    if payload.bytes.is_empty() {
        return Err(invalid(format!(
            "a {} share needs at least one byte of content",
            payload.kind
        )));
    }
    let cap = payload.kind.byte_cap();
    if payload.bytes.len() > cap {
        return Err(limit(format!(
            "a {} share is {} bytes; the cap for {} is {} bytes",
            payload.kind, payload.bytes.len(), payload.kind, cap
        )));
    }
    Ok(())
}

/// Validate an http(s) URL. The message never echoes the URL, so a refused
/// credential in the URL cannot leak into a report or a log.
fn validate_http_url(url: &str) -> Result<()> {
    if url.is_empty() {
        return Err(invalid("a link share needs a URL"));
    }
    if url.chars().count() > MAX_SHARE_URL_CHARS {
        return Err(limit(format!(
            "a link may be at most {MAX_SHARE_URL_CHARS} characters"
        )));
    }
    if url.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
        return Err(invalid(
            "a shared link must not contain whitespace or control characters",
        ));
    }
    let Some((scheme, rest)) = url.split_once("://") else {
        return Err(invalid("a shared link is missing http or https"));
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(invalid(
            "a shared link must use http or https; other schemes are refused",
        ));
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err(invalid("a shared link has no host"));
    }
    if authority.contains('@') {
        return Err(invalid(
            "a shared link carries userinfo; credentials in a URL are refused",
        ));
    }
    if authority.contains('\\') {
        return Err(invalid("a shared link has an invalid host"));
    }
    let host = if let Some(remainder) = authority.strip_prefix('[') {
        remainder.split(']').next().unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    };
    if host.is_empty() {
        return Err(invalid("a shared link has no host"));
    }
    Ok(())
}

fn hash_bytes(state: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *state ^= u64::from(*byte);
        *state = state.wrapping_mul(FNV_PRIME);
    }
}

/// Flatten to one line: control characters and whitespace runs become a single
/// space, and leading/trailing space is dropped.
fn one_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pending_space = false;
    for ch in text.chars() {
        if ch.is_control() || ch.is_whitespace() {
            pending_space = !out.is_empty();
        } else {
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.push(ch);
        }
    }
    out
}

fn one_line_bounded(text: &str, max: usize) -> String {
    let line = one_line(text);
    if line.chars().count() <= max {
        return line;
    }
    let keep = max.saturating_sub(TRUNCATION_MARKER.chars().count());
    let mut out: String = line.chars().take(keep).collect();
    out.push_str(TRUNCATION_MARKER);
    out
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn limit(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    const NOW: u64 = 1_700_000_000_000;
    const TOKEN: &str = "sk-live-7d1c-should-never-render";

    struct ScriptedSink {
        token: String,
        route: Route,
        deliveries: RefCell<Vec<(String, ShareAttachment)>>,
        receipts: RefCell<VecDeque<Result<DeliveryReceipt>>>,
    }

    impl ScriptedSink {
        fn new(route: Route) -> Self {
            Self {
                token: TOKEN.into(),
                route,
                deliveries: RefCell::new(Vec::new()),
                receipts: RefCell::new(VecDeque::new()),
            }
        }

        fn push(&self, receipt: Result<DeliveryReceipt>) {
            self.receipts.borrow_mut().push_back(receipt);
        }

        fn delivered(&self) -> Vec<(String, ShareAttachment)> {
            self.deliveries.borrow().clone()
        }
    }

    impl ShareSink for ScriptedSink {
        fn deliver(&self, session: &str, attachment: &ShareAttachment) -> Result<DeliveryReceipt> {
            self.deliveries
                .borrow_mut()
                .push((session.to_string(), attachment.clone()));
            match self.receipts.borrow_mut().pop_front() {
                Some(response) => response,
                None => Ok(DeliveryReceipt {
                    session: session.to_string(),
                    attachment_id: attachment.id.clone(),
                    route: self.route.clone(),
                    received_ms: NOW,
                    bytes: attachment.byte_len() as u64,
                }),
            }
        }

        fn route_for(&self, _session: &str) -> Route {
            self.route.clone()
        }
    }

    fn image_intent(name: &str, bytes: &[u8]) -> ShareIntent {
        let payload = SharePayload::image("image/png", Some(name), bytes).expect("valid image");
        ShareIntent::new(payload, "com.android.gallery", NOW).expect("valid intent")
    }

    fn session_target(id: &str) -> ShareTarget {
        ShareTarget::Session(id.to_string())
    }

    fn code_of<T: fmt::Debug>(result: Result<T>) -> ErrorCode {
        result.expect_err("the call should fail").code()
    }

    fn summary(id: &str, name: &str, updated_ms: u64) -> SessionSummary {
        SessionSummary {
            id: id.into(),
            name: name.into(),
            state: "idle".into(),
            updated_ms,
            unread: 0,
        }
    }

    #[test]
    fn share_an_image_reaches_the_scripted_session_sink() {
        let png = b"\x89PNG\r\n\x1a\nfake image bytes";
        let intent = image_intent("screenshot.png", png);
        let sink = ScriptedSink::new(Route::Direct);
        let router = ShareRouter::new(&sink);

        let report = share(&intent, &session_target("s1"), &router);

        assert!(report.received, "{report:?}");
        assert!(report.is_delivered());
        assert_eq!(report.target, ShareTarget::Session("s1".into()));
        assert_eq!(report.route, Route::Direct);
        assert_eq!(report.route_label(), "direct");
        assert_eq!(report.vpn_state, VpnState::Untouched);
        assert_eq!(report.delivered_ms, NOW);
        assert_eq!(report.bytes, png.len() as u64);
        assert!(report.failure.is_none());
        assert_eq!(report.attachment_id, intent.payload.attachment_id());
        assert_eq!(report.summary(), format!(
            "share {} · session s1 · direct · {} bytes · vpn untouched · received",
            report.attachment_id,
            png.len()
        ));

        let delivered = sink.delivered();
        assert_eq!(delivered.len(), 1, "one delivery reaches the session sink");
        let (session, attachment) = &delivered[0];
        assert_eq!(session, "s1");
        assert_eq!(attachment.kind, ShareKind::Image);
        assert_eq!(attachment.mime, "image/png");
        assert_eq!(attachment.name.as_deref(), Some("screenshot.png"));
        assert_eq!(attachment.bytes, png);
        assert_eq!(attachment.id, report.attachment_id);
    }

    #[test]
    fn share_relay_and_direct_report_the_right_route() {
        let intent = image_intent("shot.png", b"png");

        // A direct target is delivered into the router's session and reports a
        // direct path.
        let direct = ScriptedSink::new(Route::Direct);
        let router = ShareRouter::new(&direct)
            .with_session("s1")
            .expect("bind session");
        let report = share(&intent, &ShareTarget::Direct, &router);
        assert!(report.received);
        assert_eq!(report.route, Route::Direct);
        assert_eq!(direct.delivered()[0].0, "s1");

        // A relay target names the node, and the report names the relayed path.
        let relay = ScriptedSink::new(Route::Relay {
            node: "node-b".into(),
        });
        let router = ShareRouter::new(&relay)
            .with_session("s2")
            .expect("bind session");
        let report = share(
            &intent,
            &ShareTarget::Relay {
                node: "node-b".into(),
            },
            &router,
        );
        assert!(report.received);
        assert_eq!(
            report.route,
            Route::Relay {
                node: "node-b".into()
            }
        );
        assert_eq!(report.route_label(), "relay via node-b");
        assert_eq!(relay.delivered()[0].0, "s2");

        // A session target reports the path the mesh actually chose.
        let auto = ScriptedSink::new(Route::Relay {
            node: "node-a".into(),
        });
        let router = ShareRouter::new(&auto);
        let report = share(&intent, &session_target("s3"), &router);
        assert_eq!(
            report.route,
            Route::Relay {
                node: "node-a".into()
            }
        );
        assert_eq!(report.route.node(), Some("node-a"));

        // A failed relay delivery still names the relay it attempted.
        let broken = ScriptedSink::new(Route::Direct);
        broken.push(Err(ZeroError::new(ErrorCode::Offline, "relay link is down")));
        let router = ShareRouter::new(&broken)
            .with_session("s4")
            .expect("bind session");
        let report = share(
            &intent,
            &ShareTarget::Relay {
                node: "node-c".into(),
            },
            &router,
        );
        assert!(!report.received);
        assert_eq!(
            report.route,
            Route::Relay {
                node: "node-c".into()
            }
        );

        // A direct or relay target without a bound session is refused before
        // delivery.
        let unbound = ScriptedSink::new(Route::Direct);
        let router = ShareRouter::new(&unbound);
        let report = share(&intent, &ShareTarget::Direct, &router);
        assert!(!report.received);
        assert_eq!(
            report.failure.as_ref().map(|f| f.code),
            Some(ErrorCode::InvalidInput)
        );
        assert!(unbound.delivered().is_empty());
    }

    #[test]
    fn share_never_touches_the_vpn() {
        assert_eq!(VpnState::ALL, [VpnState::Untouched]);
        assert_eq!(VpnState::Untouched.as_str(), "untouched");
        assert!(VPN_POLICY.contains("never owns or changes the system VPN"));
        assert!(VPN_POLICY.contains("no VPN eviction"));
        assert!(SHARE_TRANSPORT.contains("mesh"));
        assert!(SHARE_TRANSPORT.contains("no socket"));

        let intent = image_intent("shot.png", b"png");
        for target in [
            session_target("s1"),
            ShareTarget::Relay {
                node: "node-a".into(),
            },
            ShareTarget::Direct,
        ] {
            assert!(
                !target.requires_vpn_change(),
                "no share target may ask for a VPN change"
            );
            let sink = ScriptedSink::new(Route::Direct);
            let router = ShareRouter::new(&sink)
                .with_session("s1")
                .expect("bind session");
            let report = share(&intent, &target, &router);
            assert_eq!(report.vpn_state, VpnState::Untouched, "{target:?}");
            assert_eq!(router.vpn_state(), VpnState::Untouched);
        }

        let refusal = refuse_vpn_change();
        assert_eq!(refusal.code(), ErrorCode::PolicyDenied);
        assert_eq!(refusal.code().as_str(), "zero.pol.denied");
        assert!(refusal.message().contains("system VPN"));
    }

    #[test]
    fn share_refuses_oversize_wrong_mime_and_bad_url_payloads() {
        // Byte caps per kind.
        let big_image = vec![0u8; MAX_SHARE_IMAGE_BYTES + 1];
        assert_eq!(
            code_of(SharePayload::image("image/png", None, &big_image)),
            ErrorCode::LimitExceeded
        );
        let big_text = "x".repeat(MAX_SHARE_TEXT_BYTES + 1);
        assert_eq!(
            code_of(SharePayload::text(&big_text)),
            ErrorCode::LimitExceeded
        );
        let big_file = vec![0u8; MAX_SHARE_FILE_BYTES + 1];
        assert_eq!(
            code_of(SharePayload::file(
                "application/octet-stream",
                "huge.bin",
                &big_file
            )),
            ErrorCode::LimitExceeded
        );

        // Mime/kind consistency.
        assert_eq!(
            code_of(SharePayload::image("text/plain", None, b"x")),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            code_of(SharePayload::image("image", None, b"x")),
            ErrorCode::InvalidInput
        );
        let text_as_image = SharePayload {
            kind: ShareKind::Text,
            mime: "image/png".into(),
            name: None,
            bytes: b"x".to_vec(),
            url: None,
        };
        assert_eq!(code_of(text_as_image.validate()), ErrorCode::InvalidInput);

        // Empty content is refused.
        assert_eq!(
            code_of(SharePayload::image("image/png", None, b"")),
            ErrorCode::InvalidInput
        );
        assert_eq!(code_of(SharePayload::text("")), ErrorCode::InvalidInput);
        assert_eq!(
            code_of(SharePayload::file("application/pdf", "empty.pdf", b"")),
            ErrorCode::InvalidInput
        );

        // Links: only http(s), no userinfo, no bytes, no other mime.
        assert_eq!(
            code_of(SharePayload::url("ftp://example.com/file")),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            code_of(SharePayload::url("https://user:hunter2@example.com/page")),
            ErrorCode::InvalidInput
        );
        let error = SharePayload::url("https://user:hunter2@example.com/page").unwrap_err();
        assert!(
            !error.message().contains("hunter2") && !error.message().contains("user:"),
            "a refused URL must not echo its credential: {error}"
        );
        let link = SharePayload::url("https://example.com").expect("an https link is valid");
        assert_eq!(link.kind, ShareKind::Url);
        assert_eq!(link.mime, "text/uri-list");
        assert!(link.bytes.is_empty());
        let link_with_bytes = SharePayload {
            kind: ShareKind::Url,
            mime: "text/uri-list".into(),
            name: None,
            bytes: b"extra".to_vec(),
            url: Some("https://example.com".into()),
        };
        assert_eq!(
            code_of(link_with_bytes.validate()),
            ErrorCode::InvalidInput
        );
        let link_with_image_mime = SharePayload {
            kind: ShareKind::Url,
            mime: "image/png".into(),
            name: None,
            bytes: Vec::new(),
            url: Some("https://example.com".into()),
        };
        assert_eq!(
            code_of(link_with_image_mime.validate()),
            ErrorCode::InvalidInput
        );

        // Names and source apps are single-line and bounded.
        let bad_name = SharePayload::image("image/png", Some("shot\n.png"), b"png");
        assert_eq!(code_of(bad_name), ErrorCode::InvalidInput);
        let long_name = "n".repeat(MAX_SHARE_NAME_CHARS + 1);
        assert_eq!(
            code_of(SharePayload::image("image/png", Some(&long_name), b"png")),
            ErrorCode::LimitExceeded
        );
        let payload = SharePayload::image("image/png", Some("shot.png"), b"png").unwrap();
        assert_eq!(
            code_of(ShareIntent::new(payload.clone(), "  ", NOW)),
            ErrorCode::InvalidInput
        );
        let long_app = "a".repeat(MAX_SHARE_SOURCE_APP_CHARS + 1);
        assert_eq!(
            code_of(ShareIntent::new(payload.clone(), long_app, NOW)),
            ErrorCode::LimitExceeded
        );
        assert_eq!(
            code_of(ShareIntent::new(payload, "app\u{7}", NOW)),
            ErrorCode::InvalidInput
        );

        // A tampered intent is refused by `share` before the sink is called.
        let tampered = ShareIntent::new(
            SharePayload {
                kind: ShareKind::Image,
                mime: "text/plain".into(),
                name: None,
                bytes: b"not an image".to_vec(),
                url: None,
            },
            "com.android.gallery",
            NOW,
        )
        .expect_err("a wrong mime intent cannot be built");
        assert_eq!(tampered.code(), ErrorCode::InvalidInput);

        let sink = ScriptedSink::new(Route::Direct);
        let router = ShareRouter::new(&sink);
        let intent = image_intent("shot.png", b"png");
        let mut broken = intent.clone();
        broken.payload.mime = "text/plain".into();
        let report = share(&broken, &session_target("s1"), &router);
        assert!(!report.received);
        assert!(report.failure.is_some());
        assert!(sink.delivered().is_empty());
    }

    #[test]
    fn share_sheet_is_deterministic_and_bounded() {
        let rows = vec![
            summary("s3", "third", 1_000),
            summary("s1", "first", 3_000),
            summary("s2", "second", 2_000),
        ];
        let first = share_sheet(&rows);
        assert_eq!(
            first.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
            vec!["s1", "s2", "s3"],
            "newest first, then id"
        );
        assert!(first
            .iter()
            .all(|row| matches!(row.target, ShareTarget::Session(_))));
        assert_eq!(first[0].target, ShareTarget::Session("s1".into()));

        let mut reversed = rows.clone();
        reversed.reverse();
        assert_eq!(first, share_sheet(&reversed), "input order does not matter");

        // Duplicates collapse, labels flatten, and malformed ids are skipped.
        let messy = vec![
            summary("s1", "first", 3_000),
            summary("s1", "stale copy", 1_000),
            summary("s1", "first", 3_000),
            summary("s9", "build\n\tthe app", 500),
            SessionSummary {
                id: "bad\nid".into(),
                name: "malformed".into(),
                state: "idle".into(),
                updated_ms: 9_000,
                unread: 0,
            },
            SessionSummary {
                id: "s10".into(),
                name: "   ".into(),
                state: "idle".into(),
                updated_ms: 10,
                unread: 0,
            },
        ];
        let sheet = share_sheet(&messy);
        assert_eq!(
            sheet.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
            vec!["s1", "s9", "s10"]
        );
        assert_eq!(sheet[0].label, "first", "the newest copy of an id wins");
        assert_eq!(sheet[1].label, "build the app");
        assert_eq!(sheet[2].label, "untitled session");

        // The sheet is capped at MAX_SHEET_ENTRIES.
        let many: Vec<SessionSummary> = (0..MAX_SHEET_ENTRIES + 10)
            .map(|index| summary(&format!("s{index:02}"), &format!("row {index}"), index as u64))
            .collect();
        let capped = share_sheet(&many);
        assert_eq!(capped.len(), MAX_SHEET_ENTRIES);
        assert_eq!(capped[0].id, "s29", "newest first");
    }

    #[test]
    fn share_a_failed_delivery_reports_the_reason_and_the_route() {
        let intent = image_intent("shot.png", b"png");
        let sink = ScriptedSink::new(Route::Direct);
        sink.push(Err(ZeroError::new(
            ErrorCode::Offline,
            "mesh link is down; reconnect and retry",
        )));
        let router = ShareRouter::new(&sink);

        let report = share(&intent, &session_target("s1"), &router);
        assert!(!report.received);
        assert!(!report.is_delivered());
        assert_eq!(report.delivered_ms, 0);
        assert_eq!(report.route, Route::Direct);
        assert_eq!(report.vpn_state, VpnState::Untouched);
        assert_eq!(report.bytes, 3, "a failed share still reports its size");
        let failure = report.failure.as_ref().expect("a reason is reported");
        assert_eq!(failure.code, ErrorCode::Offline);
        assert_eq!(failure.code.as_str(), "zero.fnd.offline");
        assert!(failure.message.contains("mesh link is down"));
        assert!(report.summary().contains("failed: zero.fnd.offline"));
        assert!(report.summary().contains("direct"));

        // A receipt for another session is refused, not reported as delivered.
        let wrong_session = ScriptedSink::new(Route::Direct);
        wrong_session.push(Ok(DeliveryReceipt {
            session: "s2".into(),
            attachment_id: intent.payload.attachment_id(),
            route: Route::Direct,
            received_ms: NOW,
            bytes: 3,
        }));
        let router = ShareRouter::new(&wrong_session);
        let report = share(&intent, &session_target("s1"), &router);
        assert!(!report.received);
        assert_eq!(
            report.failure.as_ref().map(|f| f.code),
            Some(ErrorCode::InvalidInput)
        );

        // A receipt for another attachment is refused too.
        let wrong_attachment = ScriptedSink::new(Route::Direct);
        wrong_attachment.push(Ok(DeliveryReceipt {
            session: "s1".into(),
            attachment_id: "att-0000000000000000".into(),
            route: Route::Direct,
            received_ms: NOW,
            bytes: 3,
        }));
        let router = ShareRouter::new(&wrong_attachment);
        let report = share(&intent, &session_target("s1"), &router);
        assert!(!report.received);
        assert!(report
            .failure
            .as_ref()
            .is_some_and(|f| f.message.contains("different attachment")));

        // A receipt naming a malformed relay node is refused.
        let bad_route = ScriptedSink::new(Route::Direct);
        bad_route.push(Ok(DeliveryReceipt {
            session: "s1".into(),
            attachment_id: intent.payload.attachment_id(),
            route: Route::Relay {
                node: "bad\nnode".into(),
            },
            received_ms: NOW,
            bytes: 3,
        }));
        let router = ShareRouter::new(&bad_route);
        let report = share(&intent, &session_target("s1"), &router);
        assert!(!report.received);
        assert_eq!(
            report.failure.as_ref().map(|f| f.code),
            Some(ErrorCode::InvalidInput)
        );
    }

    #[test]
    fn share_attachment_ids_are_stable_and_content_bound() {
        let first = image_intent("shot.png", b"one").payload.attachment_id();
        let again = image_intent("shot.png", b"one").payload.attachment_id();
        assert_eq!(first, again, "the same share has the same id");
        assert!(first.starts_with("att-"));
        assert_eq!(first.len(), 20);

        let other_bytes = image_intent("shot.png", b"two").payload.attachment_id();
        let other_name = image_intent("other.png", b"one").payload.attachment_id();
        let mut other_mime = image_intent("shot.png", b"one");
        other_mime.payload.mime = "image/jpeg".into();
        let mut other_url = SharePayload::url("https://example.com/a").unwrap();
        let other_url_id = other_url.attachment_id();
        other_url.url = Some("https://example.com/b".into());
        assert_ne!(first, other_bytes, "bytes change the id");
        assert_ne!(first, other_name, "the name changes the id");
        assert_ne!(first, other_mime.payload.attachment_id(), "mime changes the id");
        assert_ne!(other_url_id, other_url.attachment_id(), "url changes the id");

        // The id is derived from content, so the intent clock and source app do
        // not change it.
        let same_payload = image_intent("shot.png", b"one").payload;
        let later = ShareIntent::new(same_payload, "com.other.app", NOW + 5_000).unwrap();
        assert_eq!(first, later.payload.attachment_id());
    }

    #[test]
    fn share_text_file_and_url_reach_the_session_too() {
        let sink = ScriptedSink::new(Route::Direct);
        let router = ShareRouter::new(&sink);

        let text = ShareIntent::new(SharePayload::text("hello from the phone").unwrap(), "com.app", NOW)
            .unwrap();
        let report = share(&text, &session_target("s1"), &router);
        assert!(report.received);
        assert_eq!(sink.delivered()[0].1.kind, ShareKind::Text);
        assert_eq!(sink.delivered()[0].1.mime, "text/plain");
        assert_eq!(sink.delivered()[0].1.bytes, b"hello from the phone");

        let file = ShareIntent::new(
            SharePayload::file("application/pdf", "report.pdf", b"%PDF-1.7").unwrap(),
            "com.app",
            NOW,
        )
        .unwrap();
        let report = share(&file, &session_target("s1"), &router);
        assert!(report.received);
        assert_eq!(sink.delivered()[1].1.kind, ShareKind::File);
        assert_eq!(sink.delivered()[1].1.name.as_deref(), Some("report.pdf"));

        let link = ShareIntent::new(
            SharePayload::url("https://example.com/docs").unwrap(),
            "com.app",
            NOW,
        )
        .unwrap();
        let report = share(&link, &session_target("s1"), &router);
        assert!(report.received);
        let delivered_link = &sink.delivered()[2].1;
        assert_eq!(delivered_link.kind, ShareKind::Url);
        assert_eq!(delivered_link.mime, "text/uri-list");
        assert_eq!(
            delivered_link.url.as_deref(),
            Some("https://example.com/docs")
        );
        assert!(delivered_link.bytes.is_empty());
        assert_eq!(report.bytes, 0, "a link moves no bytes");
    }

    #[test]
    fn share_reports_and_debug_hide_payloads_and_links() {
        let sink = ScriptedSink::new(Route::Direct);
        let router = ShareRouter::new(&sink);
        let link = ShareIntent::new(
            SharePayload::url("https://example.com/doc?token=sekret-value").unwrap(),
            "com.app",
            NOW,
        )
        .unwrap();
        let report = share(&link, &session_target("s1"), &router);

        let report_json = serde_json::to_string(&report).expect("report serialises");
        let debug_report = format!("{report:?}");
        let debug_intent = format!("{link:?}");
        let debug_attachment = format!("{:?}", ShareAttachment::from_intent(&link).unwrap());
        for payload in [&report_json, &debug_report, &debug_intent, &debug_attachment] {
            assert!(
                !payload.contains("sekret-value"),
                "a view leaked the URL token: {payload}"
            );
            assert!(
                !payload.contains("https://example.com"),
                "a view leaked the URL: {payload}"
            );
            assert!(!payload.contains(&sink.token), "a view leaked a key");
        }

        let value = serde_json::to_value(&report).expect("report value");
        let mut keys = value
            .as_object()
            .expect("report object")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        assert_eq!(
            keys,
            [
                "attachment_id",
                "bytes",
                "delivered_ms",
                "failure",
                "received",
                "route",
                "target",
                "vpn_state"
            ]
        );
        assert_eq!(value["vpn_state"], "untouched");
        assert_eq!(value["route"]["kind"], "direct");

        let entry = share_sheet(&[summary("s1", "fix the build", NOW)]);
        let entry_json = serde_json::to_string(&entry).unwrap();
        assert!(!entry_json.contains(&sink.token));
        assert!(entry_json.contains("fix the build"));
    }

    #[test]
    fn share_module_stays_off_the_network_and_never_owns_a_vpn() {
        assert!(VPN_POLICY.contains("userspace mesh"));
        assert!(SHARE_TRANSPORT.contains("loopback"));
        assert!(SHARE_TRANSPORT.contains("no socket"));

        let source = include_str!("share.rs");
        for needle in [
            concat!("std::", "net"),
            concat!("Tcp", "Listener"),
            concat!("Tcp", "Stream"),
            concat!("Udp", "Socket"),
            concat!("http", "://"),
            concat!("0.0.0.", "0"),
            concat!("re", "qwest"),
            concat!("Vpn", "Service"),
            concat!("setBlocking", "("),
        ] {
            assert!(
                !source.contains(needle),
                "share must stay behind its sink and never touch a VPN; found `{needle}`"
            );
        }
    }
}
