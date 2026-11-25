//! Mobile offline input, cursor reconnect, and notifications (AND-04, AND-05,
//! AND-06; T-AND-04).
//!
//! The Android client is a remote control: it may lose the host at any moment
//! (airplane mode, a sleeping host, a mesh relay dropping). This module is the
//! client-side policy for that slice. It stores input on disk, delivers it on
//! reconnect, resumes the transcript at a cursor, and raises bounded
//! notifications. Every transport is a trait seam: this module opens no socket
//! and knows no endpoint.
//!
//! # Offline queue
//!
//! - While the host is unreachable, input is appended to a versioned JSON file
//!   (`OFFLINE_QUEUE_SCHEMA_VERSION`). Writes replace the file atomically, so a
//!   crash leaves either the old or the new queue, never a torn one.
//! - The queue is bounded by entries and bytes (measured as the serialized
//!   pending list). A full queue refuses the new item with `zero.mon.queue_full`
//!   or `zero.fnd.limit_exceeded`; nothing already queued is dropped (MON-05).
//! - [`OfflineQueue::flush`] sends pending items in queue order. An item is
//!   marked delivered only after the client acknowledges it, and the id goes
//!   into a bounded delivered ledger so a restored duplicate is skipped rather
//!   than sent again. A failed send stays queued and stops the flush, so later
//!   items never overtake it.
//!
//! # Cursor reconnect
//!
//! A [`ResumeToken`] is the store's `{generation, sequence}` cursor plus the
//! session name. A matching generation resumes from `sequence` (the first
//! entry the client has not seen), so nothing already delivered is replayed. A
//! different generation means the host rewrote the log (compaction, import,
//! reset) and the client must attach a fresh snapshot. An unreachable host is
//! [`ReconnectOutcome::Offline`]. Reconnect never touches the offline queue,
//! and a flush never moves the transcript cursor: the two are independent.
//!
//! # Notifications
//!
//! [`notify`] builds a bounded, single-line notification whose title and body
//! are scrubbed of bearer tokens, API keys, secret assignments, and long
//! credential-shaped runs. [`Notification::lock_screen_line`] reveals only the
//! title. [`NotificationOutbox`] is a bounded ring and [`NotificationSink`] is
//! the transport seam; the `ForegroundService` and `UnifiedPush` transports in
//! the Android app implement it, with no silent Google dependency in this
//! layer.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::Write;
use std::path::{Path, PathBuf};
use zero_types::error::{ErrorCode, Result, ZeroError};

/// On-disk schema version for the offline queue.
pub const OFFLINE_QUEUE_SCHEMA_VERSION: u32 = 1;
/// Default maximum number of undelivered inputs.
pub const DEFAULT_OFFLINE_MAX_ENTRIES: usize = 64;
/// Default maximum serialized size of the pending list.
pub const DEFAULT_OFFLINE_MAX_BYTES: usize = 256 * 1024;
/// Maximum bytes in one queued input's text.
pub const MAX_OFFLINE_INPUT_BYTES: usize = 16 * 1024;
/// Maximum characters in a session name.
pub const MAX_OFFLINE_SESSION_CHARS: usize = 128;
/// How many delivered ids the dedupe ledger remembers across reloads.
pub const MAX_DELIVERED_IDS: usize = 128;
/// Default number of notifications kept in the outbox.
pub const DEFAULT_NOTIFICATION_CAP: usize = 16;
/// Maximum characters in a notification title.
pub const MAX_NOTIFICATION_TITLE_CHARS: usize = 60;
/// Maximum characters in a notification body.
pub const MAX_NOTIFICATION_BODY_CHARS: usize = 200;

/// Why an offline input is being sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    /// A normal prompt that starts or continues a turn.
    Prompt,
    /// Steering for the running turn, applied at the next safe boundary.
    Steer,
    /// Cancel the running turn.
    Cancel,
}

/// One input typed on the phone while the host was unreachable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineInput {
    /// Stable id. The client and host use it to dedupe a retried delivery.
    pub id: String,
    /// Session the input belongs to.
    pub session: String,
    /// Input text. Empty only for [`InputKind::Cancel`].
    pub text: String,
    /// Client clock when the input was queued.
    pub queued_ms: u64,
    /// What the host should do with the text.
    pub kind: InputKind,
}

impl OfflineInput {
    /// True when this input is a cancel.
    pub fn is_cancel(&self) -> bool {
        self.kind == InputKind::Cancel
    }
}

/// Per-flush result.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlushReport {
    /// Ids delivered and acknowledged by this flush, in queue order.
    pub delivered: Vec<String>,
    /// Ids skipped because the delivered ledger already held them.
    pub duplicates_skipped: Vec<String>,
    /// Failures. A failure stops the flush, so the failed item and everything
    /// after it stay queued for the next attempt.
    pub failed: Vec<FlushFailure>,
    /// Client clock supplied by the caller.
    pub at_ms: u64,
}

impl FlushReport {
    /// True when every pending item was delivered and none failed.
    pub fn is_clean(&self) -> bool {
        self.failed.is_empty()
    }
}

/// One failed delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlushFailure {
    /// Id of the input that could not be delivered.
    pub id: String,
    /// Stable error code reported by the client.
    pub code: ErrorCode,
    /// Human-readable reason.
    pub message: String,
}

/// The transport the offline queue talks to. The mesh or loopback client
/// implements this; tests use a scripted client.
pub trait MobileClient {
    /// Send one input. `Ok(())` is the host's acknowledgement; an error leaves
    /// the input queued.
    fn deliver(&mut self, input: &OfflineInput) -> Result<()>;

    /// Current generation of the host's session log. A client that cannot
    /// answer is treated as offline by [`reconnect`].
    fn session_generation(&mut self, session: &str) -> Result<u64> {
        let _ = session;
        Err(ZeroError::new(
            ErrorCode::Unavailable,
            "this client does not expose session generations",
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct QueueFile {
    schema: u32,
    next_id: u64,
    pending: Vec<OfflineInput>,
    #[serde(default)]
    delivered: VecDeque<String>,
}

/// Durable, bounded queue of input typed while the host was unreachable.
#[derive(Debug)]
pub struct OfflineQueue {
    path: PathBuf,
    max_entries: usize,
    max_bytes: usize,
    next_id: u64,
    items: Vec<OfflineInput>,
    delivered: VecDeque<String>,
}

impl OfflineQueue {
    /// Open or create a queue at `path`.
    pub fn open(path: impl AsRef<Path>, max_entries: usize, max_bytes: usize) -> Result<Self> {
        if max_entries == 0 {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                "offline queue needs at least one entry",
            ));
        }
        if max_bytes == 0 {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                "offline queue needs a positive byte budget",
            ));
        }
        let path = path.as_ref().to_path_buf();
        let mut queue = Self {
            path,
            max_entries,
            max_bytes,
            next_id: 1,
            items: Vec::new(),
            delivered: VecDeque::new(),
        };
        if queue.path.exists() {
            let text = std::fs::read_to_string(&queue.path)?;
            let file: QueueFile = serde_json::from_str(&text)?;
            if file.schema != OFFLINE_QUEUE_SCHEMA_VERSION {
                return Err(ZeroError::new(
                    ErrorCode::SchemaVersion,
                    format!(
                        "offline queue schema {} is not supported; expected {}",
                        file.schema, OFFLINE_QUEUE_SCHEMA_VERSION
                    ),
                ));
            }
            let max_seen = file
                .pending
                .iter()
                .filter_map(|i| i.id.strip_prefix('m'))
                .filter_map(|n| n.parse::<u64>().ok())
                .max()
                .unwrap_or(0);
            queue.next_id = file.next_id.max(max_seen.saturating_add(1)).max(1);
            queue.items = file.pending;
            queue.delivered = file.delivered;
            while queue.delivered.len() > MAX_DELIVERED_IDS {
                queue.delivered.pop_front();
            }
        }
        Ok(queue)
    }

    /// Open with the default caps.
    pub fn open_default(path: impl AsRef<Path>) -> Result<Self> {
        Self::open(path, DEFAULT_OFFLINE_MAX_ENTRIES, DEFAULT_OFFLINE_MAX_BYTES)
    }

    /// Path of the JSON file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Undelivered inputs in queue order.
    pub fn pending_all(&self) -> &[OfflineInput] {
        &self.items
    }

    /// Undelivered inputs for one session, in queue order.
    pub fn pending(&self, session: &str) -> Vec<&OfflineInput> {
        self.items.iter().filter(|i| i.session == session).collect()
    }

    /// Number of undelivered inputs.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// True when nothing is waiting.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Delivered ids still in the dedupe ledger, oldest first.
    pub fn delivered_ids(&self) -> Vec<&str> {
        self.delivered.iter().map(String::as_str).collect()
    }

    fn pending_bytes(&self) -> Result<usize> {
        Ok(serde_json::to_vec(&self.items)?.len())
    }

    fn check_capacity(&self, input: &OfflineInput) -> Result<()> {
        if self.items.len() >= self.max_entries {
            return Err(ZeroError::new(
                ErrorCode::QueueFull,
                format!(
                    "offline queue holds {} inputs; reconnect or clear one first (nothing was dropped)",
                    self.max_entries
                ),
            ));
        }
        let extra = serde_json::to_vec(input)?.len();
        if self.pending_bytes()?.saturating_add(extra) > self.max_bytes {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "offline queue would exceed {} bytes; reconnect or clear it first (nothing was dropped)",
                    self.max_bytes
                ),
            ));
        }
        Ok(())
    }

    fn validate(input: &OfflineInput) -> Result<()> {
        if input.id.trim().is_empty() {
            return Err(ZeroError::new(ErrorCode::InvalidInput, "offline input id is empty"));
        }
        let session = input.session.trim();
        if session.is_empty() {
            return Err(ZeroError::new(ErrorCode::InvalidInput, "offline input session is empty"));
        }
        if session.chars().count() > MAX_OFFLINE_SESSION_CHARS {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                format!("offline input session exceeds {MAX_OFFLINE_SESSION_CHARS} characters"),
            ));
        }
        if input.text.len() > MAX_OFFLINE_INPUT_BYTES {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!("offline input text exceeds {MAX_OFFLINE_INPUT_BYTES} bytes"),
            ));
        }
        if input.text.trim().is_empty() && input.kind != InputKind::Cancel {
            return Err(ZeroError::new(ErrorCode::InvalidInput, "offline input text is empty"));
        }
        Ok(())
    }

    /// Append an input while the host is unreachable.
    ///
    /// The id is generated (`m1`, `m2`, ...) and returned to the caller, who
    /// shows it in the composer. Empty text is accepted only for a cancel.
    pub fn enqueue(
        &mut self,
        session: &str,
        text: impl Into<String>,
        kind: InputKind,
        now_ms: u64,
    ) -> Result<OfflineInput> {
        let input = OfflineInput {
            id: format!("m{}", self.next_id),
            session: session.trim().to_string(),
            text: text.into(),
            queued_ms: now_ms,
            kind,
        };
        Self::validate(&input)?;
        self.check_capacity(&input)?;
        self.items.push(input.clone());
        self.next_id = self.next_id.saturating_add(1);
        if let Err(e) = self.save() {
            self.items.pop();
            self.next_id = self.next_id.saturating_sub(1);
            return Err(e);
        }
        Ok(input)
    }

    /// Restore a previously seen input, for example after the app rehydrates a
    /// draft. Returns `false` (and enqueues nothing) when the id was already
    /// delivered or is already pending.
    pub fn enqueue_existing(&mut self, input: OfflineInput) -> Result<bool> {
        Self::validate(&input)?;
        if self.delivered.contains(&input.id) || self.items.iter().any(|i| i.id == input.id) {
            return Ok(false);
        }
        self.check_capacity(&input)?;
        self.items.push(input);
        if let Err(e) = self.save() {
            self.items.pop();
            return Err(e);
        }
        Ok(true)
    }

    fn record_delivered(&mut self, id: &str) {
        self.delivered.push_back(id.to_string());
        while self.delivered.len() > MAX_DELIVERED_IDS {
            self.delivered.pop_front();
        }
    }

    /// Mark an input delivered after the host's ack. Removes it from the queue
    /// and records the id in the dedupe ledger.
    pub fn mark_delivered(&mut self, id: &str) -> Result<()> {
        let pos = self
            .items
            .iter()
            .position(|i| i.id == id)
            .ok_or_else(|| ZeroError::new(ErrorCode::QueueItemMissing, format!("offline input `{id}`")))?;
        let ledger = self.delivered.clone();
        let input = self.items.remove(pos);
        self.record_delivered(id);
        if let Err(e) = self.save() {
            self.items.insert(pos, input);
            self.delivered = ledger;
            return Err(e);
        }
        Ok(())
    }

    /// Drop every undelivered input. The delivered ledger is kept so a later
    /// restore of an old id is still skipped.
    pub fn clear(&mut self) -> Result<()> {
        let old = std::mem::take(&mut self.items);
        if let Err(e) = self.save() {
            self.items = old;
            return Err(e);
        }
        Ok(())
    }

    /// Deliver pending inputs in queue order.
    ///
    /// Each item is sent once and marked delivered only after the ack. A
    /// duplicate id in the pending list is skipped via the ledger. The first
    /// failure stops the flush and leaves that item (and everything after it)
    /// queued, so order is preserved on the next attempt.
    pub fn flush(&mut self, client: &mut dyn MobileClient, now_ms: u64) -> FlushReport {
        let mut report = FlushReport { at_ms: now_ms, ..FlushReport::default() };
        while !self.items.is_empty() {
            let input = self.items[0].clone();
            if self.delivered.contains(&input.id) {
                self.items.remove(0);
                if let Err(e) = self.save() {
                    self.items.insert(0, input.clone());
                    report.failed.push(FlushFailure {
                        id: input.id,
                        code: e.code(),
                        message: e.message().to_string(),
                    });
                    break;
                }
                report.duplicates_skipped.push(input.id);
                continue;
            }
            match client.deliver(&input) {
                Ok(()) => {
                    let ledger = self.delivered.clone();
                    self.items.remove(0);
                    self.record_delivered(&input.id);
                    if let Err(e) = self.save() {
                        self.items.insert(0, input.clone());
                        self.delivered = ledger;
                        report.failed.push(FlushFailure {
                            id: input.id,
                            code: e.code(),
                            message: format!("delivered but not recorded: {}", e.message()),
                        });
                        break;
                    }
                    report.delivered.push(input.id);
                }
                Err(e) => {
                    report.failed.push(FlushFailure {
                        id: input.id,
                        code: e.code(),
                        message: e.message().to_string(),
                    });
                    break;
                }
            }
        }
        report
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = QueueFile {
            schema: OFFLINE_QUEUE_SCHEMA_VERSION,
            next_id: self.next_id,
            pending: self.items.clone(),
            delivered: self.delivered.clone(),
        };
        let tmp = self.path.with_extension("tmp");
        {
            let mut out = std::fs::File::create(&tmp)?;
            out.write_all(&serde_json::to_vec_pretty(&file)?)?;
            out.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

/// The client's transcript cursor plus the session it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeToken {
    pub session: String,
    /// Session-log generation the client last saw.
    pub generation: u64,
    /// First entry the client has not seen (the store's cursor convention).
    pub sequence: u64,
}

impl ResumeToken {
    pub fn new(session: impl Into<String>, generation: u64, sequence: u64) -> Self {
        Self { session: session.into(), generation, sequence }
    }

    /// True when the host has rewritten the log since this token was minted.
    pub fn is_stale(&self, current_generation: u64) -> bool {
        self.generation != current_generation
    }
}

/// What a reconnect attempt can do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconnectOutcome {
    /// Continue streaming after `from_sequence`.
    Resumed { from_sequence: u64 },
    /// The generation changed (or the host refused the cursor): attach a fresh
    /// snapshot. Undelivered offline inputs are untouched.
    SnapshotRequired,
    /// The host is unreachable; keep the token and retry later.
    Offline,
}

/// Decide whether to resume, attach a snapshot, or wait for the host.
///
/// This consults only the transcript cursor. It does not read, flush, or clear
/// the offline queue, so a snapshot never loses undelivered input and a flush
/// never moves the cursor.
pub fn reconnect(client: &mut dyn MobileClient, token: &ResumeToken) -> ReconnectOutcome {
    match client.session_generation(&token.session) {
        Ok(current) if !token.is_stale(current) => {
            ReconnectOutcome::Resumed { from_sequence: token.sequence }
        }
        Ok(_) => ReconnectOutcome::SnapshotRequired,
        Err(e) if e.code() == ErrorCode::AttachCursorExpired => ReconnectOutcome::SnapshotRequired,
        Err(_) => ReconnectOutcome::Offline,
    }
}

/// Kind of event a notification reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationKind {
    /// A run finished successfully.
    Completed,
    /// A run failed or was refused.
    Failed,
    /// An action is waiting for approval.
    Approval,
}

impl NotificationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Approval => "approval",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Completed => "Run complete",
            Self::Failed => "Run failed",
            Self::Approval => "Approval needed",
        }
    }

    pub fn action(self) -> NotificationAction {
        match self {
            Self::Completed | Self::Failed => NotificationAction::OpenSession,
            Self::Approval => NotificationAction::Approve,
        }
    }
}

/// What tapping the notification does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationAction {
    /// Open the session transcript.
    OpenSession,
    /// Open the approval prompt for the pending action.
    Approve,
    /// Informational only.
    None,
}

/// A lock-screen notification. Title and body are already redacted and bounded
/// by [`notify`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    pub title: String,
    pub body: String,
    pub at_ms: u64,
    pub action: NotificationAction,
}

impl Notification {
    /// The only text a lock screen may show: the title plus the action hint,
    /// never the body. Redacted again so a hand-built notification cannot leak
    /// a credential through the title.
    pub fn lock_screen_line(&self) -> String {
        let title = bounded(&one_line(&redact_secrets(&self.title)), MAX_NOTIFICATION_TITLE_CHARS);
        match self.action {
            NotificationAction::OpenSession => format!("{title} · open"),
            NotificationAction::Approve => format!("{title} · approve"),
            NotificationAction::None => title,
        }
    }
}

/// Build a redacted, bounded notification.
///
/// The body carries the session name and the detail; both are scrubbed of
/// bearer tokens, `sk-` keys, `token=...`-style assignments, and long
/// credential-shaped runs before the body is flattened and truncated.
pub fn notify(kind: NotificationKind, session: &str, detail: &str, at_ms: u64) -> Notification {
    let session = one_line(&redact_secrets(session));
    let detail = one_line(&redact_secrets(detail));
    let id = notification_id(kind, &session, &detail, at_ms);
    let body = match (session.is_empty(), detail.is_empty()) {
        (true, true) => String::new(),
        (true, false) => detail,
        (false, true) => session,
        (false, false) => format!("{session} · {detail}"),
    };
    let body = bounded(&body, MAX_NOTIFICATION_BODY_CHARS);
    Notification {
        id,
        title: kind.title().to_string(),
        body,
        at_ms,
        action: kind.action(),
    }
}

fn notification_id(kind: NotificationKind, session: &str, detail: &str, at_ms: u64) -> String {
    let material = format!("{}|{}|{}|{}", kind.as_str(), session, detail, at_ms);
    let digest = blake3::hash(material.as_bytes());
    let hex = digest.to_hex();
    format!("n{}", &hex[..16])
}

/// Transport seam. The Android app implements it over a foreground service or
/// UnifiedPush; this module never performs I/O beyond the queue file.
pub trait NotificationSink {
    /// Show one notification. An error leaves it in the outbox for a retry.
    fn notify(&mut self, notification: &Notification) -> Result<()>;
}

/// Transport kinds the Android app may pick. Both are seams here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationTransport {
    /// A foreground service owns the connection.
    ForegroundService,
    /// A UnifiedPush distributor delivers the wake-up, with no silent Google
    /// dependency.
    UnifiedPush,
}

/// Bounded ring of notifications waiting for a transport.
pub struct NotificationOutbox {
    cap: usize,
    notices: VecDeque<Notification>,
}

impl NotificationOutbox {
    pub fn new(cap: usize) -> Self {
        Self { cap: cap.max(1), notices: VecDeque::new() }
    }

    /// Append a notification. When the ring is full the oldest is dropped and
    /// returned, because notifications are transient.
    pub fn push(&mut self, notification: Notification) -> Option<Notification> {
        let dropped = if self.notices.len() >= self.cap { self.notices.pop_front() } else { None };
        self.notices.push_back(notification);
        dropped
    }

    /// Build and append a notification.
    pub fn notify(
        &mut self,
        kind: NotificationKind,
        session: &str,
        detail: &str,
        at_ms: u64,
    ) -> Option<Notification> {
        self.push(notify(kind, session, detail, at_ms))
    }

    pub fn len(&self) -> usize {
        self.notices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.notices.is_empty()
    }

    /// Pending notifications, oldest first.
    pub fn notices(&self) -> Vec<&Notification> {
        self.notices.iter().collect()
    }

    /// Send every queued notification. The first sink error stops the drain and
    /// leaves the failed notification (and the later ones) queued.
    pub fn drain_into(&mut self, sink: &mut dyn NotificationSink) -> Result<usize> {
        let mut sent = 0;
        while let Some(front) = self.notices.front() {
            sink.notify(front)?;
            self.notices.pop_front();
            sent += 1;
        }
        Ok(sent)
    }
}

/// Scrub credential-shaped text from one line.
///
/// Recognised: `Bearer <token>`, `sk-...` keys, `token=...`, `secret: ...` and
/// similar assignments, and long runs of base64/hex-like characters that
/// contain both letters and digits. This is a safety net, not a guarantee: the
/// caller should still avoid putting secrets in notification text.
pub fn redact_secrets(text: &str) -> String {
    let mut words: Vec<String> = Vec::new();
    let mut redact_next = false;
    for raw in text.split_whitespace() {
        let (lead, core, trail) = split_edges(raw);
        let lower = core.to_ascii_lowercase();
        if redact_next {
            if lower == "bearer" || lower == "basic" {
                // Keep the scheme word and keep waiting for the credential.
                words.push(format!("{lead}{core}{trail}"));
            } else {
                words.push(format!("{lead}<redacted>{trail}"));
                redact_next = false;
            }
            continue;
        }
        if core.is_empty() {
            words.push(format!("{lead}{core}{trail}"));
            continue;
        }
        if lower == "bearer" {
            words.push(format!("{lead}{core}{trail}"));
            redact_next = true;
            continue;
        }
        if let Some((key, value)) = split_key_value(core) {
            if is_secret_key(key) {
                if value.is_empty() {
                    words.push(format!("{lead}{core}{trail}"));
                    redact_next = true;
                } else {
                    let sep = &core[key.len()..key.len() + 1];
                    words.push(format!("{lead}{key}{sep}<redacted>{trail}"));
                }
                continue;
            }
            if looks_like_secret(value) {
                let sep = &core[key.len()..key.len() + 1];
                words.push(format!("{lead}{key}{sep}<redacted>{trail}"));
                continue;
            }
        }
        if looks_like_secret(core) || is_secret_key(core) {
            words.push(format!("{lead}<redacted>{trail}"));
            continue;
        }
        words.push(format!("{lead}{core}{trail}"));
    }
    words.join(" ")
}

fn split_key_value(core: &str) -> Option<(&str, &str)> {
    let idx = core.find(['=', ':'])?;
    Some((&core[..idx], &core[idx + 1..]))
}

fn is_secret_key(raw: &str) -> bool {
    let key = raw
        .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
        .replace('-', "_")
        .to_ascii_lowercase();
    matches!(
        key.as_str(),
        "token"
            | "secret"
            | "password"
            | "passwd"
            | "api_key"
            | "apikey"
            | "authorization"
            | "auth"
            | "cookie"
            | "private_key"
    ) || key.ends_with("_token")
        || key.ends_with("_secret")
        || key.ends_with("_password")
        || key.ends_with("_key")
}

fn looks_like_secret(value: &str) -> bool {
    let core = value.trim_matches(|c: char| matches!(c, '"' | '\'' | '`'));
    let lower = core.to_ascii_lowercase();
    if core.len() >= 8
        && (lower.starts_with("ghp_") || lower.starts_with("xoxb-") || lower.starts_with("akia"))
    {
        return true;
    }
    // A provider key, at the start of the word or after a separator
    // (`sess-sk-live-...`). `risk-assessment` is not a key: the character
    // before `sk-` must not be alphanumeric.
    if let Some(pos) = lower.find("sk-") {
        let boundary = pos == 0 || !core.as_bytes()[pos - 1].is_ascii_alphanumeric();
        if boundary && core.len() - (pos + 3) >= 8 {
            return true;
        }
    }
    if core.len() < 32 {
        return false;
    }
    let mut has_digit = false;
    let mut has_alpha = false;
    for c in core.chars() {
        if !c.is_ascii_alphanumeric() && !matches!(c, '+' | '/' | '=' | '_' | '-' | '.') {
            return false;
        }
        has_digit |= c.is_ascii_digit();
        has_alpha |= c.is_ascii_alphabetic();
    }
    has_digit && has_alpha
}

fn is_edge_char(c: char) -> bool {
    matches!(
        c,
        '"' | '\''
            | '`'
            | ','
            | ';'
            | '('
            | ')'
            | '['
            | ']'
            | '{'
            | '}'
            | '<'
            | '>'
            | '.'
            | '!'
            | '?'
            | '…'
    )
}

fn split_edges(raw: &str) -> (&str, &str, &str) {
    let start = raw.len() - raw.trim_start_matches(is_edge_char).len();
    let rest = &raw[start..];
    let core_len = rest.trim_end_matches(is_edge_char).len();
    (&raw[..start], &rest[..core_len], &rest[core_len..])
}

fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn bounded(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max_chars.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct ScriptedClient {
        sent: Vec<OfflineInput>,
        attempts: Vec<String>,
        fail: Vec<String>,
        offline: bool,
        generation: u64,
        generation_error: Option<ErrorCode>,
    }

    impl ScriptedClient {
        fn online(generation: u64) -> Self {
            Self { generation, ..Self::default() }
        }

        fn offline(generation: u64) -> Self {
            Self { offline: true, generation, ..Self::default() }
        }
    }

    impl MobileClient for ScriptedClient {
        fn deliver(&mut self, input: &OfflineInput) -> Result<()> {
            self.attempts.push(input.id.clone());
            if self.offline {
                return Err(ZeroError::new(ErrorCode::Offline, "no route to the host"));
            }
            if self.fail.contains(&input.id) {
                return Err(ZeroError::new(ErrorCode::Unavailable, "the host refused the input"));
            }
            self.sent.push(input.clone());
            Ok(())
        }

        fn session_generation(&mut self, _session: &str) -> Result<u64> {
            if self.offline {
                return Err(ZeroError::new(ErrorCode::Offline, "no route to the host"));
            }
            if let Some(code) = self.generation_error {
                return Err(ZeroError::new(code, "the host refused the cursor"));
            }
            Ok(self.generation)
        }
    }

    #[derive(Default)]
    struct RecordingSink {
        seen: Vec<Notification>,
        fail: bool,
    }

    impl NotificationSink for RecordingSink {
        fn notify(&mut self, notification: &Notification) -> Result<()> {
            if self.fail {
                return Err(ZeroError::new(ErrorCode::Unavailable, "no notification transport"));
            }
            self.seen.push(notification.clone());
            Ok(())
        }
    }

    #[test]
    fn mobile_offline_airplane_mode_then_reconnect_delivers_queued_input_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut queue = OfflineQueue::open_default(dir.path().join("queue.json")).unwrap();
        queue.enqueue("s1", "first", InputKind::Prompt, 10).unwrap();
        queue.enqueue("s1", "second", InputKind::Steer, 20).unwrap();
        queue.enqueue("s1", "third", InputKind::Prompt, 30).unwrap();

        let mut client = ScriptedClient::offline(7);
        let offline = queue.flush(&mut client, 40);
        assert!(offline.delivered.is_empty());
        assert_eq!(offline.failed.len(), 1);
        assert_eq!(offline.failed[0].code, ErrorCode::Offline);
        assert_eq!(queue.len(), 3);

        client.offline = false;
        let report = queue.flush(&mut client, 50);
        assert_eq!(report.delivered, vec!["m1", "m2", "m3"]);
        assert!(report.is_clean());
        let texts: Vec<&str> = client.sent.iter().map(|i| i.text.as_str()).collect();
        assert_eq!(texts, vec!["first", "second", "third"]);
        assert!(queue.is_empty());

        let retry = queue.flush(&mut client, 60);
        assert!(retry.delivered.is_empty());
        assert_eq!(client.sent.len(), 3, "a reconnect retry never redelivers an acked input");
    }

    #[test]
    fn mobile_offline_duplicate_flush_after_ack_delivers_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut queue = OfflineQueue::open_default(dir.path().join("queue.json")).unwrap();
        let item = queue.enqueue("s1", "hello", InputKind::Prompt, 1).unwrap();
        let mut client = ScriptedClient::online(3);

        let first = queue.flush(&mut client, 2);
        assert_eq!(first.delivered, vec![item.id.clone()]);
        assert_eq!(client.attempts.len(), 1);

        let second = queue.flush(&mut client, 3);
        assert!(second.delivered.is_empty());
        assert_eq!(client.attempts.len(), 1, "the same item is never sent twice");

        // A restored copy of the acked item is refused by id.
        assert!(!queue.enqueue_existing(item.clone()).unwrap());
        assert!(queue.is_empty());
        let third = queue.flush(&mut client, 4);
        assert!(third.delivered.is_empty());
        assert_eq!(client.attempts.len(), 1);

        // Even if a stale pending entry is restored, the flush skips it.
        queue.items.push(item.clone());
        let fourth = queue.flush(&mut client, 5);
        assert_eq!(fourth.duplicates_skipped, vec![item.id]);
        assert!(fourth.delivered.is_empty());
        assert!(queue.is_empty());
        assert_eq!(client.attempts.len(), 1);
    }

    #[test]
    fn mobile_offline_a_failed_send_stays_queued_and_blocks_later_items() {
        let dir = tempfile::tempdir().unwrap();
        let mut queue = OfflineQueue::open_default(dir.path().join("queue.json")).unwrap();
        let a = queue.enqueue("s1", "a", InputKind::Prompt, 1).unwrap();
        queue.enqueue("s1", "b", InputKind::Prompt, 2).unwrap();

        let mut client = ScriptedClient::online(1);
        client.fail.push(a.id.clone());
        let report = queue.flush(&mut client, 3);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].id, a.id);
        assert_eq!(report.failed[0].code, ErrorCode::Unavailable);
        assert!(report.delivered.is_empty());
        let texts: Vec<&str> = queue.pending_all().iter().map(|i| i.text.as_str()).collect();
        assert_eq!(texts, vec!["a", "b"]);
        assert_eq!(client.attempts, vec![a.id.clone()], "b does not overtake the failure");

        client.fail.clear();
        let retry = queue.flush(&mut client, 4);
        assert_eq!(retry.delivered, vec!["m1", "m2"]);
        assert!(queue.is_empty());
    }

    #[test]
    fn mobile_offline_cancel_kind_is_delivered_without_text() {
        let dir = tempfile::tempdir().unwrap();
        let mut queue = OfflineQueue::open_default(dir.path().join("queue.json")).unwrap();
        let cancel = queue.enqueue("s1", "", InputKind::Cancel, 1).unwrap();
        assert!(cancel.text.is_empty());
        assert!(cancel.is_cancel());

        let err = queue.enqueue("s1", "  ", InputKind::Prompt, 2).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidInput);

        let mut client = ScriptedClient::online(1);
        let report = queue.flush(&mut client, 3);
        assert_eq!(report.delivered, vec![cancel.id]);
        assert_eq!(client.sent.len(), 1);
        assert_eq!(client.sent[0].kind, InputKind::Cancel);
    }

    #[test]
    fn mobile_offline_queue_is_persisted_with_a_schema_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.json");
        let (first, second) = {
            let mut queue = OfflineQueue::open(&path, 8, 64 * 1024).unwrap();
            let first = queue.enqueue("s1", "one", InputKind::Prompt, 10).unwrap();
            let second = queue.enqueue("s2", "two", InputKind::Steer, 20).unwrap();
            (first, second)
        };

        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["schema"], OFFLINE_QUEUE_SCHEMA_VERSION);

        let mut queue = OfflineQueue::open(&path, 8, 64 * 1024).unwrap();
        assert_eq!(queue.pending_all(), &[first.clone(), second.clone()]);
        let mut client = ScriptedClient::online(2);
        let report = queue.flush(&mut client, 30);
        assert_eq!(report.delivered, vec![first.id, second.id]);
        assert_eq!(client.sent[0].text, "one");
        assert_eq!(client.sent[1].text, "two");

        std::fs::write(
            &path,
            r#"{"schema":99,"next_id":1,"pending":[],"delivered":[]}"#,
        )
        .unwrap();
        let err = OfflineQueue::open(&path, 8, 64 * 1024).unwrap_err();
        assert_eq!(err.code(), ErrorCode::SchemaVersion);
    }

    #[test]
    fn mobile_offline_delivered_ledger_survives_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.json");
        let item = {
            let mut queue = OfflineQueue::open_default(&path).unwrap();
            let item = queue.enqueue("s1", "once", InputKind::Prompt, 1).unwrap();
            let mut client = ScriptedClient::online(1);
            assert_eq!(queue.flush(&mut client, 2).delivered, vec![item.id.clone()]);
            item
        };

        let mut queue = OfflineQueue::open_default(&path).unwrap();
        assert!(queue.is_empty());
        assert_eq!(queue.delivered_ids(), vec![item.id.as_str()]);
        assert!(!queue.enqueue_existing(item.clone()).unwrap());
        let mut client = ScriptedClient::online(1);
        let report = queue.flush(&mut client, 3);
        assert!(report.delivered.is_empty());
        assert!(client.attempts.is_empty(), "a reloaded ack is not retried");
    }

    #[test]
    fn mobile_offline_queue_is_bounded_by_entries_and_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let mut queue = OfflineQueue::open(dir.path().join("entries.json"), 2, 64 * 1024).unwrap();
        queue.enqueue("s1", "keep-1", InputKind::Prompt, 1).unwrap();
        queue.enqueue("s1", "keep-2", InputKind::Prompt, 2).unwrap();
        let err = queue.enqueue("s1", "rejected", InputKind::Prompt, 3).unwrap_err();
        assert_eq!(err.code(), ErrorCode::QueueFull);
        assert!(err.message().contains("nothing was dropped"));
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.pending_all()[0].text, "keep-1");

        let mut bytes = OfflineQueue::open(dir.path().join("bytes.json"), 10, 260).unwrap();
        bytes.enqueue("s1", "x".repeat(100), InputKind::Prompt, 1).unwrap();
        let err = bytes.enqueue("s1", "y".repeat(100), InputKind::Prompt, 2).unwrap_err();
        assert_eq!(err.code(), ErrorCode::LimitExceeded);
        assert_eq!(bytes.len(), 1);

        let zero_entries = OfflineQueue::open(dir.path().join("zero-e.json"), 0, 1024).unwrap_err();
        assert_eq!(zero_entries.code(), ErrorCode::InvalidInput);
        let zero_bytes = OfflineQueue::open(dir.path().join("zero-b.json"), 1, 0).unwrap_err();
        assert_eq!(zero_bytes.code(), ErrorCode::InvalidInput);

        let mut limits = OfflineQueue::open(dir.path().join("limits.json"), 10, 1024 * 1024).unwrap();
        let long_session = "s".repeat(MAX_OFFLINE_SESSION_CHARS + 1);
        let err = limits.enqueue(&long_session, "x", InputKind::Prompt, 1).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidInput);
        let long_text = "x".repeat(MAX_OFFLINE_INPUT_BYTES + 1);
        let err = limits.enqueue("s1", long_text, InputKind::Prompt, 2).unwrap_err();
        assert_eq!(err.code(), ErrorCode::LimitExceeded);
        assert!(limits.is_empty());
    }

    #[test]
    fn mobile_offline_pending_filters_by_session_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let mut queue = OfflineQueue::open_default(dir.path().join("queue.json")).unwrap();
        queue.enqueue("s1", "a", InputKind::Prompt, 1).unwrap();
        queue.enqueue("s2", "b", InputKind::Prompt, 2).unwrap();
        queue.enqueue("s1", "c", InputKind::Steer, 3).unwrap();

        let s1: Vec<&str> = queue.pending("s1").iter().map(|i| i.text.as_str()).collect();
        let s2: Vec<&str> = queue.pending("s2").iter().map(|i| i.text.as_str()).collect();
        assert_eq!(s1, vec!["a", "c"]);
        assert_eq!(s2, vec!["b"]);
        assert!(queue.pending("missing").is_empty());

        let mut client = ScriptedClient::online(1);
        let report = queue.flush(&mut client, 4);
        let order: Vec<&str> = client.sent.iter().map(|i| i.text.as_str()).collect();
        assert_eq!(report.delivered, vec!["m1", "m2", "m3"]);
        assert_eq!(order, vec!["a", "b", "c"]);
    }

    #[test]
    fn mobile_offline_clear_drops_pending_but_keeps_the_delivered_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let mut queue = OfflineQueue::open_default(dir.path().join("queue.json")).unwrap();
        let a = queue.enqueue("s1", "a", InputKind::Prompt, 1).unwrap();
        let mut client = ScriptedClient::online(1);
        assert_eq!(queue.flush(&mut client, 2).delivered, vec![a.id.clone()]);
        queue.enqueue("s1", "b", InputKind::Prompt, 3).unwrap();

        queue.clear().unwrap();
        assert!(queue.is_empty());
        assert_eq!(queue.delivered_ids(), vec![a.id.as_str()]);
        assert!(!queue.enqueue_existing(a.clone()).unwrap());

        let c = queue.enqueue("s1", "c", InputKind::Prompt, 5).unwrap();
        queue.mark_delivered(&c.id).unwrap();
        assert!(queue.is_empty());
        assert_eq!(queue.delivered_ids(), vec![a.id.as_str(), c.id.as_str()]);
        let mut client = ScriptedClient::online(1);
        assert!(queue.flush(&mut client, 6).delivered.is_empty());
        assert!(client.attempts.is_empty());
    }

    #[test]
    fn mobile_offline_reconnect_resumes_after_a_valid_cursor() {
        let token = ResumeToken::new("s1", 3, 42);
        let mut client = ScriptedClient::online(3);
        assert_eq!(
            reconnect(&mut client, &token),
            ReconnectOutcome::Resumed { from_sequence: 42 }
        );
        assert!(!token.is_stale(3));
        assert!(token.is_stale(4));
    }

    #[test]
    fn mobile_offline_reconnect_snapshots_on_a_stale_or_refused_cursor() {
        let token = ResumeToken::new("s1", 3, 42);
        let mut stale = ScriptedClient::online(4);
        assert_eq!(reconnect(&mut stale, &token), ReconnectOutcome::SnapshotRequired);

        let mut refused = ScriptedClient::online(3);
        refused.generation_error = Some(ErrorCode::AttachCursorExpired);
        assert_eq!(reconnect(&mut refused, &token), ReconnectOutcome::SnapshotRequired);
    }

    #[test]
    fn mobile_offline_reconnect_reports_offline_and_keeps_the_token() {
        let token = ResumeToken::new("s1", 3, 42);
        let mut client = ScriptedClient::offline(4);
        assert_eq!(reconnect(&mut client, &token), ReconnectOutcome::Offline);
        assert_eq!(token, ResumeToken::new("s1", 3, 42));
    }

    #[test]
    fn mobile_offline_snapshot_does_not_lose_undelivered_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let mut queue = OfflineQueue::open_default(dir.path().join("queue.json")).unwrap();
        queue.enqueue("s1", "typed in a tunnel", InputKind::Prompt, 1).unwrap();
        queue.enqueue("s1", "and a steer", InputKind::Steer, 2).unwrap();

        let token = ResumeToken::new("s1", 1, 10);
        let mut client = ScriptedClient::online(2);
        assert_eq!(reconnect(&mut client, &token), ReconnectOutcome::SnapshotRequired);
        assert_eq!(queue.len(), 2, "a snapshot never wipes undelivered input");

        let report = queue.flush(&mut client, 3);
        assert_eq!(report.delivered.len(), 2);
        assert!(queue.is_empty());

        // After the snapshot the client attaches, then resumes from its new
        // cursor without replaying anything.
        let resumed = ResumeToken::new("s1", 2, 12);
        assert_eq!(
            reconnect(&mut client, &resumed),
            ReconnectOutcome::Resumed { from_sequence: 12 }
        );
        assert!(queue.is_empty());
    }

    #[test]
    fn mobile_offline_flush_does_not_move_the_transcript_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let mut queue = OfflineQueue::open_default(dir.path().join("queue.json")).unwrap();
        queue.enqueue("s1", "offline text", InputKind::Prompt, 1).unwrap();
        let token = ResumeToken::new("s1", 5, 10);

        let mut client = ScriptedClient::online(5);
        assert_eq!(queue.flush(&mut client, 2).delivered.len(), 1);
        assert_eq!(token.sequence, 10, "a flush does not move the transcript cursor");
        assert_eq!(token.generation, 5);
        assert_eq!(
            reconnect(&mut client, &token),
            ReconnectOutcome::Resumed { from_sequence: 10 }
        );
    }

    #[test]
    fn mobile_offline_notifications_redact_secrets() {
        let hex = "9f2c1d4e8a7b3c6d0e5f1a2b4c8d7e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9";
        let notification = notify(
            NotificationKind::Failed,
            "sess-sk-live-4f9a2b7c8d1e",
            &format!(
                "token=abcd1234 Authorization: Bearer abcDEF123456 key sk-live-4f9a2b7c8d1e digest {hex}"
            ),
            1_000,
        );

        let rendered = format!("{} {} {}", notification.id, notification.title, notification.body);
        for secret in [
            "sk-live-4f9a2b7c8d1e",
            "abcd1234",
            "abcDEF123456",
            hex,
        ] {
            assert!(!rendered.contains(secret), "notification leaked `{secret}`: {rendered}");
        }
        assert!(notification.body.contains("<redacted>"));
        assert_eq!(notification.action, NotificationAction::OpenSession);
        assert_eq!(notification.title, "Run failed");
        assert!(!notification.body.contains('\n'));

        let lock = notification.lock_screen_line();
        assert!(lock.starts_with("Run failed"));
        assert!(!lock.contains("token="));
        assert!(!lock.contains("sk-live"));

        let approval = notify(NotificationKind::Approval, "s1", "action 7f3a", 2_000);
        assert_eq!(approval.action, NotificationAction::Approve);
        assert!(approval.lock_screen_line().contains("approve"));
    }

    #[test]
    fn mobile_offline_notifications_are_bounded_and_evict_the_oldest() {
        let mut outbox = NotificationOutbox::new(2);
        assert!(outbox.notify(NotificationKind::Completed, "s1", "one", 1).is_none());
        assert!(outbox.notify(NotificationKind::Failed, "s1", "two", 2).is_none());
        let evicted = outbox
            .notify(NotificationKind::Approval, "s1", "three", 3)
            .expect("the third notice evicts the oldest");
        assert_eq!(evicted.body, "s1 · one");
        let dropped = outbox.push(notify(NotificationKind::Completed, "s1", "four", 4)).unwrap();
        assert_eq!(dropped.body, "s1 · two");
        assert_eq!(outbox.len(), 2);

        let long = notify(NotificationKind::Failed, "s1", &"a".repeat(500), 5);
        assert!(long.body.chars().count() <= MAX_NOTIFICATION_BODY_CHARS);
        assert!(long.title.chars().count() <= MAX_NOTIFICATION_TITLE_CHARS);
        assert!(long.body.ends_with('…'));
    }

    #[test]
    fn mobile_offline_notification_sink_is_a_bounded_transport_seam() {
        let mut outbox = NotificationOutbox::new(4);
        outbox.notify(NotificationKind::Completed, "s1", "done", 1);
        outbox.notify(NotificationKind::Failed, "s1", "boom", 2);

        let mut sink = RecordingSink::default();
        assert_eq!(outbox.drain_into(&mut sink).unwrap(), 2);
        assert_eq!(sink.seen.len(), 2);
        assert_eq!(sink.seen[0].title, "Run complete");
        assert!(outbox.is_empty());

        outbox.notify(NotificationKind::Approval, "s1", "approve me", 3);
        let mut broken = RecordingSink { fail: true, ..RecordingSink::default() };
        assert!(outbox.drain_into(&mut broken).is_err());
        assert_eq!(outbox.len(), 1, "a failed transport keeps the notice queued");

        assert_ne!(
            NotificationTransport::ForegroundService,
            NotificationTransport::UnifiedPush
        );
    }

    #[test]
    fn mobile_offline_module_has_no_network_code() {
        let source = include_str!("mobile_offline.rs");
        let banned = [
            ["std::", "net"].concat(),
            ["Tcp", "Listener"].concat(),
            ["Tcp", "Stream"].concat(),
            ["Udp", "Socket"].concat(),
            ["req", "west"].concat(),
            ["hyper", "::"].concat(),
            ["http", "://"].concat(),
            ["0.0.", "0.0"].concat(),
        ];
        for token in banned {
            assert!(
                !source.contains(&token),
                "mobile_offline must stay transport-free; found `{token}`"
            );
        }
    }
}
