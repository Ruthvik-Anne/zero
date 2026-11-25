//! Android session control (T-AND-02, AND-02, AND-03).
//!
//! After pairing (see [`crate::android_pairing`]) the phone is a remote control
//! for one host. This module is the phone-side model of that control: list the
//! host's sessions, open one, page through its transcript, send a prompt, steer
//! a running turn, inspect the queue, cancel the turn, and read the working-tree
//! diff.
//!
//! # The seam
//!
//! [`MeshSessionClient`] is the whole transport surface. Every method is a plain
//! request/response: no socket, no URL, no listener, and no retry loop. The mesh
//! (or loopback when both processes run on one machine) implements the trait.
//! The seam carries no credential: a paired session token authorises the mesh
//! connection, not these calls, so nothing here can print or serialise it.
//!
//! # The controller
//!
//! [`AndroidSessionController`] holds the client, the open session id, and the
//! transcript cursor. A screen calls the controller and never the client, so
//! validation, bounds, ordering, cursor continuity, and stable error codes live
//! in one place:
//!
//! - Ids must be non-empty, at most [`MAX_ID_CHARS`] characters, and free of
//!   control characters. Ids and cursors that arrive *from* the mesh are checked
//!   the same way: a peer that returns a malformed one is refused with
//!   `zero.fnd.invalid_input` instead of being rendered or echoed back.
//! - Prompt and steer text is bounded ([`MAX_PROMPT_CHARS`],
//!   [`MAX_STEER_CHARS`]) and must not carry control characters other than
//!   `\n` and `\t`.
//! - A transcript page is bounded to [`MAX_TRANSCRIPT_ENTRIES`] entries, one
//!   entry to [`MAX_TRANSCRIPT_ENTRY_CHARS`] characters, and a diff to
//!   [`MAX_DIFF_FILES`] files with a patch of at most
//!   [`MAX_DIFF_PATCH_BYTES`] bytes.
//! - Every list is ordered deterministically: sessions by newest first then id,
//!   diffs by path. The queue keeps its own order because it is a queue.
//!
//! # Delivery
//!
//! [`DeliveryMode`] is explicit, never inferred from the phone's clock:
//! [`DeliveryMode::Steer`] applies at the running turn's next safe boundary,
//! [`DeliveryMode::FollowUp`] is the next user message, and
//! [`DeliveryMode::Queue`] holds the text in the durable queue. `send_prompt`
//! defaults to `Queue` so a tap never interrupts a turn; `steer` and
//! `send_prompt_with` are the explicit overrides.
//!
//! # Errors
//!
//! [`MeshSessionClient`] returns typed [`ZeroError`]s. The controller re-words
//! the transport ones with retry guidance and keeps the code stable:
//!
//! - `zero.fnd.offline` and `zero.fnd.unavailable` — the host is unreachable or
//!   its session service is off; the request was not applied and can be retried.
//! - `zero.ses.cursor_expired` — the transcript generation changed; the
//!   controller clears its cursor so the next call refreshes from a snapshot.
//! - `zero.ses.not_found` — the session is not on this host.

use std::fmt;

use serde::{Deserialize, Serialize};
use zero_types::error::{ErrorCode, Result, ZeroError};

/// The transport session control uses. There is no public endpoint: the phone
/// dials the paired host over the authenticated mesh, or over loopback when both
/// run on one machine. This module opens no socket.
pub const SESSION_TRANSPORT: &str =
    "mesh or loopback only; this module holds a transport seam and opens no socket";

/// Cap on a session id, an entry id, or a cursor, in characters.
pub const MAX_ID_CHARS: usize = 128;

/// Cap on a session name, in characters.
pub const MAX_SESSION_NAME_CHARS: usize = 120;

/// Cap on a session state label, in characters.
pub const MAX_STATE_CHARS: usize = 32;

/// Cap on a transcript role label, in characters.
pub const MAX_ROLE_CHARS: usize = 32;

/// Cap on the sessions one list call may return.
pub const MAX_SESSIONS: usize = 200;

/// Cap on the entries one transcript page may return.
pub const MAX_TRANSCRIPT_ENTRIES: usize = 200;

/// Cap on one transcript entry's text, in characters.
pub const MAX_TRANSCRIPT_ENTRY_CHARS: usize = 4_000;

/// Cap on the queued items one `queue` call may return.
pub const MAX_QUEUE_ITEMS: usize = 100;

/// Cap on one queued item's text, in characters.
pub const MAX_QUEUED_TEXT_CHARS: usize = 2_000;

/// Cap on a prompt, in characters.
pub const MAX_PROMPT_CHARS: usize = 8_192;

/// Cap on a steer, in characters. Steering must fit a boundary, so it is
/// shorter than a prompt.
pub const MAX_STEER_CHARS: usize = 2_048;

/// Cap on the files one diff call may return.
pub const MAX_DIFF_FILES: usize = 200;

/// Cap on a diff path, in characters. A truncated path is display-only.
pub const MAX_DIFF_PATH_CHARS: usize = 512;

/// Cap on one file's patch, in bytes.
pub const MAX_DIFF_PATCH_BYTES: usize = 16 * 1024;

/// Marker appended to a truncated patch or path.
const TRUNCATION_MARKER: &str = "…";

/// Marker appended to a truncated patch, on its own line.
const PATCH_TRUNCATION_MARKER: &str = "\n… [patch truncated]";

/// One row of the host's session list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummary {
    pub id: String,
    pub name: String,
    /// Host-defined state label, e.g. `idle`, `running`, `awaiting_input`.
    pub state: String,
    /// Last activity, in milliseconds since the Unix epoch.
    pub updated_ms: u64,
    /// Unread entries since this device last read the session.
    pub unread: usize,
}

/// One transcript entry.
///
/// `cursor` is the cursor that resumes *after* this entry. It lets the
/// controller trim a page to the caller's limit without losing the entries it
/// did not render: the next call resumes exactly at the first dropped entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptEntry {
    pub cursor: String,
    pub id: String,
    /// Host-defined role label, e.g. `user`, `assistant`, `tool`, `system`.
    pub role: String,
    pub text: String,
    /// When the entry was recorded, in milliseconds since the Unix epoch.
    pub at_ms: u64,
}

/// One page of a transcript. `next_cursor` is `None` at the end of the stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptPage {
    pub entries: Vec<TranscriptEntry>,
    pub next_cursor: Option<String>,
}

/// One item in the host's durable input queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedItemView {
    pub id: String,
    pub text: String,
    /// Host-defined state label, e.g. `pending`, `steering`, `delivered`.
    pub state: String,
}

/// One changed file. The patch is unified-diff text, bounded to
/// [`MAX_DIFF_PATCH_BYTES`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDiff {
    pub path: String,
    pub additions: u32,
    pub deletions: u32,
    pub patch: String,
}

/// The host's acknowledgement of a prompt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptAck {
    pub session_id: String,
    /// True when the host durably queued the text instead of applying it at
    /// once (it arrived during a running turn).
    pub queued: bool,
    pub text_chars: usize,
}

/// The host's acknowledgement of a steer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SteerAck {
    pub session_id: String,
    /// The boundary the text will be applied at, e.g. `next_safe_boundary`.
    pub boundary: String,
}

/// How a message is delivered to a session that may be running a turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMode {
    /// Apply at the running turn's next safe boundary. Never rewrites a tool
    /// call already executing.
    Steer,
    /// Deliver as the next user message once the turn ends.
    FollowUp,
    /// Hold in the durable queue until the user sends it.
    Queue,
}

impl DeliveryMode {
    pub fn as_str(self) -> &'static str {
        match self {
            DeliveryMode::Steer => "steer",
            DeliveryMode::FollowUp => "follow_up",
            DeliveryMode::Queue => "queue",
        }
    }
}

/// What the controller actually did with a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryAck {
    pub session_id: String,
    pub delivery: DeliveryMode,
    /// True when the host reported the text as queued rather than applied.
    pub queued: bool,
    pub text_chars: usize,
}

/// The mesh (or loopback) session transport.
///
/// Implementors do one round trip per call. Errors must be typed; the controller
/// maps transport codes to retry guidance and keeps everything else.
pub trait MeshSessionClient {
    fn list(&self) -> Result<Vec<SessionSummary>>;
    fn transcript(&self, id: &str, cursor: Option<&str>) -> Result<TranscriptPage>;
    fn prompt(&self, id: &str, text: &str) -> Result<PromptAck>;
    fn steer(&self, id: &str, text: &str) -> Result<SteerAck>;
    fn queue(&self, id: &str) -> Result<Vec<QueuedItemView>>;
    fn cancel(&self, id: &str) -> Result<()>;
    fn diff(&self, id: &str) -> Result<Vec<FileDiff>>;
}

/// The phone's session-control state: one client, one open session, one cursor.
pub struct AndroidSessionController<C: MeshSessionClient> {
    client: C,
    session_id: Option<String>,
    cursor: Option<String>,
}

impl<C: MeshSessionClient> fmt::Debug for AndroidSessionController<C> {
    /// Prints the open session and cursor only. The client may hold a mesh
    /// credential, so it is never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AndroidSessionController")
            .field("session_id", &self.session_id)
            .field("cursor", &self.cursor)
            .finish_non_exhaustive()
    }
}

impl<C: MeshSessionClient> AndroidSessionController<C> {
    pub fn new(client: C) -> Self {
        Self {
            client,
            session_id: None,
            cursor: None,
        }
    }

    /// The open session id, if any.
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// The cursor the next transcript call resumes from. `None` means "start
    /// from a fresh snapshot".
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }

    /// List the host's sessions, newest first, then by id.
    pub fn list_sessions(&self) -> Result<Vec<SessionSummary>> {
        let sessions = self.client.list().map_err(map_transport)?;
        let mut cleaned = Vec::with_capacity(sessions.len().min(MAX_SESSIONS));
        for summary in sessions {
            cleaned.push(clean_summary(summary)?);
        }
        cleaned.sort_by(|a, b| {
            b.updated_ms
                .cmp(&a.updated_ms)
                .then_with(|| a.id.cmp(&b.id))
        });
        cleaned.truncate(MAX_SESSIONS);
        Ok(cleaned)
    }

    /// Open one session: check the id against the host's list, then reset the
    /// cursor so the first transcript page is a snapshot.
    ///
    /// This is one extra `list` round trip on purpose: an unknown id is
    /// `zero.ses.not_found` here, before any transcript or prompt is sent.
    pub fn open(&mut self, id: &str) -> Result<SessionSummary> {
        validate_id("session id", id)?;
        let sessions = self.list_sessions()?;
        let summary = sessions
            .into_iter()
            .find(|summary| summary.id == id)
            .ok_or_else(|| {
                ZeroError::new(
                    ErrorCode::SessionNotFound,
                    format!(
                        "session `{}` is not on this host; list sessions and open one that exists",
                        one_line(id)
                    ),
                )
            })?;
        self.session_id = Some(summary.id.clone());
        self.cursor = None;
        Ok(summary)
    }

    /// The next transcript page under the caller's limit.
    ///
    /// The cursor is kept across calls. A page larger than `limit` is trimmed
    /// and the cursor is set to the last kept entry's cursor, so the next call
    /// resumes at the first entry that was not shown. A stale cursor is
    /// `zero.ses.cursor_expired`, the controller clears it, and the next call
    /// refreshes from a snapshot.
    pub fn transcript(&mut self, limit: usize) -> Result<TranscriptPage> {
        if limit == 0 {
            return Err(invalid(
                "a transcript page needs a positive limit; ask for at least one entry",
            ));
        }
        if limit > MAX_TRANSCRIPT_ENTRIES {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "a transcript page may hold at most {MAX_TRANSCRIPT_ENTRIES} entries; \
                     {limit} was requested"
                ),
            ));
        }
        let id = self.require_session()?;
        let requested = self.cursor.clone();
        let page = match self.client.transcript(&id, requested.as_deref()) {
            Ok(page) => page,
            Err(error) => {
                if error.code() == ErrorCode::AttachCursorExpired {
                    self.cursor = None;
                    return Err(cursor_expired(requested.is_some(), &error));
                }
                return Err(map_transport(error));
            }
        };

        let mut entries = Vec::with_capacity(page.entries.len().min(limit));
        for entry in page.entries {
            entries.push(clean_entry(entry)?);
        }
        let mut next_cursor = match page.next_cursor {
            Some(cursor) => Some(wire_id("transcript cursor", cursor)?),
            None => None,
        };
        if entries.len() > limit {
            entries.truncate(limit);
            next_cursor = entries.last().map(|entry| entry.cursor.clone());
        }

        self.cursor = next_cursor.clone();
        Ok(TranscriptPage {
            entries,
            next_cursor,
        })
    }

    /// Send a prompt with the default delivery mode, [`DeliveryMode::Queue`].
    ///
    /// Queue is the default because a tap must never interrupt a turn that is
    /// already running; use [`Self::steer`] or [`Self::send_prompt_with`] to be
    /// explicit.
    pub fn send_prompt(&mut self, text: &str) -> Result<DeliveryAck> {
        self.send_prompt_with(text, DeliveryMode::Queue)
    }

    /// Send a prompt with an explicit delivery mode.
    pub fn send_prompt_with(&mut self, text: &str, mode: DeliveryMode) -> Result<DeliveryAck> {
        let id = self.require_session()?;
        match mode {
            DeliveryMode::Steer => {
                validate_text("steer", text, MAX_STEER_CHARS)?;
                let ack = self.client.steer(&id, text).map_err(map_transport)?;
                check_ack("steer", &ack.session_id, &id)?;
                Ok(DeliveryAck {
                    session_id: id,
                    delivery: mode,
                    queued: false,
                    text_chars: text.chars().count(),
                })
            }
            DeliveryMode::FollowUp | DeliveryMode::Queue => {
                validate_text("prompt", text, MAX_PROMPT_CHARS)?;
                let ack = self.client.prompt(&id, text).map_err(map_transport)?;
                check_ack("prompt", &ack.session_id, &id)?;
                Ok(DeliveryAck {
                    session_id: id,
                    delivery: mode,
                    queued: ack.queued,
                    text_chars: text.chars().count(),
                })
            }
        }
    }

    /// Steer the running turn at its next safe boundary.
    pub fn steer(&mut self, text: &str) -> Result<DeliveryAck> {
        self.send_prompt_with(text, DeliveryMode::Steer)
    }

    /// The host's durable input queue, in queue order.
    pub fn queue(&self) -> Result<Vec<QueuedItemView>> {
        let id = self.require_session()?;
        let items = self.client.queue(&id).map_err(map_transport)?;
        let mut cleaned = Vec::with_capacity(items.len().min(MAX_QUEUE_ITEMS));
        for item in items {
            cleaned.push(clean_queued(item)?);
        }
        cleaned.truncate(MAX_QUEUE_ITEMS);
        Ok(cleaned)
    }

    /// Cancel the running turn.
    ///
    /// Idempotent: a second cancel — or a cancel of a session whose turn has
    /// already ended (`zero.ses.closed`) — is a success, because "not running"
    /// is the state the caller asked for. The host owns de-duplication; the
    /// controller never turns a repeat into a conflict.
    pub fn cancel(&mut self) -> Result<()> {
        let id = self.require_session()?;
        match self.client.cancel(&id) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == ErrorCode::SessionClosed => Ok(()),
            Err(error) => Err(map_transport(error)),
        }
    }

    /// The working-tree diff, ordered by path and bounded.
    pub fn diff(&self) -> Result<Vec<FileDiff>> {
        let id = self.require_session()?;
        let diffs = self.client.diff(&id).map_err(map_transport)?;
        let mut cleaned = Vec::with_capacity(diffs.len().min(MAX_DIFF_FILES));
        for diff in diffs {
            cleaned.push(clean_diff(diff));
        }
        cleaned.sort_by(|a, b| a.path.cmp(&b.path));
        cleaned.truncate(MAX_DIFF_FILES);
        Ok(cleaned)
    }

    fn require_session(&self) -> Result<String> {
        self.session_id.clone().ok_or_else(|| {
            ZeroError::new(
                ErrorCode::SessionNotFound,
                "no session is open; list sessions and call open with an id first",
            )
        })
    }
}

/// Validate an id the phone supplies.
fn validate_id(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(invalid(format!(
            "a {field} must not be empty; pick one from the session list"
        )));
    }
    if value.chars().count() > MAX_ID_CHARS {
        return Err(invalid(format!(
            "a {field} may be at most {MAX_ID_CHARS} characters"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid(format!(
            "a {field} must not contain control characters; pick one from the session list"
        )));
    }
    Ok(())
}

/// Validate text the phone supplies before it reaches the mesh.
fn validate_text(field: &str, text: &str, max: usize) -> Result<()> {
    let chars = text.chars().count();
    if text.trim().is_empty() {
        return Err(invalid(format!(
            "a {field} must not be empty; type the message on the phone"
        )));
    }
    if chars > max {
        return Err(ZeroError::new(
            ErrorCode::LimitExceeded,
            format!("a {field} may be at most {max} characters; {chars} were sent"),
        ));
    }
    if let Some(ch) = text
        .chars()
        .find(|ch| ch.is_control() && *ch != '\n' && *ch != '\t')
    {
        return Err(invalid(format!(
            "a {field} must not contain the control character U+{:04X}; paste plain text",
            u32::from(ch)
        )));
    }
    Ok(())
}

/// Validate an id or cursor that arrived from the mesh. A malformed value is
/// refused rather than rendered or echoed back into a request.
fn wire_id(field: &str, value: String) -> Result<String> {
    if value.is_empty()
        || value.chars().count() > MAX_ID_CHARS
        || value.chars().any(char::is_control)
    {
        return Err(invalid(format!(
            "the mesh returned a {field} that is empty, longer than {MAX_ID_CHARS} \
             characters, or contains control characters; refuse this response and retry"
        )));
    }
    Ok(value)
}

fn clean_summary(mut summary: SessionSummary) -> Result<SessionSummary> {
    summary.id = wire_id("session id", summary.id)?;
    summary.name = one_line_bounded(&summary.name, MAX_SESSION_NAME_CHARS);
    if summary.name.is_empty() {
        summary.name = "untitled session".into();
    }
    summary.state = one_line_bounded(&summary.state, MAX_STATE_CHARS);
    if summary.state.is_empty() {
        summary.state = "unknown".into();
    }
    Ok(summary)
}

fn clean_entry(mut entry: TranscriptEntry) -> Result<TranscriptEntry> {
    entry.cursor = wire_id("transcript cursor", entry.cursor)?;
    entry.id = wire_id("transcript entry id", entry.id)?;
    entry.role = one_line_bounded(&entry.role, MAX_ROLE_CHARS);
    if entry.role.is_empty() {
        entry.role = "unknown".into();
    }
    entry.text = sanitize(&entry.text, MAX_TRANSCRIPT_ENTRY_CHARS);
    Ok(entry)
}

fn clean_queued(mut item: QueuedItemView) -> Result<QueuedItemView> {
    item.id = wire_id("queue item id", item.id)?;
    item.state = one_line_bounded(&item.state, MAX_STATE_CHARS);
    if item.state.is_empty() {
        item.state = "unknown".into();
    }
    item.text = sanitize(&item.text, MAX_QUEUED_TEXT_CHARS);
    Ok(item)
}

/// Bound one diff. A long patch ends with [`PATCH_TRUNCATION_MARKER`]; a long
/// path ends with [`TRUNCATION_MARKER`] and is then display-only.
fn clean_diff(mut diff: FileDiff) -> FileDiff {
    diff.path = one_line_bounded(&diff.path, MAX_DIFF_PATH_CHARS);
    if diff.path.is_empty() {
        diff.path = "unknown path".into();
    }
    diff.patch = bound_patch(diff.patch);
    diff
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
    bound_chars(&line, max, TRUNCATION_MARKER)
}

/// Keep `\n` and `\t`, replace every other control character with a space, and
/// bound the result. Only `max` characters are ever copied, so a hostile peer
/// cannot make the phone build an unbounded string.
fn sanitize(text: &str, max: usize) -> String {
    let mut out = String::with_capacity(text.len().min(max * 4));
    for ch in text.chars().take(max) {
        if ch == '\n' || ch == '\t' {
            out.push(ch);
        } else if ch.is_control() {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    if text.chars().count() > max {
        let keep = max.saturating_sub(TRUNCATION_MARKER.chars().count());
        out = out
            .chars()
            .take(keep)
            .chain(TRUNCATION_MARKER.chars())
            .collect();
    }
    out
}

/// Bound `text` to `max` characters, ending a cut value with `marker`.
fn bound_chars(text: &str, max: usize, marker: &str) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let keep = max.saturating_sub(marker.chars().count());
    let mut out: String = text.chars().take(keep).collect();
    out.push_str(marker);
    out
}

/// Bound a patch to [`MAX_DIFF_PATCH_BYTES`] on a character boundary.
fn bound_patch(patch: String) -> String {
    if patch.len() <= MAX_DIFF_PATCH_BYTES {
        return patch;
    }
    let budget = MAX_DIFF_PATCH_BYTES.saturating_sub(PATCH_TRUNCATION_MARKER.len());
    let end = floor_char_boundary(&patch, budget);
    let mut out = String::with_capacity(end + PATCH_TRUNCATION_MARKER.len());
    out.push_str(&patch[..end]);
    out.push_str(PATCH_TRUNCATION_MARKER);
    out
}

fn floor_char_boundary(text: &str, max_bytes: usize) -> usize {
    if text.len() <= max_bytes {
        return text.len();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// Re-word a transport failure with retry guidance, keeping the stable code.
fn map_transport(error: ZeroError) -> ZeroError {
    match error.code() {
        ErrorCode::Offline => ZeroError::new(
            ErrorCode::Offline,
            format!(
                "the mesh host is unreachable, so nothing was sent; reconnect and retry: {}",
                error.message()
            ),
        ),
        ErrorCode::Unavailable => ZeroError::new(
            ErrorCode::Unavailable,
            format!(
                "the host's session service is unavailable; retry when it is enabled: {}",
                error.message()
            ),
        ),
        ErrorCode::Timeout => ZeroError::new(
            ErrorCode::Timeout,
            format!(
                "the mesh host did not answer in time; retry the same request: {}",
                error.message()
            ),
        ),
        _ => error,
    }
}

/// A stale cursor: the controller has already cleared it, so the next call
/// refreshes from a snapshot.
fn cursor_expired(had_cursor: bool, error: &ZeroError) -> ZeroError {
    let guidance = if had_cursor {
        "the transcript cursor is stale because the session was compacted or resumed; \
         the cursor was cleared — call transcript again to refresh from the snapshot"
    } else {
        "the host reported a stale cursor for a fresh request; the cursor was cleared — \
         call transcript again to refresh from the snapshot"
    };
    ZeroError::new(
        ErrorCode::AttachCursorExpired,
        format!("{guidance}: {}", error.message()),
    )
}

/// A client must answer for the session it was asked about.
fn check_ack(field: &str, reported: &str, expected: &str) -> Result<()> {
    if reported != expected {
        return Err(invalid(format!(
            "the mesh acknowledged the {field} for a different session; refuse this response"
        )));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    const TOKEN: &str = "Bearer sk-live-9f2c-should-never-render";

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        List,
        Transcript { id: String, cursor: Option<String> },
        Prompt { id: String, text: String },
        Steer { id: String, text: String },
        Queue { id: String },
        Cancel { id: String },
        Diff { id: String },
    }

    struct Scripted {
        token: String,
        calls: RefCell<Vec<Call>>,
        lists: RefCell<VecDeque<Result<Vec<SessionSummary>>>>,
        transcripts: RefCell<VecDeque<Result<TranscriptPage>>>,
        prompts: RefCell<VecDeque<Result<PromptAck>>>,
        steers: RefCell<VecDeque<Result<SteerAck>>>,
        queues: RefCell<VecDeque<Result<Vec<QueuedItemView>>>>,
        cancels: RefCell<VecDeque<Result<()>>>,
        diffs: RefCell<VecDeque<Result<Vec<FileDiff>>>>,
    }

    impl Scripted {
        fn new() -> Self {
            Self {
                token: TOKEN.into(),
                calls: RefCell::new(Vec::new()),
                lists: RefCell::new(VecDeque::new()),
                transcripts: RefCell::new(VecDeque::new()),
                prompts: RefCell::new(VecDeque::new()),
                steers: RefCell::new(VecDeque::new()),
                queues: RefCell::new(VecDeque::new()),
                cancels: RefCell::new(VecDeque::new()),
                diffs: RefCell::new(VecDeque::new()),
            }
        }

        fn push_list(&self, response: Result<Vec<SessionSummary>>) {
            self.lists.borrow_mut().push_back(response);
        }

        fn push_transcript(&self, response: Result<TranscriptPage>) {
            self.transcripts.borrow_mut().push_back(response);
        }

        fn push_prompt(&self, response: Result<PromptAck>) {
            self.prompts.borrow_mut().push_back(response);
        }

        fn push_steer(&self, response: Result<SteerAck>) {
            self.steers.borrow_mut().push_back(response);
        }

        fn push_queue(&self, response: Result<Vec<QueuedItemView>>) {
            self.queues.borrow_mut().push_back(response);
        }

        fn push_cancel(&self, response: Result<()>) {
            self.cancels.borrow_mut().push_back(response);
        }

        fn push_diff(&self, response: Result<Vec<FileDiff>>) {
            self.diffs.borrow_mut().push_back(response);
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.borrow().clone()
        }
    }

    fn next<T>(queue: &RefCell<VecDeque<T>>, what: &str) -> T {
        queue
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| panic!("the script has no {what} response left"))
    }

    impl MeshSessionClient for Scripted {
        fn list(&self) -> Result<Vec<SessionSummary>> {
            self.calls.borrow_mut().push(Call::List);
            next(&self.lists, "list")
        }

        fn transcript(&self, id: &str, cursor: Option<&str>) -> Result<TranscriptPage> {
            self.calls.borrow_mut().push(Call::Transcript {
                id: id.to_string(),
                cursor: cursor.map(str::to_string),
            });
            next(&self.transcripts, "transcript")
        }

        fn prompt(&self, id: &str, text: &str) -> Result<PromptAck> {
            self.calls.borrow_mut().push(Call::Prompt {
                id: id.to_string(),
                text: text.to_string(),
            });
            next(&self.prompts, "prompt")
        }

        fn steer(&self, id: &str, text: &str) -> Result<SteerAck> {
            self.calls.borrow_mut().push(Call::Steer {
                id: id.to_string(),
                text: text.to_string(),
            });
            next(&self.steers, "steer")
        }

        fn queue(&self, id: &str) -> Result<Vec<QueuedItemView>> {
            self.calls
                .borrow_mut()
                .push(Call::Queue { id: id.to_string() });
            next(&self.queues, "queue")
        }

        fn cancel(&self, id: &str) -> Result<()> {
            self.calls
                .borrow_mut()
                .push(Call::Cancel { id: id.to_string() });
            next(&self.cancels, "cancel")
        }

        fn diff(&self, id: &str) -> Result<Vec<FileDiff>> {
            self.calls
                .borrow_mut()
                .push(Call::Diff { id: id.to_string() });
            next(&self.diffs, "diff")
        }
    }

    /// The controller takes one client, tests keep a handle to inspect calls.
    impl MeshSessionClient for Rc<Scripted> {
        fn list(&self) -> Result<Vec<SessionSummary>> {
            (**self).list()
        }
        fn transcript(&self, id: &str, cursor: Option<&str>) -> Result<TranscriptPage> {
            (**self).transcript(id, cursor)
        }
        fn prompt(&self, id: &str, text: &str) -> Result<PromptAck> {
            (**self).prompt(id, text)
        }
        fn steer(&self, id: &str, text: &str) -> Result<SteerAck> {
            (**self).steer(id, text)
        }
        fn queue(&self, id: &str) -> Result<Vec<QueuedItemView>> {
            (**self).queue(id)
        }
        fn cancel(&self, id: &str) -> Result<()> {
            (**self).cancel(id)
        }
        fn diff(&self, id: &str) -> Result<Vec<FileDiff>> {
            (**self).diff(id)
        }
    }

    fn summary(
        id: &str,
        name: &str,
        state: &str,
        updated_ms: u64,
        unread: usize,
    ) -> SessionSummary {
        SessionSummary {
            id: id.into(),
            name: name.into(),
            state: state.into(),
            updated_ms,
            unread,
        }
    }

    fn entry(cursor: &str, id: &str, role: &str, text: &str) -> TranscriptEntry {
        TranscriptEntry {
            cursor: cursor.into(),
            id: id.into(),
            role: role.into(),
            text: text.into(),
            at_ms: 1_700_000_000_000,
        }
    }

    fn page(entries: Vec<TranscriptEntry>, next_cursor: Option<&str>) -> TranscriptPage {
        TranscriptPage {
            entries,
            next_cursor: next_cursor.map(str::to_string),
        }
    }

    fn queued(id: &str, text: &str, state: &str) -> QueuedItemView {
        QueuedItemView {
            id: id.into(),
            text: text.into(),
            state: state.into(),
        }
    }

    fn diff(path: &str, additions: u32, deletions: u32, patch: &str) -> FileDiff {
        FileDiff {
            path: path.into(),
            additions,
            deletions,
            patch: patch.into(),
        }
    }

    fn prompt_ack(session: &str, queued: bool, text_chars: usize) -> PromptAck {
        PromptAck {
            session_id: session.into(),
            queued,
            text_chars,
        }
    }

    fn steer_ack(session: &str) -> SteerAck {
        SteerAck {
            session_id: session.into(),
            boundary: "next_safe_boundary".into(),
        }
    }

    fn scripted() -> (Rc<Scripted>, AndroidSessionController<Rc<Scripted>>) {
        let client = Rc::new(Scripted::new());
        let controller = AndroidSessionController::new(Rc::clone(&client));
        (client, controller)
    }

    fn opened(client: &Rc<Scripted>) -> AndroidSessionController<Rc<Scripted>> {
        let mut controller = AndroidSessionController::new(Rc::clone(client));
        client.push_list(Ok(vec![summary("s1", "fix the build", "idle", 1_000, 2)]));
        controller.open("s1").expect("the scripted session opens");
        controller
    }

    fn code_of<T: fmt::Debug>(result: Result<T>) -> ErrorCode {
        result.expect_err("the call should fail").code()
    }

    #[test]
    fn android_session_a_full_flow_drives_every_action_in_order() {
        let (client, mut controller) = scripted();
        client.push_list(Ok(vec![
            summary("s1", "fix the build", "running", 2_000, 3),
            summary("s2", "review docs", "idle", 1_000, 0),
        ]));
        // `open` re-lists so an unknown id fails before any transcript request.
        client.push_list(Ok(vec![summary(
            "s1",
            "fix the build",
            "running",
            2_000,
            3,
        )]));
        client.push_transcript(Ok(page(
            vec![
                entry("c1", "e1", "user", "the tests fail"),
                entry("c2", "e2", "assistant", "looking"),
            ],
            Some("c2"),
        )));
        client.push_prompt(Ok(prompt_ack("s1", true, 8)));
        client.push_steer(Ok(steer_ack("s1")));
        client.push_queue(Ok(vec![queued("q1", "run the tests", "pending")]));
        client.push_diff(Ok(vec![diff("src/a.rs", 3, 1, "@@ -1 +1 @@")]));
        client.push_cancel(Ok(()));

        let sessions = controller.list_sessions().expect("list");
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].id, "s1", "newest first");
        assert_eq!(sessions[0].unread, 3);

        let opened = controller.open("s1").expect("open");
        assert_eq!(opened.state, "running");
        assert_eq!(controller.session_id(), Some("s1"));
        assert_eq!(controller.cursor(), None, "open resets to a snapshot");

        let page = controller.transcript(10).expect("transcript");
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.next_cursor.as_deref(), Some("c2"));
        assert_eq!(controller.cursor(), Some("c2"));

        let prompt = controller.send_prompt("fix it").expect("prompt");
        assert_eq!(prompt.delivery, DeliveryMode::Queue);
        assert!(prompt.queued);
        assert_eq!(prompt.text_chars, 6);

        let steer = controller.steer("use the small fixture").expect("steer");
        assert_eq!(steer.delivery, DeliveryMode::Steer);
        assert!(!steer.queued);

        let queue = controller.queue().expect("queue");
        assert_eq!(queue, vec![queued("q1", "run the tests", "pending")]);

        let diffs = controller.diff().expect("diff");
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "src/a.rs");

        controller.cancel().expect("cancel");

        assert_eq!(
            client.calls(),
            vec![
                Call::List,
                Call::List,
                Call::Transcript {
                    id: "s1".into(),
                    cursor: None
                },
                Call::Prompt {
                    id: "s1".into(),
                    text: "fix it".into()
                },
                Call::Steer {
                    id: "s1".into(),
                    text: "use the small fixture".into()
                },
                Call::Queue { id: "s1".into() },
                Call::Diff { id: "s1".into() },
                Call::Cancel { id: "s1".into() },
            ],
            "the full flow reaches the mesh once per action, in order"
        );
    }

    #[test]
    fn android_session_pages_keep_the_cursor_and_refresh_after_it_expires() {
        let client = Rc::new(Scripted::new());
        let mut controller = opened(&client);

        client.push_transcript(Ok(page(
            vec![
                entry("c1", "e1", "user", "one"),
                entry("c2", "e2", "assistant", "two"),
            ],
            Some("c2"),
        )));
        let first = controller.transcript(10).expect("first page");
        assert_eq!(first.next_cursor.as_deref(), Some("c2"));
        assert_eq!(controller.cursor(), Some("c2"));

        client.push_transcript(Ok(page(
            vec![entry("c3", "e3", "assistant", "three")],
            None,
        )));
        let second = controller.transcript(10).expect("second page");
        assert_eq!(second.entries[0].id, "e3");
        assert_eq!(second.next_cursor, None);
        assert_eq!(controller.cursor(), None, "the stream ended");

        // A stale cursor clears itself and says how to refresh.
        let client = Rc::new(Scripted::new());
        let mut fresh = opened(&client);
        client.push_transcript(Ok(page(vec![entry("c1", "e1", "user", "one")], Some("c1"))));
        fresh.transcript(10).expect("prime the cursor");
        client.push_transcript(Err(ZeroError::new(
            ErrorCode::AttachCursorExpired,
            "generation 4 moved to 5",
        )));
        let error = fresh.transcript(10).expect_err("the cursor is stale");
        assert_eq!(error.code(), ErrorCode::AttachCursorExpired);
        assert_eq!(error.code().as_str(), "zero.ses.cursor_expired");
        assert!(error.message().contains("snapshot"), "{error}");
        assert_eq!(fresh.cursor(), None, "the stale cursor is dropped");

        client.push_transcript(Ok(page(vec![entry("n1", "n1", "system", "fresh")], None)));
        fresh.transcript(10).expect("a retry snapshots");
        let cursors: Vec<Option<String>> = client
            .calls()
            .iter()
            .filter_map(|call| match call {
                Call::Transcript { cursor, .. } => Some(cursor.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(
            cursors,
            vec![None, Some("c1".into()), None],
            "the stale request repeated its cursor, then the retry dropped it"
        );
    }

    #[test]
    fn android_session_trims_an_oversized_page_without_losing_entries() {
        let client = Rc::new(Scripted::new());
        let mut controller = opened(&client);

        client.push_transcript(Ok(page(
            vec![
                entry("c1", "e1", "user", "one"),
                entry("c2", "e2", "assistant", "two"),
                entry("c3", "e3", "assistant", "three"),
            ],
            Some("c3"),
        )));
        let trimmed = controller.transcript(2).expect("trimmed page");
        assert_eq!(trimmed.entries.len(), 2);
        assert_eq!(
            trimmed.next_cursor.as_deref(),
            Some("c2"),
            "the cursor resumes at the first entry that was not shown"
        );
        assert_eq!(controller.cursor(), Some("c2"));

        // The page is bounded at both ends.
        assert_eq!(code_of(controller.transcript(0)), ErrorCode::InvalidInput);
        assert_eq!(
            code_of(controller.transcript(MAX_TRANSCRIPT_ENTRIES + 1)),
            ErrorCode::LimitExceeded
        );
    }

    #[test]
    fn android_session_queue_and_steer_take_different_roads() {
        let client = Rc::new(Scripted::new());
        let mut controller = opened(&client);

        client.push_prompt(Ok(prompt_ack("s1", true, 7)));
        let queued = controller.send_prompt("hold it").expect("queued prompt");
        assert_eq!(queued.delivery, DeliveryMode::Queue);
        assert!(queued.queued);

        client.push_prompt(Ok(prompt_ack("s1", true, 9)));
        let follow_up = controller
            .send_prompt_with("after this", DeliveryMode::FollowUp)
            .expect("follow-up");
        assert_eq!(follow_up.delivery, DeliveryMode::FollowUp);

        client.push_steer(Ok(steer_ack("s1")));
        let steer = controller.steer("stop and look").expect("steer");
        assert_eq!(steer.delivery, DeliveryMode::Steer);
        assert!(!steer.queued);

        let calls = client.calls();
        assert!(
            matches!(&calls[1], Call::Prompt { text, .. } if text == "hold it"),
            "{calls:?}"
        );
        assert!(
            matches!(&calls[2], Call::Prompt { text, .. } if text == "after this"),
            "{calls:?}"
        );
        assert!(
            matches!(&calls[3], Call::Steer { text, .. } if text == "stop and look"),
            "steer never goes through prompt: {calls:?}"
        );
        assert_eq!(
            calls
                .iter()
                .filter(|call| matches!(call, Call::Prompt { .. }))
                .count(),
            2
        );
        assert_eq!(
            calls
                .iter()
                .filter(|call| matches!(call, Call::Steer { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn android_session_refuses_oversize_or_malformed_text_before_the_mesh() {
        let client = Rc::new(Scripted::new());
        let mut controller = opened(&client);
        let before = client.calls().len();

        let long_prompt = "x".repeat(MAX_PROMPT_CHARS + 1);
        assert_eq!(
            code_of(controller.send_prompt(&long_prompt)),
            ErrorCode::LimitExceeded
        );
        let long_steer = "x".repeat(MAX_STEER_CHARS + 1);
        assert_eq!(
            code_of(controller.steer(&long_steer)),
            ErrorCode::LimitExceeded
        );
        // A prompt-sized steer is still too long for a boundary.
        let wide_steer = "x".repeat(MAX_PROMPT_CHARS);
        assert_eq!(
            code_of(controller.steer(&wide_steer)),
            ErrorCode::LimitExceeded
        );
        assert_eq!(
            code_of(controller.send_prompt("   ")),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            code_of(controller.send_prompt("bell\u{7}")),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            code_of(controller.steer("null\u{0}")),
            ErrorCode::InvalidInput
        );

        assert_eq!(
            client.calls().len(),
            before,
            "a refused message never reaches the mesh"
        );

        // A newline and a tab are ordinary prompt text.
        client.push_prompt(Ok(prompt_ack("s1", true, 12)));
        controller
            .send_prompt("line one\n\tline two")
            .expect("newlines are allowed");
    }

    #[test]
    fn android_session_an_unknown_session_is_not_found_before_any_action() {
        let (client, mut controller) = scripted();
        client.push_list(Ok(vec![summary("s1", "fix the build", "idle", 1_000, 0)]));

        let error = controller.open("ghost").expect_err("unknown session");
        assert_eq!(error.code(), ErrorCode::SessionNotFound);
        assert_eq!(error.code().as_str(), "zero.ses.not_found");
        assert!(error.message().contains("ghost"), "{error}");
        assert_eq!(controller.session_id(), None);

        // No session is open, so every action is refused locally.
        assert_eq!(
            code_of(controller.transcript(10)),
            ErrorCode::SessionNotFound
        );
        assert_eq!(
            code_of(controller.send_prompt("hi")),
            ErrorCode::SessionNotFound
        );
        assert_eq!(code_of(controller.steer("hi")), ErrorCode::SessionNotFound);
        assert_eq!(code_of(controller.queue()), ErrorCode::SessionNotFound);
        assert_eq!(code_of(controller.diff()), ErrorCode::SessionNotFound);
        assert_eq!(code_of(controller.cancel()), ErrorCode::SessionNotFound);

        // Malformed ids are refused before the list round trip.
        assert_eq!(code_of(controller.open("")), ErrorCode::InvalidInput);
        assert_eq!(code_of(controller.open("bad\nid")), ErrorCode::InvalidInput);
        assert_eq!(
            code_of(controller.open(&"i".repeat(MAX_ID_CHARS + 1))),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            client.calls(),
            vec![Call::List],
            "only the first open listed"
        );

        // A session that vanishes between list and action is still not found.
        let client = Rc::new(Scripted::new());
        let mut controller = opened(&client);
        client.push_transcript(Err(ZeroError::new(
            ErrorCode::SessionNotFound,
            "session s1 was deleted",
        )));
        let error = controller.transcript(10).expect_err("deleted session");
        assert_eq!(error.code(), ErrorCode::SessionNotFound);
        assert_eq!(controller.session_id(), Some("s1"));
    }

    #[test]
    fn android_session_transport_failures_keep_the_code_and_add_retry_guidance() {
        let (client, controller) = scripted();
        client.push_list(Err(ZeroError::new(ErrorCode::Offline, "mesh link is down")));
        let error = controller.list_sessions().expect_err("offline");
        assert_eq!(error.code(), ErrorCode::Offline);
        assert_eq!(error.code().as_str(), "zero.fnd.offline");
        assert!(error.message().contains("reconnect"), "{error}");
        assert!(error.message().contains("retry"), "{error}");

        client.push_list(Err(ZeroError::new(
            ErrorCode::Unavailable,
            "no worker on this host",
        )));
        let error = controller.list_sessions().expect_err("unavailable");
        assert_eq!(error.code(), ErrorCode::Unavailable);
        assert_eq!(error.code().as_str(), "zero.fnd.unavailable");
        assert!(error.message().contains("retry"), "{error}");

        // A failure mid-session is mapped the same way and leaves the session
        // open, so the phone can retry the same action.
        let client = Rc::new(Scripted::new());
        let mut controller = opened(&client);
        client.push_prompt(Err(ZeroError::new(ErrorCode::Offline, "link dropped")));
        let error = controller.send_prompt("hi").expect_err("offline prompt");
        assert_eq!(error.code(), ErrorCode::Offline);
        assert!(error.message().contains("nothing was sent"), "{error}");
        assert_eq!(controller.session_id(), Some("s1"));

        client.push_prompt(Err(ZeroError::new(ErrorCode::Timeout, "no answer")));
        let error = controller.send_prompt("hi").expect_err("timeout");
        assert_eq!(error.code(), ErrorCode::Timeout);
        assert!(error.message().contains("retry"), "{error}");
    }

    #[test]
    fn android_session_cancel_is_idempotent_and_never_a_conflict() {
        let client = Rc::new(Scripted::new());
        let mut controller = opened(&client);

        client.push_cancel(Ok(()));
        controller
            .cancel()
            .expect("the first cancel stops the turn");
        // The host reports the session as already closed: still the state the
        // caller asked for, so it is a success.
        client.push_cancel(Err(ZeroError::new(
            ErrorCode::SessionClosed,
            "the turn already ended",
        )));
        controller.cancel().expect("a repeat cancel is a no-op");

        // Any other failure is real and surfaces.
        client.push_cancel(Err(ZeroError::new(
            ErrorCode::PolicyDenied,
            "this device may not cancel",
        )));
        assert_eq!(code_of(controller.cancel()), ErrorCode::PolicyDenied);

        let cancels = client
            .calls()
            .into_iter()
            .filter(|call| matches!(call, Call::Cancel { .. }))
            .count();
        assert_eq!(cancels, 3, "the controller forwards each cancel once");
        assert_eq!(controller.session_id(), Some("s1"));
    }

    #[test]
    fn android_session_diffs_are_bounded_and_ordered_by_path() {
        let client = Rc::new(Scripted::new());
        let controller = opened(&client);
        let huge = "a".repeat(MAX_DIFF_PATCH_BYTES + 4_096);
        let long_path = format!("dir/{}", "p".repeat(MAX_DIFF_PATH_CHARS + 50));

        client.push_diff(Ok(vec![
            diff("src/z.rs", 1, 0, "@@ -1 +1 @@"),
            diff(&long_path, 2, 2, &huge),
            diff("src/a.rs", 3, 4, "@@ -2 +2 @@"),
        ]));
        let diffs = controller.diff().expect("diff");

        assert_eq!(diffs.len(), 3);
        assert_eq!(
            diffs
                .iter()
                .map(|diff| diff.path.as_str())
                .collect::<Vec<_>>(),
            vec![diffs[0].path.as_str(), "src/a.rs", "src/z.rs"],
            "diffs are ordered by path"
        );
        assert!(
            diffs[0].path.starts_with("dir/"),
            "the long path sorts first: {}",
            diffs[0].path
        );
        let big = &diffs[0];
        assert!(
            big.patch.len() <= MAX_DIFF_PATCH_BYTES,
            "the patch is bounded: {} bytes",
            big.patch.len()
        );
        assert!(
            big.patch.ends_with("[patch truncated]"),
            "a cut patch says so"
        );
        assert!(big.path.chars().count() <= MAX_DIFF_PATH_CHARS);
        assert!(big.path.ends_with(TRUNCATION_MARKER), "{}", big.path);

        // The file count is capped and the order is deterministic.
        let many: Vec<FileDiff> = (0..MAX_DIFF_FILES + 20)
            .map(|i| diff(&format!("src/f{i:04}.rs"), 1, 1, "@@ -1 +1 @@"))
            .collect();
        let mut reversed = many.clone();
        reversed.reverse();
        let client = Rc::new(Scripted::new());
        let controller = opened(&client);
        client.push_diff(Ok(reversed));
        let capped = controller.diff().expect("capped diff");
        assert_eq!(capped.len(), MAX_DIFF_FILES);
        let mut sorted = capped.clone();
        sorted.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(capped, sorted, "path order is the order a phone shows");
    }

    #[test]
    fn android_session_lists_are_ordered_deterministically() {
        let client = Rc::new(Scripted::new());
        let controller = AndroidSessionController::new(Rc::clone(&client));
        let rows = vec![
            summary("s3", "third", "idle", 1_000, 0),
            summary("s1", "first", "running", 3_000, 1),
            summary("s2", "second", "idle", 2_000, 5),
        ];
        client.push_list(Ok(rows.clone()));
        let first = controller.list_sessions().expect("list");
        assert_eq!(
            first.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            vec!["s1", "s2", "s3"],
            "newest first, then id"
        );

        client.push_list(Ok(rows.into_iter().rev().collect()));
        let second = controller.list_sessions().expect("list again");
        assert_eq!(first, second, "the same rows produce the same order");

        // Ties break by id, so two rows at the same instant never flip.
        client.push_list(Ok(vec![
            summary("b", "b", "idle", 5_000, 0),
            summary("a", "a", "idle", 5_000, 0),
        ]));
        let tied = controller.list_sessions().expect("tied list");
        assert_eq!(
            tied.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            vec!["a", "b"]
        );

        // Names and states are flattened and bounded; malformed ids are refused.
        client.push_list(Ok(vec![summary(
            "s9",
            "build\n\tthe app",
            "ru\u{7}nning",
            1,
            0,
        )]));
        let cleaned = controller.list_sessions().expect("cleaned list");
        assert_eq!(cleaned[0].name, "build the app");
        assert_eq!(cleaned[0].state, "ru nning");

        client.push_list(Ok(vec![summary("bad\nid", "x", "idle", 1, 0)]));
        assert_eq!(code_of(controller.list_sessions()), ErrorCode::InvalidInput);
    }

    #[test]
    fn android_session_views_and_debug_carry_no_secret() {
        let client = Rc::new(Scripted::new());
        let mut controller = opened(&client);
        client.push_list(Ok(vec![summary("s1", "fix the build", "idle", 1_000, 2)]));
        client.push_list(Ok(vec![summary("s1", "fix the build", "idle", 1_000, 2)]));
        client.push_transcript(Ok(page(
            vec![entry("c1", "e1", "user", "hello")],
            Some("c1"),
        )));
        client.push_prompt(Ok(prompt_ack("s1", true, 5)));
        client.push_steer(Ok(steer_ack("s1")));
        client.push_queue(Ok(vec![queued("q1", "run it", "pending")]));
        client.push_diff(Ok(vec![diff("src/a.rs", 1, 0, "@@ -1 +1 @@")]));
        client.push_cancel(Ok(()));

        let sessions = controller.list_sessions().expect("list");
        controller.open("s1").expect("open");
        let page = controller.transcript(10).expect("transcript");
        let prompt = controller.send_prompt("hello").expect("prompt");
        let steer = controller.steer("go").expect("steer");
        let queue = controller.queue().expect("queue");
        let diffs = controller.diff().expect("diff");
        controller.cancel().expect("cancel");

        let mut payloads = vec![
            serde_json::to_string(&sessions).unwrap(),
            serde_json::to_string(&page).unwrap(),
            serde_json::to_string(&prompt).unwrap(),
            serde_json::to_string(&steer).unwrap(),
            serde_json::to_string(&queue).unwrap(),
            serde_json::to_string(&diffs).unwrap(),
        ];
        payloads.push(format!("{controller:?}"));
        let token = client.token.clone();
        for payload in &payloads {
            assert!(
                !payload.contains(&token),
                "a view leaked the token: {payload}"
            );
            assert!(
                !payload.contains("sk-live"),
                "a view leaked a key: {payload}"
            );
            let lowered = payload.to_lowercase();
            for forbidden in ["token", "secret", "authorization", "bearer"] {
                assert!(
                    !lowered.contains(forbidden),
                    "a view carries `{forbidden}`: {payload}"
                );
            }
        }

        let debug = format!("{controller:?}");
        assert!(debug.contains("AndroidSessionController"), "{debug}");
        assert!(debug.contains("s1"), "{debug}");
        assert!(
            debug.contains("c1"),
            "the cursor is visible for support: {debug}"
        );

        // The field sets are closed: a phone screen gets exactly these keys.
        let keys = |value: &serde_json::Value| -> Vec<String> {
            value
                .as_object()
                .expect("object")
                .keys()
                .cloned()
                .collect::<Vec<_>>()
        };
        let mut summary_keys = keys(&serde_json::to_value(&sessions[0]).unwrap());
        summary_keys.sort();
        assert_eq!(
            summary_keys,
            ["id", "name", "state", "unread", "updated_ms"]
        );
        let mut diff_keys = keys(&serde_json::to_value(&diffs[0]).unwrap());
        diff_keys.sort();
        assert_eq!(diff_keys, ["additions", "deletions", "patch", "path"]);
        let mut queued_keys = keys(&serde_json::to_value(&queue[0]).unwrap());
        queued_keys.sort();
        assert_eq!(queued_keys, ["id", "state", "text"]);
        let mut page_keys = keys(&serde_json::to_value(&page).unwrap());
        page_keys.sort();
        assert_eq!(page_keys, ["entries", "next_cursor"]);
        let mut ack_keys = keys(&serde_json::to_value(&prompt).unwrap());
        ack_keys.sort();
        assert_eq!(ack_keys, ["delivery", "queued", "session_id", "text_chars"]);
    }

    #[test]
    fn android_session_stays_off_the_network_and_names_its_transport() {
        assert!(SESSION_TRANSPORT.contains("mesh"), "{SESSION_TRANSPORT}");
        assert!(SESSION_TRANSPORT.contains("loopback"));
        assert!(SESSION_TRANSPORT.contains("no socket"));

        // Structural check: the module holds a seam, not a listener. The
        // needles are split so this assertion is not itself a match.
        let source = include_str!("android_session.rs");
        for needle in [
            concat!("std::", "net"),
            concat!("Tcp", "Listener"),
            concat!("Tcp", "Stream"),
            concat!("Udp", "Socket"),
            concat!("http", "://"),
            concat!("0.0.0.", "0"),
            concat!("re", "qwest"),
        ] {
            assert!(
                !source.contains(needle),
                "android_session must stay behind its seam; found `{needle}`"
            );
        }
    }
}
