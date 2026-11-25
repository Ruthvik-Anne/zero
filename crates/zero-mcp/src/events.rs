//! MCP events (T-MCP-05, MCP-05, MCP-10).
//!
//! Source: the MCP Events extension `io.modelcontextprotocol/events` for
//! revision `2026-07-28`. The extension offers three delivery modes:
//! `events/poll` (pull), `events/stream` (push), and `events/subscribe`
//! (webhook). This module implements the transport-independent pull loop and
//! the webhook verifier; the push and webhook transports themselves are
//! deferred (see `docs/mcp.md`).
//!
//! Two rules shape the design:
//!
//! - **No resumption assumption.** A cursor is a position in a stream the
//!   server owns. If the server no longer recognises it, the source reports
//!   [`ResyncRequired`] and the poller returns it to the caller. The poller
//!   never guesses a nearby position and never skips events silently.
//! - **Verify before parsing.** A webhook body is untrusted bytes until its
//!   HMAC and timestamp have been checked. [`verify_webhook`] rejects a
//!   missing, stale, or invalid signature before deserialising the body, and
//!   no error ever contains the signature, key id, key bytes, or body.
//!
//! Signatures use RFC 2104 HMAC-SHA256 over the exact raw request body, with
//! the signature carried as hex (case-insensitive). The replay window is an
//! absolute skew against an injected clock, and repeated event ids are dropped
//! by a bounded first-in-first-out seen set.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fmt;

use serde_json::Value;
use sha2::{Digest, Sha256};
use zero_types::clock::{Clock, SystemClock};
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::headers::Headers;
use crate::jsonrpc::protocol_error;

/// Webhook header naming the key the sender used.
pub const HEADER_EVENT_KEY_ID: &str = "X-MCP-Event-Key-Id";
/// Webhook header carrying the hex HMAC-SHA256 signature.
pub const HEADER_EVENT_SIGNATURE: &str = "X-MCP-Event-Signature";
/// Webhook header carrying the sender's Unix timestamp in milliseconds.
pub const HEADER_EVENT_TIMESTAMP: &str = "X-MCP-Event-Timestamp";

/// Maximum number of event ids retained by a [`WebhookReceiver`] for dedupe.
pub const MAX_SEEN_EVENT_IDS: usize = 1024;

/// Default replay window for [`WebhookReceiver`]: five minutes either side.
pub const DEFAULT_WEBHOOK_TOLERANCE_MS: u64 = 5 * 60 * 1_000;

/// Stable prefix of the canonical error a source returns for a dead cursor.
///
/// The prefix exists because [`EventSource::poll`] speaks the crate-wide
/// [`zero_types::error::Result`]; [`ResyncRequired`] is the typed form and
/// [`resync_required`] builds the wire error. No event payload is involved.
pub const RESYNC_REQUIRED_MARKER: &str = "event cursor requires resync";

/// An opaque position in an event stream.
///
/// The value is meaningful only to the source that issued it. Callers treat it
/// as a token and pass it back unchanged; they never construct one from event
/// contents or add arithmetic to it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventCursor(String);

impl EventCursor {
    /// Wrap a cursor issued by a source.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The opaque wire value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the cursor is the empty string.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for EventCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One event delivered by poll, push, or webhook.
///
/// `payload` is untrusted server data: it is data, never instructions. The
/// manual `Debug` implementation therefore prints the id, the kind, and the
/// delivery time but redacts the payload body, so a log statement cannot dump
/// it by accident.
#[derive(Clone, PartialEq)]
pub struct Event {
    /// Event id, unique within the source's retention window.
    pub id: String,
    /// Event kind (for example `resource_updated`).
    pub kind: String,
    /// Event body, passed through as untrusted data.
    pub payload: Value,
    /// Local delivery time in Unix milliseconds.
    pub delivered_at_ms: i64,
}

impl Event {
    /// Build an event from already-validated parts.
    pub fn new(
        id: impl Into<String>,
        kind: impl Into<String>,
        payload: Value,
        delivered_at_ms: i64,
    ) -> Self {
        Self {
            id: id.into(),
            kind: kind.into(),
            payload,
            delivered_at_ms,
        }
    }

    /// Parse a webhook body as an event.
    ///
    /// The value must be a JSON object with a non-empty string `id`. An
    /// optional `kind` must be a non-empty string and defaults to `"event"`.
    /// The whole object is preserved as `payload`. Every failure is
    /// `zero.prv.protocol` and names only the offending field, never its value.
    pub fn from_value(value: Value, delivered_at_ms: i64) -> Result<Self> {
        let object = match value {
            Value::Object(object) => object,
            _ => return Err(protocol_error("event payload must be a JSON object")),
        };
        let id = match object.get("id") {
            Some(Value::String(id)) if !id.is_empty() => id.clone(),
            Some(Value::String(_)) => {
                return Err(protocol_error("event `id` must not be empty"));
            }
            Some(_) => return Err(protocol_error("event `id` must be a string")),
            None => return Err(protocol_error("event is missing `id`")),
        };
        let kind = match object.get("kind") {
            None | Some(Value::Null) => "event".to_string(),
            Some(Value::String(kind)) if !kind.is_empty() => kind.clone(),
            Some(Value::String(_)) => {
                return Err(protocol_error("event `kind` must not be empty"));
            }
            Some(_) => return Err(protocol_error("event `kind` must be a string")),
        };
        Ok(Self {
            id,
            kind,
            payload: Value::Object(object),
            delivered_at_ms,
        })
    }

    /// Check the invariants an adapter must uphold.
    ///
    /// A source that builds [`Event`] values directly is still checked by
    /// [`EventPoller`]: an empty id or kind is `zero.prv.protocol`.
    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            return Err(protocol_error("event `id` must not be empty"));
        }
        if self.kind.is_empty() {
            return Err(protocol_error("event `kind` must not be empty"));
        }
        Ok(())
    }
}

impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Event")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("payload", &"<redacted>")
            .field("delivered_at_ms", &self.delivered_at_ms)
            .finish()
    }
}

/// One batch returned by an [`EventSource`].
#[derive(Debug, Clone, PartialEq)]
pub struct EventBatch {
    /// Events in delivery order.
    pub events: Vec<Event>,
    /// Cursor to send with the next poll, or `None` when the source has no
    /// position to advance to yet.
    pub next_cursor: Option<EventCursor>,
    /// Remaining subscription lease in milliseconds, or `None` when the
    /// server did not renew it.
    pub ttl_ms: Option<u64>,
}

impl EventBatch {
    /// Build a batch.
    pub fn new(events: Vec<Event>, next_cursor: Option<EventCursor>, ttl_ms: Option<u64>) -> Self {
        Self {
            events,
            next_cursor,
            ttl_ms,
        }
    }

    /// Whether the batch carried no events.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

/// A transport seam for event delivery.
///
/// Poll and push adapters both implement this method: a poll adapter forwards
/// the cursor to `events/poll`, a push adapter buffers whatever `events/stream`
/// delivers and returns the buffer. Webhook delivery bypasses this trait and
/// enters through [`WebhookReceiver`].
pub trait EventSource {
    /// Fetch the next batch after `cursor`.
    ///
    /// `None` asks for the oldest retained events. A source that no longer
    /// recognises the cursor must return [`resync_required`], never a guess.
    fn poll(&self, cursor: Option<&EventCursor>) -> Result<EventBatch>;
}

impl<T: EventSource + ?Sized> EventSource for &T {
    fn poll(&self, cursor: Option<&EventCursor>) -> Result<EventBatch> {
        (**self).poll(cursor)
    }
}

impl<T: EventSource + ?Sized> EventSource for Box<T> {
    fn poll(&self, cursor: Option<&EventCursor>) -> Result<EventBatch> {
        (**self).poll(cursor)
    }
}

/// The typed form of "this cursor is unknown or expired; resync".
///
/// Returned by [`EventPoller::poll_once`] and
/// [`EventPoller::poll_until_idle`]. The caller must discard its local
/// position and start again from the source's oldest retained event; continuing
/// with the dead cursor would skip events, which this crate refuses to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResyncRequired {
    reason: String,
}

impl ResyncRequired {
    /// Build a resync signal with a human-readable reason.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    /// Why the source rejected the cursor.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for ResyncRequired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "event resync required: {}", self.reason)
    }
}

/// The canonical error an [`EventSource`] returns for a dead cursor.
///
/// Use [`ResyncRequired::from_error`] to recognise it. It is
/// `zero.prv.protocol` with [`RESYNC_REQUIRED_MARKER`] as the message prefix;
/// the reason is appended and must not contain a payload or credential.
pub fn resync_required(reason: impl Into<String>) -> ZeroError {
    let reason: String = reason.into();
    ZeroError::new(
        ErrorCode::ProviderProtocol,
        format!("{RESYNC_REQUIRED_MARKER}: {reason}"),
    )
}

impl ResyncRequired {
    /// Recognise the canonical error returned by [`resync_required`].
    pub fn from_error(error: &ZeroError) -> Option<Self> {
        if error.code() != ErrorCode::ProviderProtocol {
            return None;
        }
        let rest = error.message().strip_prefix(RESYNC_REQUIRED_MARKER)?;
        Some(Self::new(rest.strip_prefix(": ").unwrap_or(rest)))
    }
}

/// The outcome of one [`EventPoller::poll_once`] call.
#[derive(Debug, Clone, PartialEq)]
pub enum EventPollOutcome {
    /// A batch, possibly empty, and the cursor that follows it.
    Batch(EventBatch),
    /// The source rejected the cursor; the caller must resync.
    ResyncRequired(ResyncRequired),
}

/// Accumulated result of [`EventPoller::poll_until_idle`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EventPollSummary {
    /// Events received in delivery order across all polls.
    pub events: Vec<Event>,
    /// Number of `poll_once` attempts made.
    pub batches: u32,
    /// Whether an empty batch was seen before the attempt bound.
    pub idle: bool,
    /// Set when a source rejected the cursor; the loop stopped there.
    pub resync_required: Option<ResyncRequired>,
}

/// Drives one [`EventSource`] with its own cursor and subscription lease.
///
/// The poller owns the cursor: callers never have to thread it through, and a
/// successful poll advances it from the batch's `next_cursor`. A batch with
/// `next_cursor: None` does not reset the cursor; a source that loses its
/// position must say so with [`resync_required`].
pub struct EventPoller<S> {
    source: S,
    cursor: Option<EventCursor>,
    expires_at_ms: Option<i64>,
    clock: std::sync::Arc<dyn Clock>,
}

impl<S: EventSource> EventPoller<S> {
    /// Create a poller with no cursor, no lease, and the system clock.
    pub fn new(source: S) -> Self {
        Self {
            source,
            cursor: None,
            expires_at_ms: None,
            clock: std::sync::Arc::new(SystemClock),
        }
    }

    /// Replace the clock used for TTL checks. Tests inject [`zero_types::clock::FakeClock`].
    pub fn with_clock(mut self, clock: std::sync::Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// The cursor that will be sent with the next poll.
    pub fn cursor(&self) -> Option<&EventCursor> {
        self.cursor.as_ref()
    }

    /// The absolute lease deadline in Unix milliseconds, when known.
    pub fn expires_at_ms(&self) -> Option<i64> {
        self.expires_at_ms
    }

    /// Whether the subscription lease has run out.
    ///
    /// An unknown lease (`None`) never expires; the server renews it with a
    /// `ttl_ms` on a batch.
    pub fn is_expired(&self) -> bool {
        self.expires_at_ms
            .is_some_and(|expires_at| self.clock.now().0 >= expires_at)
    }

    /// Extend the lease by `ttl_ms` from now and return the new deadline.
    ///
    /// Renewal is refused once the lease has expired: the subscription is gone
    /// and the caller must [`Self::resubscribe`] rather than pretend it is
    /// alive.
    pub fn renew(&mut self, ttl_ms: u64) -> Result<i64> {
        if self.is_expired() {
            return Err(subscription_expired());
        }
        let expires_at = self.deadline_after(ttl_ms);
        self.expires_at_ms = Some(expires_at);
        Ok(expires_at)
    }

    /// Forget the local cursor and lease so the next poll starts fresh.
    ///
    /// The transport adapter may need to perform the actual `events/subscribe`
    /// again; this method only resets the poller's own state. It is the
    /// recovery path after [`Self::is_expired`] returns true.
    pub fn resubscribe(&mut self) {
        self.cursor = None;
        self.expires_at_ms = None;
    }

    /// Poll once, advancing the cursor when the source returns one.
    ///
    /// An expired lease fails before the source is called with
    /// `zero.prv.timeout`. A rejected cursor returns
    /// [`EventPollOutcome::ResyncRequired`] and clears the local cursor. A
    /// malformed event fails the whole batch without advancing the cursor, so
    /// no event is skipped.
    pub fn poll_once(&mut self) -> Result<EventPollOutcome> {
        self.ensure_active()?;
        let batch = match self.source.poll(self.cursor.as_ref()) {
            Ok(batch) => batch,
            Err(error) => {
                if let Some(resync) = ResyncRequired::from_error(&error) {
                    self.cursor = None;
                    return Ok(EventPollOutcome::ResyncRequired(resync));
                }
                return Err(error);
            }
        };
        for event in &batch.events {
            event.validate()?;
        }
        if let Some(next) = batch.next_cursor.clone() {
            self.cursor = Some(next);
        }
        if let Some(ttl_ms) = batch.ttl_ms {
            self.expires_at_ms = Some(self.deadline_after(ttl_ms));
        }
        Ok(EventPollOutcome::Batch(batch))
    }

    /// Poll until an empty batch, a resync signal, or `max_attempts`.
    ///
    /// The attempt bound counts polls, not events. Reaching it is not an error:
    /// the summary reports the events collected so far with `idle: false`, and
    /// the caller can poll again later with the same cursor. `max_attempts: 0`
    /// is `zero.fnd.invalid_input`.
    pub fn poll_until_idle(&mut self, max_attempts: u32) -> Result<EventPollSummary> {
        if max_attempts == 0 {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                "event polling needs at least one attempt",
            ));
        }
        let mut summary = EventPollSummary::default();
        for _ in 0..max_attempts {
            summary.batches += 1;
            match self.poll_once()? {
                EventPollOutcome::Batch(batch) => {
                    let idle = batch.is_empty();
                    summary.events.extend(batch.events);
                    if idle {
                        summary.idle = true;
                        return Ok(summary);
                    }
                }
                EventPollOutcome::ResyncRequired(resync) => {
                    summary.resync_required = Some(resync);
                    return Ok(summary);
                }
            }
        }
        Ok(summary)
    }

    fn ensure_active(&self) -> Result<()> {
        if self.is_expired() {
            Err(subscription_expired())
        } else {
            Ok(())
        }
    }

    fn deadline_after(&self, ttl_ms: u64) -> i64 {
        self.clock
            .now()
            .0
            .saturating_add(i64::try_from(ttl_ms).unwrap_or(i64::MAX))
    }
}

fn subscription_expired() -> ZeroError {
    ZeroError::new(
        ErrorCode::ProviderTimeout,
        "event subscription expired; resubscribe before polling",
    )
}

/// Verifies a webhook signature.
///
/// Implementations must compare in constant time and must not treat a missing
/// or unknown `key_id` as valid. The payload is the exact raw request body.
pub trait SignatureVerifier {
    /// Verify `signature` for `payload` using `key_id`.
    fn verify(&self, key_id: &str, payload: &[u8], signature: &str) -> bool;
}

impl<T: SignatureVerifier + ?Sized> SignatureVerifier for &T {
    fn verify(&self, key_id: &str, payload: &[u8], signature: &str) -> bool {
        (**self).verify(key_id, payload, signature)
    }
}

/// HMAC-SHA256 verifier with a small key ring keyed by key id.
///
/// Only this type holds key bytes. Its `Debug` form prints the number of
/// configured keys, never a key id or key material. Signatures are accepted as
/// 64 hex characters in either case, with an optional `sha256=` prefix.
pub struct HmacSha256Verifier {
    keys: BTreeMap<String, Vec<u8>>,
}

impl HmacSha256Verifier {
    /// An empty key ring. Every verification fails until a key is added.
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    /// Add a key, replacing any existing secret under the same id.
    pub fn with_key(mut self, key_id: impl Into<String>, secret: impl AsRef<[u8]>) -> Self {
        self.insert_key(key_id, secret);
        self
    }

    /// Add a key in place.
    pub fn insert_key(&mut self, key_id: impl Into<String>, secret: impl AsRef<[u8]>) {
        self.keys.insert(key_id.into(), secret.as_ref().to_vec());
    }

    /// Number of configured keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether no key is configured.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Compute the lowercase hex HMAC-SHA256 a sender would put in
    /// [`HEADER_EVENT_SIGNATURE`], or `None` when `key_id` is unknown.
    ///
    /// This is the inverse of [`SignatureVerifier::verify`] and exists for
    /// test fixtures and for adapters that emit webhooks; it never formats a
    /// key or signature into an error or log.
    pub fn sign_hex(&self, key_id: &str, payload: &[u8]) -> Option<String> {
        let secret = self.keys.get(key_id)?;
        Some(hex_encode(&hmac_sha256(secret, payload)))
    }
}

impl Default for HmacSha256Verifier {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for HmacSha256Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HmacSha256Verifier")
            .field("keys", &self.keys.len())
            .finish()
    }
}

impl SignatureVerifier for HmacSha256Verifier {
    fn verify(&self, key_id: &str, payload: &[u8], signature: &str) -> bool {
        let Some(secret) = self.keys.get(key_id) else {
            return false;
        };
        let Some(provided) = decode_hex_signature(signature) else {
            return false;
        };
        let expected = hmac_sha256(secret, payload);
        constant_time_eq(&expected, &provided)
    }
}

/// The result of accepting a webhook.
#[derive(Debug, Clone, PartialEq)]
pub enum WebhookOutcome {
    /// A verified event that has not been seen before.
    Deliver(Event),
    /// A verified event whose id is still in the seen set; do not redeliver it.
    Duplicate {
        /// The repeated event id.
        event_id: String,
    },
}

/// Stateful webhook entry point: verify, validate, dedupe.
///
/// The receiver keeps at most [`MAX_SEEN_EVENT_IDS`] ids (configurable) in
/// first-in-first-out order; once full, the oldest id is evicted so a replay
/// after the retention window is delivered again rather than silently dropped.
/// The seen set is in memory only: persistence within the cursor window is a
/// transport concern and is deferred.
pub struct WebhookReceiver<V: SignatureVerifier> {
    verifier: V,
    tolerance_ms: u64,
    capacity: usize,
    seen: HashSet<String>,
    order: VecDeque<String>,
}

impl<V: SignatureVerifier> WebhookReceiver<V> {
    /// Create a receiver with the default five-minute replay window and
    /// [`MAX_SEEN_EVENT_IDS`] dedupe slots.
    pub fn new(verifier: V) -> Self {
        Self {
            verifier,
            tolerance_ms: DEFAULT_WEBHOOK_TOLERANCE_MS,
            capacity: MAX_SEEN_EVENT_IDS,
            seen: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// Replace the replay window in milliseconds.
    pub fn with_tolerance_ms(mut self, tolerance_ms: u64) -> Self {
        self.tolerance_ms = tolerance_ms;
        self
    }

    /// Replace the dedupe bound. Zero is raised to one.
    pub fn with_seen_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity.max(1);
        self
    }

    /// The verifier in use.
    pub fn verifier(&self) -> &V {
        &self.verifier
    }

    /// Number of event ids currently retained.
    pub fn seen_len(&self) -> usize {
        self.seen.len()
    }

    /// Verify and dedupe one webhook delivery.
    ///
    /// Header, timestamp, and signature checks run before the body is parsed.
    /// A repeated id is reported as [`WebhookOutcome::Duplicate`] instead of
    /// producing a second event.
    pub fn receive(
        &mut self,
        headers: &Headers,
        body: &[u8],
        now_ms: i64,
    ) -> Result<WebhookOutcome> {
        let event = verify_webhook(headers, body, &self.verifier, now_ms, self.tolerance_ms)?;
        if self.seen.contains(&event.id) {
            return Ok(WebhookOutcome::Duplicate { event_id: event.id });
        }
        self.seen.insert(event.id.clone());
        self.order.push_back(event.id.clone());
        while self.order.len() > self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.seen.remove(&evicted);
            }
        }
        Ok(WebhookOutcome::Deliver(event))
    }
}

/// Verify one webhook body and return the event, without dedupe state.
///
/// Checks run in this order and stop at the first failure:
///
/// 1. `X-MCP-Event-Key-Id`, `X-MCP-Event-Signature`, and
///    `X-MCP-Event-Timestamp` must be present and non-empty.
/// 2. The timestamp must be Unix milliseconds within `tolerance_ms` of
///    `now_ms`, in either direction.
/// 3. The signature must verify over the exact `body` bytes.
/// 4. The body must parse as a JSON object with a string `id`.
///
/// Steps 1 to 3 run before any JSON parsing, so a forged body is never fed to
/// the parser. Failures are `zero.prv.protocol`; no error message contains a
/// header value, key, signature, or body content. Use [`WebhookReceiver`] when
/// duplicate suppression is needed.
pub fn verify_webhook<V: SignatureVerifier + ?Sized>(
    headers: &Headers,
    body: &[u8],
    verifier: &V,
    now_ms: i64,
    tolerance_ms: u64,
) -> Result<Event> {
    let key_id = required_header(headers, HEADER_EVENT_KEY_ID)?;
    let signature = required_header(headers, HEADER_EVENT_SIGNATURE)?;
    let timestamp = required_header(headers, HEADER_EVENT_TIMESTAMP)?;
    let timestamp: i64 = timestamp
        .parse()
        .map_err(|_| protocol_error("webhook `X-MCP-Event-Timestamp` must be Unix milliseconds"))?;
    let skew = (i128::from(now_ms) - i128::from(timestamp)).abs();
    if skew > i128::from(tolerance_ms) {
        return Err(protocol_error(
            "webhook timestamp is outside the allowed replay window",
        ));
    }
    if !verifier.verify(key_id, body, signature) {
        return Err(protocol_error("webhook signature verification failed"));
    }
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| protocol_error("webhook body must be valid JSON"))?;
    Event::from_value(value, now_ms)
}

fn required_header<'a>(headers: &'a Headers, name: &str) -> Result<&'a str> {
    match headers.get(name) {
        Some(value) if !value.trim().is_empty() => Ok(value.trim()),
        Some(_) => Err(protocol_error(format!(
            "webhook `{name}` header must not be empty"
        ))),
        None => Err(protocol_error(format!(
            "webhook is missing the `{name}` header"
        ))),
    }
}

const HMAC_BLOCK_BYTES: usize = 64;

/// RFC 2104 HMAC-SHA256.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; HMAC_BLOCK_BYTES];
    if key.len() > HMAC_BLOCK_BYTES {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0u8; HMAC_BLOCK_BYTES];
    let mut outer_pad = [0u8; HMAC_BLOCK_BYTES];
    for (index, byte) in block.iter().enumerate() {
        inner_pad[index] = byte ^ 0x36;
        outer_pad[index] = byte ^ 0x5c;
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_hash);
    let digest = outer.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn decode_hex_signature(signature: &str) -> Option<[u8; 32]> {
    let value = signature.trim();
    let value = match value.split_once('=') {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("sha256") => rest.trim(),
        Some(_) => return None,
        None => value,
    };
    let bytes = value.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut output = [0u8; 32];
    for (index, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(output)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

/// Constant-time comparison for equal-length byte strings.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc_4231_case_2() {
        let verifier = HmacSha256Verifier::new().with_key("jefe", "Jefe");
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        assert!(verifier.verify("jefe", b"what do ya want for nothing?", expected));
        assert!(verifier.verify(
            "jefe",
            b"what do ya want for nothing?",
            &expected.to_ascii_uppercase()
        ));
        assert!(verifier.verify(
            "jefe",
            b"what do ya want for nothing?",
            &format!("sha256={expected}")
        ));
        assert!(!verifier.verify("jefe", b"what do ya want for nothing?", "00"));
        assert!(!verifier.verify("jefe", b"tampered", expected));
        assert!(!verifier.verify("other", b"what do ya want for nothing?", expected));
    }

    #[test]
    fn hmac_hashes_long_keys_per_rfc_2104() {
        // RFC 4231 case 6: a 131-byte key is hashed to 32 bytes first.
        let key = [0xaa; 131];
        let verifier = HmacSha256Verifier::new().with_key("k", key);
        let expected = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";
        assert!(verifier.verify(
            "k",
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            expected
        ));
    }

    #[test]
    fn hex_decoder_rejects_wrong_shapes() {
        assert!(decode_hex_signature("").is_none());
        assert!(decode_hex_signature("abc").is_none());
        assert!(decode_hex_signature(&"zz".repeat(32)).is_none());
        assert!(decode_hex_signature(&format!("sha1={}", "00".repeat(32))).is_none());
    }

    #[test]
    fn verifier_debug_does_not_print_key_material() {
        let verifier = HmacSha256Verifier::new().with_key("key-1", "super-secret");
        let debug = format!("{verifier:?}");
        assert!(debug.contains("keys"));
        assert!(!debug.contains("key-1"));
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn event_debug_redacts_the_payload() {
        let event = Event::new(
            "evt-1",
            "resource_updated",
            serde_json::json!({"secret": "body"}),
            5,
        );
        let debug = format!("{event:?}");
        assert!(debug.contains("evt-1"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("body"));
    }
}
