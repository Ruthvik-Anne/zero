//! Local end-to-end tracing of a turn (OBS-02, OBS-04).
//!
//! A [`Trace`] is a bounded tree of [`Span`]s rooted at one `Turn` span. The
//! tree makes the Done criterion for T-OBS-02 visible: a completed turn carries
//! at least one `Provider`, one `Tool`, and one `Frame` span under the turn
//! root. [`turn_trace`] scripts such a turn and [`assert_turn_covers`] checks
//! it.
//!
//! Traces are local-only. Nothing here opens a socket, spawns a task, or sends
//! anything to a collector. [`TraceStore`] keeps one append-only JSONL file per
//! trace under a caller-supplied directory, so the newest record can be loaded
//! after a restart.
//!
//! Attributes are metadata, never conversation content. Secret-looking keys and
//! message-body keys are rejected; control characters are stripped from names,
//! keys, values, and event text before a span is stored.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use zero_types::error::{ErrorCode, Result, ZeroError};

/// Schema version written into each `TraceStore` record.
pub const TRACE_SCHEMA_VERSION: u32 = 1;

/// Maximum bytes in a span name after control characters are stripped.
pub const MAX_SPAN_NAME_LEN: usize = 64;
/// Maximum bytes in an attribute key.
pub const MAX_ATTRIBUTE_KEY_LEN: usize = 32;
/// Maximum bytes in an attribute value.
pub const MAX_ATTRIBUTE_VALUE_LEN: usize = 128;
/// Maximum attributes attached to one span.
pub const MAX_ATTRIBUTES_PER_SPAN: usize = 16;
/// Maximum events attached to one span.
pub const MAX_EVENTS_PER_SPAN: usize = 32;
/// Maximum bytes in one event text.
pub const MAX_EVENT_TEXT_LEN: usize = 128;
/// Maximum spans in one trace.
pub const MAX_SPANS_PER_TRACE: usize = 2_048;
/// Maximum parent-chain depth. A deeper tree is refused rather than walked.
pub const MAX_SPAN_DEPTH: usize = 32;
/// Maximum bytes in one trace file (`TraceStore`); retention is T-OBS-03.
pub const MAX_TRACE_FILE_BYTES: u64 = 4 * 1024 * 1024;
/// Maximum bytes in one serialized record, before the newline.
pub const MAX_TRACE_RECORD_BYTES: usize = 1024 * 1024;

const TRACE_ID_LEN: usize = 32;
const SPAN_ID_LEN: usize = 16;

/// Attribute keys that must never be recorded, even as metadata.
const SECRET_KEY_MARKERS: [&str; 8] = [
    "token",
    "secret",
    "key",
    "password",
    "passwd",
    "credential",
    "authorization",
    "cookie",
];

/// Attribute keys that would smuggle conversation text into a trace.
const MESSAGE_KEY_MARKERS: [&str; 6] =
    ["message", "prompt", "content", "completion", "transcript", "body"];

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn corrupt(path: &Path, offset: usize, detail: &str) -> ZeroError {
    ZeroError::new(
        ErrorCode::Corrupt,
        format!("{}: {detail} at byte {offset}", path.display()),
    )
}

/// Strip every control character from a caller-supplied string.
///
/// Names, attribute keys, attribute values, and event text pass through this
/// before validation, so a newline or ANSI escape can never break the text
/// tree or an on-disk JSONL line.
fn strip_control(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).collect()
}

fn validate_attribute_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(invalid("span attribute key is empty"));
    }
    if key.len() > MAX_ATTRIBUTE_KEY_LEN {
        return Err(invalid(format!(
            "span attribute key `{key}` exceeds {MAX_ATTRIBUTE_KEY_LEN} bytes"
        )));
    }
    if !key
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
    {
        return Err(invalid(format!(
            "span attribute key `{key}` must be ASCII letters, digits, `_`, `-`, or `.`"
        )));
    }
    let lowered = key.to_ascii_lowercase();
    if SECRET_KEY_MARKERS.iter().any(|marker| lowered.contains(marker)) {
        return Err(invalid(format!(
            "span attribute key `{key}` looks like a secret; secrets are not recorded"
        )));
    }
    if MESSAGE_KEY_MARKERS.iter().any(|marker| lowered.contains(marker)) {
        return Err(invalid(format!(
            "span attribute key `{key}` is message text; only metadata is recorded"
        )));
    }
    Ok(())
}

fn validate_attribute_value(value: &str) -> Result<()> {
    if value.len() > MAX_ATTRIBUTE_VALUE_LEN {
        return Err(invalid(format!(
            "span attribute value exceeds {MAX_ATTRIBUTE_VALUE_LEN} bytes"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid(
            "span attribute value contains a control character; strip it first",
        ));
    }
    Ok(())
}

macro_rules! id_type {
    ($name:ident, $len:expr, $label:literal) => {
        #[doc = concat!("Stable ", $label, ": lowercase hex, fixed length.")]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Length of the identifier in bytes.
            pub const LEN: usize = $len;

            /// Parse and validate an identifier from text.
            pub fn parse(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                let valid = value.len() == $len
                    && value
                        .bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
                if !valid {
                    return Err(invalid(format!(
                        "{} must be {} lowercase hex characters",
                        $label, $len
                    )));
                }
                Ok(Self(value))
            }

            /// The identifier as a borrowed string.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(
                deserializer: D,
            ) -> std::result::Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                Self::parse(raw).map_err(serde::de::Error::custom)
            }
        }
    };
}

id_type!(TraceId, TRACE_ID_LEN, "trace id");
id_type!(SpanId, SPAN_ID_LEN, "span id");

impl TraceId {
    /// Derive a deterministic trace id from a seed string.
    pub fn from_seed(seed: &str) -> Self {
        let digest = blake3::hash(seed.as_bytes()).to_hex().to_string();
        Self(digest[..TRACE_ID_LEN].to_string())
    }
}

impl SpanId {
    /// Derive a deterministic span id from its trace and an ordinal.
    pub fn from_seed(trace: &TraceId, ordinal: u32) -> Self {
        let seed = format!("{}\n{ordinal}", trace.as_str());
        let digest = blake3::hash(seed.as_bytes()).to_hex().to_string();
        Self(digest[..SPAN_ID_LEN].to_string())
    }
}

/// The stage of a turn a span belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanKind {
    Turn,
    Provider,
    Tool,
    Kernel,
    Frame,
    Policy,
    Scheduler,
}

impl SpanKind {
    /// Every kind, in declaration order.
    pub const ALL: [SpanKind; 7] = [
        SpanKind::Turn,
        SpanKind::Provider,
        SpanKind::Tool,
        SpanKind::Kernel,
        SpanKind::Frame,
        SpanKind::Policy,
        SpanKind::Scheduler,
    ];

    /// Lowercase label used by the text renderer and JSON.
    pub const fn as_str(self) -> &'static str {
        match self {
            SpanKind::Turn => "turn",
            SpanKind::Provider => "provider",
            SpanKind::Tool => "tool",
            SpanKind::Kernel => "kernel",
            SpanKind::Frame => "frame",
            SpanKind::Policy => "policy",
            SpanKind::Scheduler => "scheduler",
        }
    }
}

impl fmt::Display for SpanKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One timed unit of work in a turn.
///
/// Construct with [`Span::new`] and the builder methods so names and attributes
/// are sanitized. The fields are public for serde and for tests that need to
/// model corruption, but [`Span::validate`] re-checks every constraint and
/// [`Trace::validate`] rejects anything that slipped past a constructor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub id: SpanId,
    pub trace_id: TraceId,
    pub parent: Option<SpanId>,
    pub name: String,
    pub kind: SpanKind,
    pub start_ms: i64,
    pub end_ms: Option<i64>,
    pub attributes: BTreeMap<String, String>,
    pub events: Vec<(i64, String)>,
}

impl Span {
    /// Start a span. The name is stripped of control characters and trimmed.
    pub fn new(
        trace_id: TraceId,
        id: SpanId,
        parent: Option<SpanId>,
        name: impl Into<String>,
        kind: SpanKind,
        start_ms: i64,
    ) -> Result<Self> {
        let name = strip_control(&name.into()).trim().to_string();
        let span = Self {
            id,
            trace_id,
            parent,
            name,
            kind,
            start_ms,
            end_ms: None,
            attributes: BTreeMap::new(),
            events: Vec::new(),
        };
        span.validate()?;
        Ok(span)
    }

    /// Attach a metadata attribute. Secret and message-body keys are refused.
    pub fn attribute(mut self, key: &str, value: impl Into<String>) -> Result<Self> {
        let key = strip_control(key).trim().to_string();
        validate_attribute_key(&key)?;
        let value = strip_control(&value.into());
        validate_attribute_value(&value)?;
        if !self.attributes.contains_key(&key) && self.attributes.len() >= MAX_ATTRIBUTES_PER_SPAN
        {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!("a span accepts at most {MAX_ATTRIBUTES_PER_SPAN} attributes"),
            ));
        }
        self.attributes.insert(key, value);
        Ok(self)
    }

    /// Attach a timestamped event. Event text is metadata, not message text.
    pub fn event(mut self, ts: i64, text: impl Into<String>) -> Result<Self> {
        if self.events.len() >= MAX_EVENTS_PER_SPAN {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!("a span accepts at most {MAX_EVENTS_PER_SPAN} events"),
            ));
        }
        let text = strip_control(&text.into());
        if text.is_empty() {
            return Err(invalid("span event text is empty"));
        }
        if text.len() > MAX_EVENT_TEXT_LEN {
            return Err(invalid(format!(
                "span event text exceeds {MAX_EVENT_TEXT_LEN} bytes"
            )));
        }
        if ts < self.start_ms {
            return Err(invalid("span event is before the span start"));
        }
        if let Some(end) = self.end_ms {
            if ts > end {
                return Err(invalid("span event is after the span end"));
            }
        }
        self.events.push((ts, text));
        Ok(self)
    }

    /// Close the span. A span can be finished once and only after it started.
    pub fn finish(&mut self, end_ms: i64) -> Result<()> {
        if end_ms < self.start_ms {
            return Err(invalid(format!(
                "span `{}` ends before it starts",
                self.name
            )));
        }
        if self.end_ms.is_some() {
            return Err(invalid(format!(
                "span `{}` is already finished",
                self.name
            )));
        }
        if self.events.iter().any(|(ts, _)| *ts > end_ms) {
            return Err(invalid(format!(
                "span `{}` has an event after its end",
                self.name
            )));
        }
        self.end_ms = Some(end_ms);
        Ok(())
    }

    /// Elapsed milliseconds once the span is finished.
    pub fn duration_ms(&self) -> Option<i64> {
        self.end_ms.map(|end| end - self.start_ms)
    }

    /// Re-check every bound on this span in isolation.
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(invalid("span name is empty"));
        }
        if self.name.len() > MAX_SPAN_NAME_LEN {
            return Err(invalid(format!(
                "span name `{}` exceeds {MAX_SPAN_NAME_LEN} bytes",
                self.name
            )));
        }
        if self.name.chars().any(char::is_control) {
            return Err(invalid("span name contains a control character"));
        }
        if self.parent.as_ref() == Some(&self.id) {
            return Err(invalid(format!(
                "span `{}` cannot be its own parent",
                self.name
            )));
        }
        if self.attributes.len() > MAX_ATTRIBUTES_PER_SPAN {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!("a span accepts at most {MAX_ATTRIBUTES_PER_SPAN} attributes"),
            ));
        }
        for (key, value) in &self.attributes {
            validate_attribute_key(key)?;
            validate_attribute_value(value)?;
        }
        if self.events.len() > MAX_EVENTS_PER_SPAN {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!("a span accepts at most {MAX_EVENTS_PER_SPAN} events"),
            ));
        }
        if let Some(end) = self.end_ms {
            if end < self.start_ms {
                return Err(invalid(format!(
                    "span `{}` ends before it starts",
                    self.name
                )));
            }
        }
        for (ts, text) in &self.events {
            if *ts < self.start_ms {
                return Err(invalid("span event is before the span start"));
            }
            if let Some(end) = self.end_ms {
                if *ts > end {
                    return Err(invalid("span event is after the span end"));
                }
            }
            if text.is_empty() || text.len() > MAX_EVENT_TEXT_LEN {
                return Err(invalid(format!(
                    "span event text must be 1..={MAX_EVENT_TEXT_LEN} bytes"
                )));
            }
            if text.chars().any(char::is_control) {
                return Err(invalid("span event text contains a control character"));
            }
        }
        Ok(())
    }
}

/// A completed (or in-flight) turn trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trace {
    pub trace_id: TraceId,
    pub spans: Vec<Span>,
    pub root: SpanId,
}

impl Trace {
    /// Create an empty trace with a caller-chosen root id. The root span itself
    /// still has to be added before the trace validates.
    pub fn new(trace_id: TraceId, root: SpanId) -> Self {
        Self { trace_id, spans: Vec::new(), root }
    }

    /// Start a trace with a finished-shape `Turn` root span.
    pub fn start(trace_id: TraceId, name: &str, start_ms: i64) -> Result<Self> {
        let root = SpanId::from_seed(&trace_id, 0);
        let mut trace = Self::new(trace_id.clone(), root.clone());
        let span = Span::new(trace_id, root, None, name, SpanKind::Turn, start_ms)?;
        trace.add_span(span)?;
        Ok(trace)
    }

    /// The root span id.
    pub fn root(&self) -> &SpanId {
        &self.root
    }

    /// Look up one span by id.
    pub fn span(&self, id: &SpanId) -> Option<&Span> {
        self.spans.iter().find(|span| &span.id == id)
    }

    /// Number of spans in this trace.
    pub fn span_count(&self) -> usize {
        self.spans.len()
    }

    /// Add one span, refusing duplicates and orphans.
    ///
    /// The first span must be the root and must have no parent. Every later
    /// span must name an existing parent. A full trace is capped at
    /// [`MAX_SPANS_PER_TRACE`].
    pub fn add_span(&mut self, span: Span) -> Result<()> {
        span.validate()?;
        if span.trace_id != self.trace_id {
            return Err(invalid(format!(
                "span `{}` belongs to trace {} not {}",
                span.name, span.trace_id, self.trace_id
            )));
        }
        if self.spans.iter().any(|existing| existing.id == span.id) {
            return Err(invalid(format!(
                "duplicate span id {} in trace {}",
                span.id, self.trace_id
            )));
        }
        if self.spans.len() >= MAX_SPANS_PER_TRACE {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!("a trace accepts at most {MAX_SPANS_PER_TRACE} spans"),
            ));
        }
        match &span.parent {
            None => {
                if span.id != self.root {
                    return Err(invalid(format!(
                        "span `{}` has no parent but is not the trace root",
                        span.name
                    )));
                }
                if !self.spans.is_empty() {
                    return Err(invalid("the trace root span already exists"));
                }
            }
            Some(parent) => {
                if !self.spans.iter().any(|existing| &existing.id == parent) {
                    return Err(invalid(format!(
                        "span `{}` names missing parent {parent}",
                        span.name
                    )));
                }
            }
        }
        self.spans.push(span);
        Ok(())
    }

    /// Finish one span by id.
    pub fn finish_span(&mut self, id: &SpanId, end_ms: i64) -> Result<()> {
        let span = self
            .spans
            .iter_mut()
            .find(|span| &span.id == id)
            .ok_or_else(|| {
                ZeroError::new(
                    ErrorCode::NotFound,
                    format!("span {id} is not in trace {}", self.trace_id),
                )
            })?;
        span.finish(end_ms)
    }

    /// Deterministic tree from the root. Children are ordered by start time and
    /// then by id, so two runs over the same spans render identically.
    pub fn span_tree(&self) -> Result<SpanNode> {
        self.validate()?;
        let mut children: BTreeMap<SpanId, Vec<&Span>> = BTreeMap::new();
        for span in &self.spans {
            if let Some(parent) = &span.parent {
                children.entry(parent.clone()).or_default().push(span);
            }
        }
        for list in children.values_mut() {
            list.sort_by(|left, right| {
                left.start_ms
                    .cmp(&right.start_ms)
                    .then_with(|| left.id.cmp(&right.id))
            });
        }
        let root = self
            .spans
            .iter()
            .find(|span| span.id == self.root)
            .ok_or_else(|| invalid("trace root span is missing"))?;
        Ok(build_node(root, &children))
    }

    /// Full structural validation.
    ///
    /// Rejects an empty trace, missing/duplicate ids, a wrong trace id, a
    /// missing or extra root, orphaned parents, cycles, self-parents, chains
    /// deeper than [`MAX_SPAN_DEPTH`], unreachable spans, and any span that
    /// fails [`Span::validate`].
    pub fn validate(&self) -> Result<()> {
        if self.spans.is_empty() {
            return Err(invalid("trace has no spans"));
        }
        if self.spans.len() > MAX_SPANS_PER_TRACE {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!("a trace accepts at most {MAX_SPANS_PER_TRACE} spans"),
            ));
        }

        let mut by_id: BTreeMap<&SpanId, &Span> = BTreeMap::new();
        for span in &self.spans {
            if span.trace_id != self.trace_id {
                return Err(invalid(format!(
                    "span `{}` belongs to trace {} not {}",
                    span.name, span.trace_id, self.trace_id
                )));
            }
            if by_id.insert(&span.id, span).is_some() {
                return Err(invalid(format!(
                    "duplicate span id {} in trace {}",
                    span.id, self.trace_id
                )));
            }
        }

        if !by_id.contains_key(&self.root) {
            return Err(invalid(format!(
                "trace root {} is missing from its spans",
                self.root
            )));
        }
        let roots: Vec<&Span> = self
            .spans
            .iter()
            .filter(|span| span.parent.is_none())
            .collect();
        if roots.len() != 1 || roots[0].id != self.root {
            return Err(invalid(
                "a trace must have exactly one parentless span and it must be the root",
            ));
        }

        for span in &self.spans {
            span.validate()?;
            if let Some(parent) = &span.parent {
                if !by_id.contains_key(parent) {
                    return Err(invalid(format!(
                        "span `{}` names missing parent {parent}",
                        span.name
                    )));
                }
            }
            let mut seen = BTreeSet::new();
            let mut current = span.parent.clone();
            let mut depth = 0usize;
            while let Some(parent) = current {
                if parent == span.id || !seen.insert(parent.clone()) {
                    return Err(invalid(format!(
                        "span `{}` is part of a parent cycle",
                        span.name
                    )));
                }
                depth += 1;
                if depth > MAX_SPAN_DEPTH {
                    return Err(ZeroError::new(
                        ErrorCode::LimitExceeded,
                        format!("span parent chain exceeds {MAX_SPAN_DEPTH} links"),
                    ));
                }
                let parent_span = by_id.get(&parent).ok_or_else(|| {
                    invalid(format!("span `{}` names missing parent {parent}", span.name))
                })?;
                current = parent_span.parent.clone();
            }
        }

        let mut reachable: BTreeSet<&SpanId> = BTreeSet::new();
        let mut stack = vec![&self.root];
        while let Some(id) = stack.pop() {
            if !reachable.insert(id) {
                continue;
            }
            for span in &self.spans {
                if span.parent.as_ref() == Some(id) {
                    stack.push(&span.id);
                }
            }
        }
        if reachable.len() != self.spans.len() {
            return Err(invalid(format!(
                "trace {} has orphaned spans that are not reachable from the root",
                self.trace_id
            )));
        }
        Ok(())
    }
}

/// One node in the deterministic tree projection of a trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpanNode {
    pub id: SpanId,
    pub kind: SpanKind,
    pub name: String,
    pub start_ms: i64,
    pub end_ms: Option<i64>,
    pub attributes: BTreeMap<String, String>,
    pub events: usize,
    pub children: Vec<SpanNode>,
}

fn build_node(span: &Span, children: &BTreeMap<SpanId, Vec<&Span>>) -> SpanNode {
    let nested = children
        .get(&span.id)
        .map(|list| {
            list.iter()
                .map(|child| build_node(child, children))
                .collect()
        })
        .unwrap_or_default();
    SpanNode {
        id: span.id.clone(),
        kind: span.kind,
        name: span.name.clone(),
        start_ms: span.start_ms,
        end_ms: span.end_ms,
        attributes: span.attributes.clone(),
        events: span.events.len(),
        children: nested,
    }
}

/// Verify the T-OBS-02 Done criterion on a completed turn trace.
///
/// The trace must validate, the root must be a finished `Turn`, at least one
/// `Provider`, `Tool`, and `Frame` span must exist under the root, and every
/// child must finish inside its parent's interval.
pub fn assert_turn_covers(trace: &Trace) -> Result<()> {
    trace.validate()?;
    let root = trace
        .span(&trace.root)
        .ok_or_else(|| invalid("trace root span is missing"))?;
    if root.kind != SpanKind::Turn {
        return Err(invalid(format!(
            "trace root `{}` is a {} span, not a turn",
            root.name, root.kind
        )));
    }
    if root.end_ms.is_none() {
        return Err(invalid("turn root is not finished"));
    }

    for kind in [SpanKind::Provider, SpanKind::Tool, SpanKind::Frame] {
        let covered = trace.spans.iter().any(|span| {
            span.kind == kind
                && span.end_ms.is_some()
                && parent_chain_reaches_root(trace, &span.id)
        });
        if !covered {
            return Err(invalid(format!(
                "turn trace is missing a finished {kind} span under the root"
            )));
        }
    }

    for span in &trace.spans {
        let Some(parent_id) = &span.parent else {
            continue;
        };
        let parent = trace
            .span(parent_id)
            .ok_or_else(|| invalid(format!("span `{}` names a missing parent", span.name)))?;
        if span.start_ms < parent.start_ms {
            return Err(invalid(format!(
                "span `{}` starts before its parent `{}`",
                span.name, parent.name
            )));
        }
        if let (Some(end), Some(parent_end)) = (span.end_ms, parent.end_ms) {
            if end > parent_end {
                return Err(invalid(format!(
                    "span `{}` ends after its parent `{}`",
                    span.name, parent.name
                )));
            }
        }
    }
    Ok(())
}

fn parent_chain_reaches_root(trace: &Trace, id: &SpanId) -> bool {
    let mut seen = BTreeSet::new();
    let mut current = Some(id.clone());
    while let Some(id) = current {
        if &id == trace.root() {
            return true;
        }
        if !seen.insert(id.clone()) {
            return false;
        }
        current = trace.span(&id).and_then(|span| span.parent.clone());
    }
    false
}

/// Build the scripted local turn used by tests and as a worked example.
///
/// The turn runs provider completion, one tool call, and one frame render under
/// the turn root, then finishes the root. Every id is derived deterministically
/// from a fixed seed and every attribute is metadata only.
pub fn turn_trace() -> Result<Trace> {
    let trace_id = TraceId::from_seed("trace:local-turn");
    let root_id = SpanId::from_seed(&trace_id, 0);
    let mut trace = Trace::new(trace_id.clone(), root_id.clone());

    let root = Span::new(
        trace_id.clone(),
        root_id,
        None,
        "turn",
        SpanKind::Turn,
        1_000,
    )?
    .attribute("turn", "1")?;
    trace.add_span(root)?;

    let provider_id = SpanId::from_seed(&trace_id, 1);
    let provider = Span::new(
        trace_id.clone(),
        provider_id.clone(),
        Some(trace.root.clone()),
        "provider.complete",
        SpanKind::Provider,
        1_001,
    )?
    .attribute("provider", "local")?
    .attribute("model", "zero-local")?
    .attribute("duration_ms", "40")?
    .event(1_040, "response tokens=128")?;
    trace.add_span(provider)?;
    trace.finish_span(&provider_id, 1_041)?;

    let tool_id = SpanId::from_seed(&trace_id, 2);
    let tool = Span::new(
        trace_id.clone(),
        tool_id.clone(),
        Some(trace.root.clone()),
        "tool.read_file",
        SpanKind::Tool,
        1_042,
    )?
    .attribute("tool", "read_file")?
    .attribute("duration_ms", "20")?;
    trace.add_span(tool)?;
    trace.finish_span(&tool_id, 1_062)?;

    let frame_id = SpanId::from_seed(&trace_id, 3);
    let frame = Span::new(
        trace_id.clone(),
        frame_id.clone(),
        Some(trace.root.clone()),
        "frame.render",
        SpanKind::Frame,
        1_070,
    )?
    .attribute("frame", "conversation")?
    .attribute("duration_ms", "15")?;
    trace.add_span(frame)?;
    trace.finish_span(&frame_id, 1_085)?;

    trace.finish_span(&trace.root.clone(), 1_090)?;
    assert_turn_covers(&trace)?;
    Ok(trace)
}

/// Summary of one stored trace, in `list_traces` order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceSummary {
    pub trace_id: TraceId,
    pub root_name: String,
    pub span_count: usize,
    pub started_ms: i64,
    pub duration_ms: i64,
    pub complete: bool,
    pub kinds: Vec<SpanKind>,
}

impl TraceSummary {
    fn from_trace(trace: &Trace) -> Self {
        let (root_name, duration_ms) = match trace.span(&trace.root) {
            Some(root) => (
                root.name.clone(),
                root.end_ms.map(|end| end - root.start_ms).unwrap_or(0),
            ),
            None => (String::new(), 0),
        };
        let started_ms = trace
            .spans
            .iter()
            .map(|span| span.start_ms)
            .min()
            .unwrap_or(0);
        let complete = trace.spans.iter().all(|span| span.end_ms.is_some());
        let mut kinds: Vec<SpanKind> = trace.spans.iter().map(|span| span.kind).collect();
        kinds.sort();
        kinds.dedup();
        Self {
            trace_id: trace.trace_id.clone(),
            root_name,
            span_count: trace.spans.len(),
            started_ms,
            duration_ms,
            complete,
            kinds,
        }
    }
}

#[derive(Serialize)]
struct TraceRecordRef<'a> {
    schema_version: u32,
    trace: &'a Trace,
}

#[derive(Deserialize)]
struct TraceRecord {
    schema_version: u32,
    trace: Trace,
}

/// Append-only JSONL storage for traces: one file per trace.
///
/// Each [`TraceStore::append`] writes one complete record and fsyncs it. A
/// later append leaves earlier records untouched, so the file is a local
/// history and [`TraceStore::load_trace`] returns the newest complete record.
/// Files are capped at [`MAX_TRACE_FILE_BYTES`] (or a caller limit) and are
/// forced to mode `0600` on Unix. Retention is T-OBS-03.
#[derive(Debug)]
pub struct TraceStore {
    root: PathBuf,
    max_file_bytes: u64,
    lock: Mutex<()>,
}

impl TraceStore {
    /// Open (and create) a trace directory with the default file cap.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_limit(root, MAX_TRACE_FILE_BYTES)
    }

    /// Open a trace directory with an explicit per-file byte cap.
    pub fn open_with_limit(root: impl AsRef<Path>, max_file_bytes: u64) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root, max_file_bytes, lock: Mutex::new(()) })
    }

    /// Directory holding the trace files.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Path of one trace file.
    pub fn path_for(&self, trace_id: &TraceId) -> PathBuf {
        self.root.join(format!("{trace_id}.jsonl"))
    }

    /// Validate and append one record. Returns the new file length.
    ///
    /// The append is a single write under a process mutex, with the file opened
    /// in append mode. A record that would push the file past the cap is
    /// refused with `zero.fnd.limit_exceeded` before anything is written.
    pub fn append(&self, trace: &Trace) -> Result<u64> {
        trace.validate()?;
        let record = TraceRecordRef { schema_version: TRACE_SCHEMA_VERSION, trace };
        let mut line = serde_json::to_vec(&record)?;
        if line.len() > MAX_TRACE_RECORD_BYTES {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "trace record is {} bytes; the cap is {MAX_TRACE_RECORD_BYTES}",
                    line.len()
                ),
            ));
        }
        line.push(b'\n');
        let path = self.path_for(&trace.trace_id);
        let _guard = self.lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = match std::fs::metadata(&path) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error.into()),
        };
        let projected = current.saturating_add(line.len() as u64);
        if projected > self.max_file_bytes {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "trace file {} would reach {projected} bytes; the cap is {}",
                    path.display(),
                    self.max_file_bytes
                ),
            ));
        }
        let mut file = open_append(&path)?;
        file.write_all(&line)?;
        file.flush()?;
        file.sync_data()?;
        Ok(projected)
    }

    /// Load the newest record for one trace.
    ///
    /// A missing file is `zero.fnd.not_found`; a complete but unparseable line,
    /// an empty line, and an unterminated final line are all
    /// `zero.fnd.corrupt`. A record from another schema version is
    /// `zero.fnd.schema_version`. The decoded trace is fully revalidated.
    pub fn load_trace(&self, trace_id: &TraceId) -> Result<Trace> {
        let path = self.path_for(trace_id);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ZeroError::new(
                    ErrorCode::NotFound,
                    format!("trace {trace_id} is not stored at {}", path.display()),
                ))
            }
            Err(error) => return Err(error.into()),
        };
        if bytes.is_empty() {
            return Err(corrupt(&path, 0, "trace file is empty"));
        }

        let mut latest: Option<Trace> = None;
        let mut offset = 0usize;
        for raw in bytes.split_inclusive(|byte| *byte == b'\n') {
            if raw.last() != Some(&b'\n') {
                return Err(corrupt(
                    &path,
                    offset,
                    "torn final trace record (no trailing newline)",
                ));
            }
            let line = &raw[..raw.len() - 1];
            if line.is_empty() {
                return Err(corrupt(&path, offset, "empty trace record"));
            }
            let record: TraceRecord = serde_json::from_slice(line)
                .map_err(|error| corrupt(&path, offset, &format!("unparseable trace record: {error}")))?;
            if record.schema_version != TRACE_SCHEMA_VERSION {
                return Err(ZeroError::new(
                    ErrorCode::SchemaVersion,
                    format!(
                        "{}: trace record schema {} is not supported (expected {TRACE_SCHEMA_VERSION})",
                        path.display(),
                        record.schema_version
                    ),
                ));
            }
            latest = Some(record.trace);
            offset += raw.len();
        }

        let trace = latest.ok_or_else(|| corrupt(&path, 0, "trace file has no records"))?;
        if &trace.trace_id != trace_id {
            return Err(corrupt(
                &path,
                0,
                "stored trace id does not match the file name",
            ));
        }
        trace.validate()?;
        Ok(trace)
    }

    /// Summaries of every stored trace, sorted by trace id.
    ///
    /// Files that are not named after a valid [`TraceId`] are ignored; a trace
    /// file that fails to load fails the whole listing rather than hiding data.
    pub fn list_traces(&self) -> Result<Vec<TraceSummary>> {
        let entries = match std::fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut ids = Vec::new();
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("jsonl") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            if let Ok(trace_id) = TraceId::parse(stem) {
                ids.push(trace_id);
            }
        }
        ids.sort();
        let mut summaries = Vec::with_capacity(ids.len());
        for trace_id in ids {
            let trace = self.load_trace(&trace_id)?;
            summaries.push(TraceSummary::from_trace(&trace));
        }
        Ok(summaries)
    }
}

/// Open a trace file for a single append.
///
/// `0600` is requested at creation and enforced afterwards on Unix, so an
/// existing file with looser permissions is tightened rather than trusted.
fn open_append(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(0o600);
        file.set_permissions(permissions)?;
    }
    Ok(file)
}

/// Deterministic text tree with durations and span attributes.
pub fn render_text(trace: &Trace) -> Result<String> {
    let root = trace.span_tree()?;
    let mut out = format!("trace {} root={}\n", trace.trace_id, trace.root);
    render_node(&root, 0, &mut out);
    Ok(out)
}

fn render_node(node: &SpanNode, depth: usize, out: &mut String) {
    let indent = "  ".repeat(depth);
    let duration = match node.end_ms {
        Some(end) => format!("{}ms", end - node.start_ms),
        None => "open".to_string(),
    };
    out.push_str(&format!(
        "{indent}{} [{}] {}",
        node.name, node.kind, duration
    ));
    match node.end_ms {
        Some(end) => out.push_str(&format!(" ({}..{end})", node.start_ms)),
        None => out.push_str(&format!(" (start {})", node.start_ms)),
    }
    for (key, value) in &node.attributes {
        out.push_str(&format!(" {key}={value}"));
    }
    if node.events > 0 {
        out.push_str(&format!(" events={}", node.events));
    }
    out.push('\n');
    for child in &node.children {
        render_node(child, depth + 1, out);
    }
}

/// Pretty JSON projection of a validated trace.
pub fn to_json(trace: &Trace) -> Result<String> {
    trace.validate()?;
    Ok(serde_json::to_string_pretty(trace)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn tid() -> TraceId {
        TraceId::parse("0123456789abcdef0123456789abcdef").unwrap()
    }

    fn sid(n: u64) -> SpanId {
        SpanId::parse(format!("{n:016x}")).unwrap()
    }

    fn trace_with_root() -> Trace {
        let trace_id = tid();
        let root = sid(0);
        let mut trace = Trace::new(trace_id.clone(), root.clone());
        let span = Span::new(trace_id, root, None, "turn", SpanKind::Turn, 100).unwrap();
        trace.add_span(span).unwrap();
        trace
    }

    #[test]
    fn spans_add_finish_and_order_deterministically() {
        let mut trace = trace_with_root();
        let trace_id = trace.trace_id.clone();
        let root = trace.root.clone();

        let late = sid(2);
        let early = sid(1);
        trace
            .add_span(
                Span::new(
                    trace_id.clone(),
                    late.clone(),
                    Some(root.clone()),
                    "tool.late",
                    SpanKind::Tool,
                    120,
                )
                .unwrap(),
            )
            .unwrap();
        trace
            .add_span(
                Span::new(
                    trace_id,
                    early.clone(),
                    Some(root.clone()),
                    "provider.early",
                    SpanKind::Provider,
                    110,
                )
                .unwrap(),
            )
            .unwrap();

        trace.finish_span(&early, 115).unwrap();
        trace.finish_span(&late, 130).unwrap();
        trace.finish_span(&root, 140).unwrap();

        let tree = trace.span_tree().unwrap();
        assert_eq!(tree.kind, SpanKind::Turn);
        assert_eq!(tree.end_ms, Some(140));
        assert_eq!(tree.children.len(), 2);
        assert_eq!(tree.children[0].name, "provider.early");
        assert_eq!(tree.children[0].end_ms, Some(115));
        assert_eq!(tree.children[1].name, "tool.late");
        assert_eq!(trace.span(&early).unwrap().duration_ms(), Some(5));
        assert_eq!(trace.span_count(), 3);

        assert_eq!(
            trace.finish_span(&early, 116).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            trace.finish_span(&sid(99), 1).unwrap_err().code(),
            ErrorCode::NotFound
        );
    }

    #[test]
    fn duplicate_orphan_and_cycle_spans_are_rejected() {
        let mut trace = trace_with_root();
        let trace_id = trace.trace_id.clone();
        let root = trace.root.clone();

        let orphan = Span::new(
            trace_id.clone(),
            sid(5),
            Some(sid(4)),
            "tool.orphan",
            SpanKind::Tool,
            101,
        )
        .unwrap();
        assert_eq!(trace.add_span(orphan).unwrap_err().code(), ErrorCode::InvalidInput);

        let duplicate = Span::new(
            trace_id.clone(),
            root.clone(),
            Some(sid(3)),
            "turn.duplicate",
            SpanKind::Tool,
            101,
        )
        .unwrap();
        assert_eq!(
            trace.add_span(duplicate).unwrap_err().code(),
            ErrorCode::InvalidInput
        );

        let child = sid(6);
        trace
            .add_span(
                Span::new(
                    trace_id,
                    child.clone(),
                    Some(root.clone()),
                    "tool.child",
                    SpanKind::Tool,
                    102,
                )
                .unwrap(),
            )
            .unwrap();
        // Root -> child -> root is a cycle.
        trace.spans[0].parent = Some(child.clone());
        assert_eq!(trace.validate().unwrap_err().code(), ErrorCode::InvalidInput);

        // Restore the root, then make the child its own parent.
        trace.spans[0].parent = None;
        trace.spans[1].parent = Some(child);
        assert_eq!(trace.validate().unwrap_err().code(), ErrorCode::InvalidInput);

        // A duplicate span injected past the constructor is still refused.
        let mut duplicated = trace_with_root();
        duplicated.spans.push(duplicated.spans[0].clone());
        assert_eq!(
            duplicated.validate().unwrap_err().code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn scripted_turn_covers_provider_tool_and_frame() {
        let trace = turn_trace().unwrap();
        assert_turn_covers(&trace).unwrap();
        assert_eq!(trace.span_count(), 4);

        let root = trace.span(&trace.root).unwrap();
        assert_eq!(root.kind, SpanKind::Turn);
        assert_eq!(root.end_ms, Some(1_090));
        for kind in [SpanKind::Provider, SpanKind::Tool, SpanKind::Frame] {
            let span = trace
                .spans
                .iter()
                .find(|span| span.kind == kind)
                .unwrap_or_else(|| panic!("missing {kind} span"));
            assert_eq!(span.parent.as_ref(), Some(&trace.root), "{kind}");
            assert!(span.start_ms >= root.start_ms, "{kind}");
            assert!(span.end_ms.unwrap() <= root.end_ms.unwrap(), "{kind}");
        }

        let tree = trace.span_tree().unwrap();
        assert_eq!(tree.children.len(), 3);
        assert_eq!(
            tree.children
                .iter()
                .map(|child| child.kind)
                .collect::<Vec<_>>(),
            vec![SpanKind::Provider, SpanKind::Tool, SpanKind::Frame]
        );

        let mut broken = trace.clone();
        broken.spans.retain(|span| span.kind != SpanKind::Frame);
        broken.validate().unwrap();
        assert_eq!(
            assert_turn_covers(&broken).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn secret_and_message_attribute_keys_are_rejected() {
        let trace_id = tid();
        for key in [
            "api_key",
            "provider_token",
            "password",
            "client_secret",
            "Authorization",
        ] {
            let span = Span::new(
                trace_id.clone(),
                sid(1),
                None,
                "provider.complete",
                SpanKind::Provider,
                0,
            )
            .unwrap();
            let error = span.attribute(key, "redacted").unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidInput, "{key}");
        }

        for key in ["prompt", "message", "content", "completion"] {
            let span = Span::new(
                trace_id.clone(),
                sid(1),
                None,
                "provider.complete",
                SpanKind::Provider,
                0,
            )
            .unwrap();
            let error = span.attribute(key, "hello").unwrap_err();
            assert_eq!(error.code(), ErrorCode::InvalidInput, "{key}");
        }

        let safe = Span::new(
            trace_id,
            sid(1),
            None,
            "provider.complete",
            SpanKind::Provider,
            0,
        )
        .unwrap()
        .attribute("model", "zero-local")
        .unwrap();
        assert_eq!(safe.attributes["model"], "zero-local");
    }

    #[test]
    fn control_characters_are_stripped_from_names_attributes_and_events() {
        let span = Span::new(
            tid(),
            sid(1),
            None,
            "provider\n.complete",
            SpanKind::Provider,
            0,
        )
        .unwrap()
        .attribute("prov\nider", "local\u{1b}[31m")
        .unwrap()
        .attribute("model", "local\nmodel\t1")
        .unwrap()
        .event(1, "first\tline")
        .unwrap();

        assert_eq!(span.name, "provider.complete");
        assert_eq!(span.attributes["provider"], "local[31m");
        assert_eq!(span.attributes["model"], "localmodel1");
        assert_eq!(span.events[0].1, "firstline");
        span.validate().unwrap();
    }

    #[test]
    fn trace_validation_rejects_wrong_trace_and_bad_timing() {
        let mut trace = trace_with_root();
        let other = TraceId::from_seed("other-trace");
        let foreign = Span::new(other, sid(9), None, "turn", SpanKind::Turn, 1).unwrap();
        assert_eq!(
            trace.add_span(foreign).unwrap_err().code(),
            ErrorCode::InvalidInput
        );

        let root = trace.root.clone();
        assert_eq!(
            trace.finish_span(&root, 99).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
        trace.finish_span(&root, 100).unwrap();

        assert!(TraceId::parse("ABC").is_err());
        assert!(TraceId::parse("0123456789abcdef0123456789abcde").is_err());
        assert!(SpanId::parse("000000000000000g").is_err());
        assert!(SpanId::parse("0000000000000000").is_ok());
    }

    #[test]
    fn jsonl_append_and_load_round_trip_newest_record() {
        let directory = tempfile::tempdir().unwrap();
        let store = TraceStore::open(directory.path().join("traces")).unwrap();
        let mut trace = turn_trace().unwrap();
        let path = store.path_for(&trace.trace_id);

        let written = store.append(&trace).unwrap();
        assert!(written > 0);
        assert!(std::fs::read(&path).unwrap().ends_with(b"\n"));
        assert_eq!(store.load_trace(&trace.trace_id).unwrap(), trace);

        trace.spans[1]
            .attributes
            .insert("cached".to_string(), "true".to_string());
        let second = store.append(&trace).unwrap();
        assert!(second > written);
        assert_eq!(store.load_trace(&trace.trace_id).unwrap(), trace);
        assert_eq!(
            std::fs::read_to_string(&path)
                .unwrap()
                .lines()
                .count(),
            2
        );

        let missing = TraceId::from_seed("missing");
        assert_eq!(
            store.load_trace(&missing).unwrap_err().code(),
            ErrorCode::NotFound
        );
    }

    #[test]
    fn corrupt_torn_and_wrong_schema_records_are_typed() {
        let directory = tempfile::tempdir().unwrap();
        let store = TraceStore::open(directory.path()).unwrap();
        let trace = turn_trace().unwrap();
        let path = store.path_for(&trace.trace_id);

        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"{\"schema_version\":1,\"trace\":{").unwrap();
        drop(file);
        assert_eq!(
            store.load_trace(&trace.trace_id).unwrap_err().code(),
            ErrorCode::Corrupt
        );

        std::fs::write(&path, b"not json\n").unwrap();
        assert_eq!(
            store.load_trace(&trace.trace_id).unwrap_err().code(),
            ErrorCode::Corrupt
        );

        std::fs::write(&path, b"\n").unwrap();
        assert_eq!(
            store.load_trace(&trace.trace_id).unwrap_err().code(),
            ErrorCode::Corrupt
        );

        std::fs::write(&path, b"").unwrap();
        assert_eq!(
            store.load_trace(&trace.trace_id).unwrap_err().code(),
            ErrorCode::Corrupt
        );

        let record = serde_json::json!({"schema_version": 99, "trace": trace});
        std::fs::write(&path, format!("{}\n", serde_json::to_string(&record).unwrap())).unwrap();
        assert_eq!(
            store.load_trace(&trace.trace_id).unwrap_err().code(),
            ErrorCode::SchemaVersion
        );
    }

    #[test]
    fn list_traces_returns_sorted_summaries() {
        let directory = tempfile::tempdir().unwrap();
        let store = TraceStore::open(directory.path()).unwrap();
        let first = turn_trace().unwrap();
        store.append(&first).unwrap();

        let second_id = TraceId::from_seed("second-turn");
        let mut second = Trace::start(second_id.clone(), "turn", 500).unwrap();
        let second_root = second.root.clone();
        second
            .add_span(
                Span::new(
                    second_id.clone(),
                    SpanId::from_seed(&second_id, 1),
                    Some(second_root.clone()),
                    "tool.echo",
                    SpanKind::Tool,
                    501,
                )
                .unwrap(),
            )
            .unwrap();
        store.append(&second).unwrap();

        let summaries = store.list_traces().unwrap();
        assert_eq!(summaries.len(), 2);
        assert!(summaries
            .windows(2)
            .all(|pair| pair[0].trace_id <= pair[1].trace_id));

        let summary = summaries
            .iter()
            .find(|summary| summary.trace_id == first.trace_id)
            .unwrap();
        assert_eq!(summary.root_name, "turn");
        assert_eq!(summary.span_count, 4);
        assert_eq!(summary.started_ms, 1_000);
        assert_eq!(summary.duration_ms, 90);
        assert!(summary.complete);
        assert_eq!(
            summary.kinds,
            vec![
                SpanKind::Turn,
                SpanKind::Provider,
                SpanKind::Tool,
                SpanKind::Frame
            ]
        );

        let incomplete = summaries
            .iter()
            .find(|summary| summary.trace_id == second_id)
            .unwrap();
        assert!(!incomplete.complete);
        assert_eq!(incomplete.duration_ms, 0);
    }

    #[test]
    fn render_text_and_json_are_deterministic() {
        let first = turn_trace().unwrap();
        let second = turn_trace().unwrap();
        assert_eq!(render_text(&first).unwrap(), render_text(&second).unwrap());
        assert_eq!(to_json(&first).unwrap(), to_json(&second).unwrap());

        let text = render_text(&first).unwrap();
        assert!(text.starts_with(&format!("trace {}", first.trace_id)), "{text}");
        for needle in [
            "turn [turn] 90ms",
            "provider.complete [provider] 40ms",
            "tool.read_file [tool] 20ms",
            "frame.render [frame] 15ms",
            "model=zero-local",
            "tool=read_file",
        ] {
            assert!(text.contains(needle), "missing `{needle}` in:\n{text}");
        }

        let value: Value = serde_json::from_str(&to_json(&first).unwrap()).unwrap();
        assert_eq!(value["spans"].as_array().unwrap().len(), 4);
        assert_eq!(value["trace_id"].as_str(), Some(first.trace_id.as_str()));
    }

    #[test]
    fn append_refuses_records_past_the_file_cap() {
        let directory = tempfile::tempdir().unwrap();
        let store = TraceStore::open_with_limit(directory.path(), 16).unwrap();
        let trace = turn_trace().unwrap();
        let error = store.append(&trace).unwrap_err();
        assert_eq!(error.code(), ErrorCode::LimitExceeded);
        assert!(!store.path_for(&trace.trace_id).exists());
    }

    #[cfg(unix)]
    #[test]
    fn trace_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let store = TraceStore::open(directory.path()).unwrap();
        let trace = turn_trace().unwrap();
        store.append(&trace).unwrap();
        let mode = std::fs::metadata(store.path_for(&trace.trace_id))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn the_module_contains_no_network_code() {
        let source = include_str!("trace.rs");
        let forbidden = [
            concat!("std::", "net"),
            concat!("Tcp", "Stream"),
            concat!("Udp", "Socket"),
            concat!("Tcp", "Listener"),
            concat!("req", "west"),
            concat!("hyper", "::"),
            concat!("ure", "q"),
            concat!("http", "://"),
            concat!("https", "://"),
        ];
        for token in forbidden {
            assert!(
                !source.contains(token),
                "trace.rs must stay local-only, found `{token}`"
            );
        }
    }
}
