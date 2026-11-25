//! Monitor engine (MON-06, MON-11, MON-13, MON-14, T-MON-02).
//!
//! A monitor is a long-running child process. Each stdout line becomes content
//! in an event; bursts are coalesced into a single [`MonitorEvent`] so an idle
//! or chatty monitor does not spend a token per line. Stderr never becomes an
//! event: it goes to a [`LogSink`] through a bounded queue that drops the
//! oldest line and counts the drop when the sink stalls.
//!
//! The engine is synchronous and caller-driven: [`MonitorEngine::start`] spawns,
//! [`MonitorEngine::drain`] collects ready events, [`MonitorEngine::stop`] kills
//! and reaps, and [`MonitorEngine::mute`] silences one monitor without stopping
//! it. There is no ambient runtime and no background timer.
//!
//! # No shell by default
//!
//! [`MonitorSpec`] names an executable and its arguments. The engine never
//! wraps the command in `sh -c`, `cmd /c`, or PowerShell. A caller that needs a
//! shell must name it explicitly, so every shell metacharacter is visible to the
//! policy layer (M2) instead of being hidden inside a monitor string.
//!
//! # Environment scrubbing
//!
//! A child is spawned with a merged and scrubbed environment: variables whose
//! names contain `KEY`, `TOKEN`, `SECRET`, `PASSWORD`, or `CREDENTIAL` are
//! removed, except `SSH_AUTH_SOCK` and `GPG_AGENT_INFO`. The policy is a local
//! duplicate of `zero-secrets::scrubbed_env` because `zero-agent` sits above
//! `zero-secrets` in the dependency graph and `zero-agent` must not depend on it
//! (CRT-04). Keep the two lists in sync.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::Instant;
use zero_types::error::{ErrorCode, Result, ZeroError};

/// Appended to a stdout or stderr line that exceeded the per-line cap.
pub const TRUNCATION_MARKER: &str = " ...[truncated]";
/// Default per-line cap for both streams.
pub const DEFAULT_LINE_CAP_BYTES: usize = 8 * 1024;
/// Default bound on stdout lines waiting for a `drain` call.
pub const DEFAULT_MAX_QUEUED_LINES: usize = 4 * 1024;
/// Default bound on events returned by one `drain` call.
pub const DEFAULT_MAX_EVENTS_PER_DRAIN: usize = 16;
/// Default bound on stderr lines waiting for the sink.
pub const DEFAULT_STDERR_QUEUE_LINES: usize = 256;
/// Default bound on lines kept by [`MemoryLogSink`].
pub const DEFAULT_MEMORY_LOG_LINES: usize = 256;

const SECRET_MARKERS: &[&str] = &["KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"];
const SECRET_EXEMPT: &[&str] = &["SSH_AUTH_SOCK", "GPG_AGENT_INFO"];

// ---------------------------------------------------------------------------
// Spec, status, event
// ---------------------------------------------------------------------------

/// Declarative description of one monitor (MON-09 shape).
///
/// `command` is an executable, not a shell string. `args` is passed verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorSpec {
    pub id: String,
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env: BTreeMap<String, String>,
    pub description: Option<String>,
    /// Per-line cap for this monitor's stdout and stderr. When `None`, the
    /// engine-wide `with_line_cap` default applies.
    pub max_output_bytes: Option<usize>,
}

impl MonitorSpec {
    pub fn new(id: impl Into<String>, name: impl Into<String>, command: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            command: command.into(),
            args: Vec::new(),
            cwd: None,
            env: BTreeMap::new(),
            description: None,
            max_output_bytes: None,
        }
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn cwd(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cwd = Some(dir.into());
        self
    }

    pub fn env(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(name.into(), value.into());
        self
    }

    pub fn description(mut self, text: impl Into<String>) -> Self {
        self.description = Some(text.into());
        self
    }

    /// Override the per-line cap for this monitor (both streams).
    pub fn max_output_bytes(mut self, bytes: usize) -> Self {
        self.max_output_bytes = Some(bytes.max(1));
        self
    }
}

/// Lifecycle state of one monitor.
///
/// `Starting` exists for the declarative surface; [`MonitorEngine::start`]
/// spawns synchronously and returns a handle in `Running`, so callers normally
/// observe only `Running`, `Stopped`, or `Failed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorStatus {
    Starting,
    Running,
    Stopped,
    Failed,
}

/// A monitor after a successful spawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorHandle {
    pub id: String,
    pub status: MonitorStatus,
    pub pid: u32,
}

/// One coalesced stdout burst from one monitor.
///
/// `lines` preserves arrival order and contains only stdout. `line_count` is
/// the number of lines in this event (equal to `lines.len()`); `truncated` is
/// true when a line was cut at the per-line cap or when a burst was split
/// because the per-burst cap was reached (the remainder stays buffered).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorEvent {
    pub monitor_id: String,
    pub at_ms: i64,
    pub lines: Vec<String>,
    pub truncated: bool,
    pub line_count: usize,
}

/// Coalescing thresholds for stdout bursts (MON-13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BurstWindow {
    pub max_lines: usize,
    pub max_bytes: usize,
    pub window_ms: u64,
}

impl BurstWindow {
    /// Values are clamped so a window always makes progress.
    pub fn new(max_lines: usize, max_bytes: usize, window_ms: u64) -> Self {
        Self { max_lines: max_lines.max(1), max_bytes: max_bytes.max(1), window_ms }
    }
}

impl Default for BurstWindow {
    fn default() -> Self {
        Self::new(64, 16 * 1024, 250)
    }
}

/// Destination for stderr lines. A sink never sees stdout.
pub trait LogSink: Send + Sync {
    fn log(&self, line: &str);
}

/// Bounded, drop-oldest in-memory sink used by tests and by the default engine.
#[derive(Debug)]
pub struct MemoryLogSink {
    lines: Mutex<VecDeque<String>>,
    capacity: usize,
    dropped: AtomicU64,
}

impl Default for MemoryLogSink {
    fn default() -> Self {
        Self::new(DEFAULT_MEMORY_LOG_LINES)
    }
}

impl MemoryLogSink {
    pub fn new(capacity: usize) -> Self {
        Self {
            lines: Mutex::new(VecDeque::new()),
            capacity: capacity.max(1),
            dropped: AtomicU64::new(0),
        }
    }

    /// A snapshot of the retained lines, oldest first.
    pub fn lines(&self) -> Vec<String> {
        lock(&self.lines).iter().cloned().collect()
    }

    /// Lines dropped because the tail was full.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::SeqCst)
    }

    pub fn clear(&self) {
        lock(&self.lines).clear();
    }
}

impl LogSink for MemoryLogSink {
    fn log(&self, line: &str) {
        let mut lines = lock(&self.lines);
        if lines.len() >= self.capacity {
            lines.pop_front();
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
        lines.push_back(line.to_string());
    }
}

/// Counters and current state for one monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorStats {
    pub status: MonitorStatus,
    pub pid: u32,
    pub started_at_ms: i64,
    /// True once the stdout reader reached end of file.
    pub eof: bool,
    /// True when the engine killed the child for exceeding its timeout.
    pub timed_out: bool,
    pub stdout_lines: u64,
    pub stderr_lines: u64,
    /// Lines whose content was cut at the per-line cap.
    pub truncated_lines: u64,
    /// Buffered stdout lines discarded because the queue was full.
    pub dropped_stdout: u64,
    /// stdout lines discarded while the monitor was muted.
    pub dropped_on_mute: u64,
    /// Buffered stdout lines discarded by an explicit stop.
    pub dropped_on_stop: u64,
    /// Bursts split by the per-burst line or byte cap.
    pub split_bursts: u64,
    /// stderr lines dropped because the sink was too slow.
    pub stderr_dropped: u64,
    pub pending_lines: usize,
    pub buffered_bytes: usize,
}

// ---------------------------------------------------------------------------
// Environment policy
// ---------------------------------------------------------------------------

/// Whether a variable name looks credential-bearing under the CRT-04 policy.
pub fn is_secret_variable(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    SECRET_MARKERS.iter().any(|marker| upper.contains(marker))
        && !SECRET_EXEMPT.contains(&upper.as_str())
}

/// Remove credential-bearing variables from a child environment.
pub fn scrubbed_env(base: impl IntoIterator<Item = (String, String)>) -> BTreeMap<String, String> {
    base.into_iter().filter(|(name, _)| !is_secret_variable(name)).collect()
}

fn monitor_environment(spec_env: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut merged = BTreeMap::new();
    for (name, value) in std::env::vars_os() {
        let (Ok(name), Ok(value)) = (name.into_string(), value.into_string()) else {
            // A non-Unicode entry cannot be forwarded safely; drop it.
            continue;
        };
        merged.insert(name, value);
    }
    merged.extend(spec_env.iter().map(|(name, value)| (name.clone(), value.clone())));
    scrubbed_env(merged)
}

// ---------------------------------------------------------------------------
// pty-free line reader
// ---------------------------------------------------------------------------

enum ReadLine {
    Line { text: String, truncated: bool },
    Eof,
}

fn text_floor_boundary(text: &str, cap: usize) -> usize {
    if cap >= text.len() {
        return text.len();
    }
    let mut index = cap;
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn read_line<R: BufRead>(reader: &mut R, cap: usize) -> std::io::Result<ReadLine> {
    let mut bytes = Vec::new();
    let mut truncated = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if bytes.is_empty() && !truncated {
                return Ok(ReadLine::Eof);
            }
            break;
        }
        let mut consumed = 0usize;
        let mut newline = false;
        for &byte in available {
            consumed += 1;
            if byte == b'\n' {
                newline = true;
                break;
            }
            if bytes.len() < cap {
                bytes.push(byte);
            } else {
                // The physical line continues past the cap. Consume it all so
                // it cannot leak into the next line, but keep only the prefix.
                truncated = true;
            }
        }
        reader.consume(consumed);
        if newline {
            break;
        }
    }
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if text.ends_with('\r') {
        text.pop();
    }
    if truncated {
        let boundary = text_floor_boundary(&text, cap.min(text.len()));
        text.truncate(boundary);
        text.push_str(TRUNCATION_MARKER);
    }
    Ok(ReadLine::Line { text, truncated })
}

// ---------------------------------------------------------------------------
// stderr pump: bounded queue, drop-oldest, counted
// ---------------------------------------------------------------------------

struct StderrQueue {
    lines: VecDeque<String>,
    capacity: usize,
    closed: bool,
    dropped: u64,
}

struct StderrPump {
    shared: Arc<(Mutex<StderrQueue>, Condvar)>,
    writer: Option<JoinHandle<()>>,
}

fn push_stderr(pump: &Arc<(Mutex<StderrQueue>, Condvar)>, line: String) {
    let (lock, ready) = pump.as_ref();
    let mut queue = lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if queue.lines.len() >= queue.capacity {
        queue.lines.pop_front();
        queue.dropped += 1;
    }
    queue.lines.push_back(line);
    ready.notify_one();
}

impl StderrPump {
    fn new(capacity: usize, sink: Arc<dyn LogSink>) -> std::io::Result<Self> {
        let shared = Arc::new((
            Mutex::new(StderrQueue {
                lines: VecDeque::new(),
                capacity: capacity.max(1),
                closed: false,
                dropped: 0,
            }),
            Condvar::new(),
        ));
        let writer_shared = Arc::clone(&shared);
        let writer = std::thread::Builder::new()
            .name("zero-monitor-stderr-sink".to_string())
            .spawn(move || {
                let (lock, ready) = writer_shared.as_ref();
                loop {
                    let line = {
                        let mut queue =
                            lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        while queue.lines.is_empty() && !queue.closed {
                            queue = ready
                                .wait(queue)
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                        }
                        queue.lines.pop_front()
                    };
                    match line {
                        Some(line) => sink.log(&line),
                        None => break,
                    }
                }
            })?;
        Ok(Self { shared, writer: Some(writer) })
    }

    fn sender(&self) -> Arc<(Mutex<StderrQueue>, Condvar)> {
        Arc::clone(&self.shared)
    }

    fn dropped(&self) -> u64 {
        let (lock, _) = self.shared.as_ref();
        lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner).dropped
    }

    /// Close the queue and wake the writer. A writer blocked inside a stalled
    /// sink is detached, never joined: stop must never wait on a slow sink.
    fn close(&mut self) {
        {
            let (lock, ready) = self.shared.as_ref();
            let mut queue = lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            queue.closed = true;
            ready.notify_all();
        }
        if let Some(writer) = self.writer.take() {
            if writer.is_finished() {
                let _ = writer.join();
            }
        }
    }
}

impl Drop for StderrPump {
    fn drop(&mut self) {
        self.close();
    }
}

// ---------------------------------------------------------------------------
// Runtime
// ---------------------------------------------------------------------------

struct PendingLine {
    text: String,
    at: Instant,
    truncated: bool,
    bytes: usize,
}

struct SharedState {
    inbox: VecDeque<PendingLine>,
    buffered_bytes: usize,
    max_queued_lines: usize,
    muted: bool,
    stdout_eof: bool,
    stdout_lines: u64,
    stderr_lines: u64,
    truncated_lines: u64,
    dropped_stdout: u64,
    muted_dropped: u64,
    stopped_dropped: u64,
    split_bursts: u64,
}

impl SharedState {
    fn new(max_queued_lines: usize) -> Self {
        Self {
            inbox: VecDeque::new(),
            buffered_bytes: 0,
            max_queued_lines: max_queued_lines.max(1),
            muted: false,
            stdout_eof: false,
            stdout_lines: 0,
            stderr_lines: 0,
            truncated_lines: 0,
            dropped_stdout: 0,
            muted_dropped: 0,
            stopped_dropped: 0,
            split_bursts: 0,
        }
    }
}

fn spawn_stdout_reader(
    shared: Arc<Mutex<SharedState>>,
    stdout: std::process::ChildStdout,
    line_cap: usize,
) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("zero-monitor-stdout".to_string())
        .spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                match read_line(&mut reader, line_cap) {
                    Ok(ReadLine::Eof) | Err(_) => break,
                    Ok(ReadLine::Line { text, truncated }) => {
                        let bytes = text.len();
                        let mut state = lock(&shared);
                        state.stdout_lines += 1;
                        if truncated {
                            state.truncated_lines += 1;
                        }
                        if state.muted {
                            state.muted_dropped += 1;
                            continue;
                        }
                        if state.inbox.len() >= state.max_queued_lines {
                            if let Some(dropped) = state.inbox.pop_front() {
                                state.buffered_bytes =
                                    state.buffered_bytes.saturating_sub(dropped.bytes);
                                state.dropped_stdout += 1;
                            }
                        }
                        state.buffered_bytes += bytes;
                        state.inbox.push_back(PendingLine {
                            text,
                            at: Instant::now(),
                            truncated,
                            bytes,
                        });
                    }
                }
            }
            lock(&shared).stdout_eof = true;
        })
}

fn spawn_stderr_reader(
    shared: Arc<Mutex<SharedState>>,
    stderr: std::process::ChildStderr,
    line_cap: usize,
    pump: Arc<(Mutex<StderrQueue>, Condvar)>,
) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("zero-monitor-stderr".to_string())
        .spawn(move || {
            let mut reader = BufReader::new(stderr);
            loop {
                match read_line(&mut reader, line_cap) {
                    Ok(ReadLine::Eof) | Err(_) => break,
                    Ok(ReadLine::Line { text, .. }) => {
                        lock(&shared).stderr_lines += 1;
                        push_stderr(&pump, text);
                    }
                }
            }
        })
}

struct MonitorRuntime {
    spec: MonitorSpec,
    child: Option<Child>,
    status: MonitorStatus,
    pid: u32,
    started_at_ms: i64,
    timed_out: bool,
    shared: Arc<Mutex<SharedState>>,
    stdout_reader: Option<JoinHandle<()>>,
    stderr_reader: Option<JoinHandle<()>>,
    pump: Option<StderrPump>,
    stderr_dropped: u64,
    ready: VecDeque<MonitorEvent>,
}

impl MonitorRuntime {
    fn join_finished_readers(&mut self) {
        if self.stdout_reader.as_ref().is_some_and(JoinHandle::is_finished) {
            if let Some(handle) = self.stdout_reader.take() {
                let _ = handle.join();
            }
        }
        if self.stderr_reader.as_ref().is_some_and(JoinHandle::is_finished) {
            if let Some(handle) = self.stderr_reader.take() {
                let _ = handle.join();
            }
        }
    }

    /// Kill the child (if any), reap it, join both readers, and retire the
    /// stderr pump. `by_user` clears buffered stdout and ready events so a
    /// later drain cannot emit anything after an explicit stop.
    fn terminate(&mut self, by_user: bool) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(handle) = self.stdout_reader.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.stderr_reader.take() {
            let _ = handle.join();
        }
        if by_user {
            {
                let mut state = lock(&self.shared);
                let dropped = state.inbox.len() as u64;
                state.inbox.clear();
                state.buffered_bytes = 0;
                state.stopped_dropped += dropped;
                state.muted = false;
            }
            self.ready.clear();
            self.status = MonitorStatus::Stopped;
        }
        self.retire_pump();
    }

    fn retire_pump(&mut self) {
        if let Some(mut pump) = self.pump.take() {
            self.stderr_dropped = pump.dropped();
            pump.close();
        }
    }

    fn poll_lifecycle(&mut self, now_ms: i64, timeout_ms: Option<u64>) {
        let Some(child) = self.child.as_mut() else {
            self.join_finished_readers();
            return;
        };
        if let Some(limit) = timeout_ms {
            let elapsed = now_ms.saturating_sub(self.started_at_ms);
            if elapsed >= 0 && u64::try_from(elapsed).unwrap_or(u64::MAX) >= limit {
                self.timed_out = true;
                self.terminate(false);
                self.status = MonitorStatus::Failed;
                return;
            }
        }
        match child.try_wait() {
            Ok(Some(exit)) => {
                self.status =
                    if exit.success() { MonitorStatus::Stopped } else { MonitorStatus::Failed };
                self.child = None;
                self.join_finished_readers();
            }
            Ok(None) => {
                if self.status == MonitorStatus::Starting {
                    self.status = MonitorStatus::Running;
                }
            }
            Err(_) => {
                self.status = MonitorStatus::Failed;
                self.terminate(false);
            }
        }
    }

    fn set_muted(&mut self, muted: bool) {
        let mut state = lock(&self.shared);
        state.muted = muted;
        if muted {
            let dropped = state.inbox.len() as u64;
            state.inbox.clear();
            state.buffered_bytes = 0;
            state.muted_dropped += dropped;
        }
    }

    fn next_event(&mut self, window: BurstWindow, now_ms: i64) -> Option<MonitorEvent> {
        if let Some(event) = self.ready.pop_front() {
            return Some(event);
        }
        self.take_burst(window, now_ms)
    }

    fn take_burst(&mut self, window: BurstWindow, now_ms: i64) -> Option<MonitorEvent> {
        let terminal = matches!(self.status, MonitorStatus::Stopped | MonitorStatus::Failed);
        let mut state = lock(&self.shared);
        if state.inbox.is_empty() {
            return None;
        }
        let elapsed_ms = state
            .inbox
            .front()
            .map(|line| line.at.elapsed().as_millis() as u64)
            .unwrap_or(0);
        let ready = terminal
            || state.stdout_eof
            || state.inbox.len() >= window.max_lines
            || state.buffered_bytes >= window.max_bytes
            || elapsed_ms >= window.window_ms;
        if !ready {
            return None;
        }

        let mut lines = Vec::new();
        let mut bytes = 0usize;
        let mut truncated = false;
        while let Some(front) = state.inbox.front() {
            if lines.len() >= window.max_lines {
                truncated = true;
                break;
            }
            if !lines.is_empty() && bytes + front.bytes > window.max_bytes {
                truncated = true;
                break;
            }
            let line = state.inbox.pop_front().expect("front is present");
            state.buffered_bytes = state.buffered_bytes.saturating_sub(line.bytes);
            bytes += line.bytes;
            if line.truncated {
                truncated = true;
            }
            lines.push(line.text);
        }
        if !state.inbox.is_empty() {
            truncated = true;
            state.split_bursts += 1;
        }
        let line_count = lines.len();
        drop(state);
        if line_count == 0 {
            return None;
        }
        Some(MonitorEvent {
            monitor_id: self.spec.id.clone(),
            at_ms: now_ms,
            lines,
            truncated,
            line_count,
        })
    }

    fn stats(&self) -> MonitorStats {
        let state = lock(&self.shared);
        MonitorStats {
            status: self.status,
            pid: self.pid,
            started_at_ms: self.started_at_ms,
            eof: state.stdout_eof,
            timed_out: self.timed_out,
            stdout_lines: state.stdout_lines,
            stderr_lines: state.stderr_lines,
            truncated_lines: state.truncated_lines,
            dropped_stdout: state.dropped_stdout,
            dropped_on_mute: state.muted_dropped,
            dropped_on_stop: state.stopped_dropped,
            split_bursts: state.split_bursts,
            stderr_dropped: self.pump.as_ref().map(StderrPump::dropped).unwrap_or(self.stderr_dropped),
            pending_lines: state.inbox.len(),
            buffered_bytes: state.buffered_bytes,
        }
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Owns every monitor, the shared log sink, and the coalescing policy.
pub struct MonitorEngine {
    monitors: Vec<MonitorRuntime>,
    sink: Arc<dyn LogSink>,
    window: BurstWindow,
    line_cap: usize,
    max_queued_lines: usize,
    max_events_per_drain: usize,
    stderr_queue_lines: usize,
    timeout_ms: Option<u64>,
}

impl Default for MonitorEngine {
    fn default() -> Self {
        Self::with_sink(Arc::new(MemoryLogSink::default()))
    }
}

impl MonitorEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_sink(sink: Arc<dyn LogSink>) -> Self {
        Self {
            monitors: Vec::new(),
            sink,
            window: BurstWindow::default(),
            line_cap: DEFAULT_LINE_CAP_BYTES,
            max_queued_lines: DEFAULT_MAX_QUEUED_LINES,
            max_events_per_drain: DEFAULT_MAX_EVENTS_PER_DRAIN,
            stderr_queue_lines: DEFAULT_STDERR_QUEUE_LINES,
            timeout_ms: None,
        }
    }

    pub fn with_window(mut self, window: BurstWindow) -> Self {
        self.window = window;
        self
    }

    pub fn with_line_cap(mut self, bytes: usize) -> Self {
        self.line_cap = bytes.max(1);
        self
    }

    pub fn with_max_queued_lines(mut self, lines: usize) -> Self {
        self.max_queued_lines = lines.max(1);
        self
    }

    pub fn with_max_events_per_drain(mut self, events: usize) -> Self {
        self.max_events_per_drain = events.max(1);
        self
    }

    pub fn with_stderr_queue(mut self, lines: usize) -> Self {
        self.stderr_queue_lines = lines.max(1);
        self
    }

    /// Optional wall-clock budget measured against the `now_ms` passed to
    /// `start` and `drain`. A timed-out monitor is killed, reaped, marked
    /// `Failed`, and its final buffered lines are drained once.
    pub fn with_timeout_ms(mut self, timeout_ms: Option<u64>) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    pub fn ids(&self) -> Vec<&str> {
        self.monitors.iter().map(|monitor| monitor.spec.id.as_str()).collect()
    }

    pub fn status(&self, id: &str) -> Option<MonitorStatus> {
        self.monitors.iter().find(|monitor| monitor.spec.id == id).map(|monitor| monitor.status)
    }

    pub fn handle(&self, id: &str) -> Option<MonitorHandle> {
        self.monitors.iter().find(|monitor| monitor.spec.id == id).map(|monitor| MonitorHandle {
            id: monitor.spec.id.clone(),
            status: monitor.status,
            pid: monitor.pid,
        })
    }

    pub fn stats(&self, id: &str) -> Result<MonitorStats> {
        self.monitors
            .iter()
            .find(|monitor| monitor.spec.id == id)
            .map(MonitorRuntime::stats)
            .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("monitor `{id}`")))
    }

    /// Spawn one monitor. The environment is merged and scrubbed, stdin is
    /// null, and stdout/stderr are piped to the engine's readers.
    pub fn start(&mut self, spec: MonitorSpec, now_ms: i64) -> Result<MonitorHandle> {
        if spec.id.trim().is_empty() {
            return Err(ZeroError::new(ErrorCode::InvalidInput, "monitor id is empty"));
        }
        if spec.command.trim().is_empty() {
            return Err(ZeroError::new(ErrorCode::InvalidInput, "monitor command is empty"));
        }
        if self.monitors.iter().any(|monitor| monitor.spec.id == spec.id) {
            return Err(ZeroError::new(
                ErrorCode::AlreadyExists,
                format!("monitor `{}` is already running; stop it first", spec.id),
            ));
        }

        let environment = monitor_environment(&spec.env);
        let line_cap = spec.max_output_bytes.unwrap_or(self.line_cap).max(1);
        let mut command = Command::new(&spec.command);
        command
            .args(&spec.args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in &environment {
            command.env(name, value);
        }
        if let Some(cwd) = &spec.cwd {
            command.current_dir(cwd);
        }
        let mut child = command.spawn().map_err(|error| {
            ZeroError::new(
                ErrorCode::Unavailable,
                format!(
                    "cannot start monitor `{}` (`{}`) without a shell: {error}",
                    spec.id, spec.command
                ),
            )
        })?;
        let pid = child.id();
        let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ZeroError::new(ErrorCode::Internal, "monitor pipes were not created"));
        };

        let shared = Arc::new(Mutex::new(SharedState::new(self.max_queued_lines)));
        let stdout_reader = match spawn_stdout_reader(Arc::clone(&shared), stdout, line_cap) {
            Ok(handle) => handle,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ZeroError::new(
                    ErrorCode::Internal,
                    format!("failed to start the monitor stdout reader: {error}"),
                ));
            }
        };
        let pump = match StderrPump::new(self.stderr_queue_lines, Arc::clone(&self.sink)) {
            Ok(pump) => pump,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                return Err(ZeroError::new(
                    ErrorCode::Internal,
                    format!("failed to start the monitor stderr pump: {error}"),
                ));
            }
        };
        let stderr_reader =
            match spawn_stderr_reader(Arc::clone(&shared), stderr, line_cap, pump.sender()) {
                Ok(handle) => handle,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_reader.join();
                    return Err(ZeroError::new(
                        ErrorCode::Internal,
                        format!("failed to start the monitor stderr reader: {error}"),
                    ));
                }
            };

        let id = spec.id.clone();
        self.monitors.push(MonitorRuntime {
            spec,
            child: Some(child),
            status: MonitorStatus::Running,
            pid,
            started_at_ms: now_ms,
            timed_out: false,
            shared,
            stdout_reader: Some(stdout_reader),
            stderr_reader: Some(stderr_reader),
            pump: Some(pump),
            stderr_dropped: 0,
            ready: VecDeque::new(),
        });
        Ok(MonitorHandle { id, status: MonitorStatus::Running, pid })
    }

    /// Collect ready events. Events are returned in per-monitor arrival order.
    /// `now_ms` stamps the event and drives the optional timeout; the burst
    /// window itself is measured from the first buffered line's arrival.
    ///
    /// At most `max_events_per_drain` events are returned. Any further ready
    /// events stay buffered for the next call, so a drain cap never drops a
    /// line.
    pub fn drain(&mut self, now_ms: i64) -> Vec<MonitorEvent> {
        for runtime in &mut self.monitors {
            runtime.poll_lifecycle(now_ms, self.timeout_ms);
        }
        let budget = self.max_events_per_drain;
        let mut events = Vec::new();
        for runtime in &mut self.monitors {
            while events.len() < budget {
                match runtime.next_event(self.window, now_ms) {
                    Some(event) => events.push(event),
                    None => break,
                }
            }
            if events.len() >= budget {
                break;
            }
        }
        events
    }

    /// Kill and reap one monitor, and discard its buffered stdout so nothing is
    /// emitted after an explicit stop. Idempotent.
    pub fn stop(&mut self, id: &str, _now_ms: i64) -> Result<()> {
        let runtime = self
            .monitors
            .iter_mut()
            .find(|monitor| monitor.spec.id == id)
            .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("monitor `{id}`")))?;
        runtime.terminate(true);
        Ok(())
    }

    /// Terminate and forget one monitor so its name can be started again.
    ///
    /// This is the only call that releases a name; `stop` keeps the runtime so a
    /// later start cannot silently respawn a monitor that exited. The restart
    /// policy (T-MON-04) calls this only for an explicit, confirmed restart.
    pub fn forget(&mut self, id: &str) -> Result<()> {
        let index = self
            .monitors
            .iter()
            .position(|monitor| monitor.spec.id == id)
            .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("monitor `{id}`")))?;
        self.monitors[index].terminate(true);
        self.monitors.remove(index);
        Ok(())
    }

    /// Silence one monitor (MON-14) without stopping it. While muted, stdout is
    /// still read (so the child cannot block on a full pipe) but discarded and
    /// counted; stderr continues to the log sink. Unmuting resumes events.
    pub fn mute(&mut self, id: &str, muted: bool) -> Result<()> {
        let runtime = self
            .monitors
            .iter_mut()
            .find(|monitor| monitor.spec.id == id)
            .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("monitor `{id}`")))?;
        runtime.set_muted(muted);
        Ok(())
    }
}

impl Drop for MonitorEngine {
    fn drop(&mut self) {
        for runtime in &mut self.monitors {
            runtime.terminate(true);
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_variables_are_scrubbed_but_agent_sockets_are_kept() {
        let env = scrubbed_env([
            ("OPENAI_API_KEY".to_string(), "sk-leak".to_string()),
            ("AWS_SECRET_ACCESS_KEY".to_string(), "s".to_string()),
            ("CREDENTIAL_FILE".to_string(), "c".to_string()),
            ("SSH_AUTH_SOCK".to_string(), "/tmp/agent".to_string()),
            ("GPG_AGENT_INFO".to_string(), "/tmp/gpg".to_string()),
            ("MONKEY".to_string(), "scraped by KEY".to_string()),
            ("HOME".to_string(), "/home/u".to_string()),
        ]);
        assert_eq!(env.get("SSH_AUTH_SOCK").map(String::as_str), Some("/tmp/agent"));
        assert_eq!(env.get("GPG_AGENT_INFO").map(String::as_str), Some("/tmp/gpg"));
        assert_eq!(env.get("HOME").map(String::as_str), Some("/home/u"));
        assert!(!env.contains_key("OPENAI_API_KEY"));
        assert!(!env.contains_key("AWS_SECRET_ACCESS_KEY"));
        assert!(!env.contains_key("CREDENTIAL_FILE"));
        assert!(!env.contains_key("MONKEY"), "the marker match is a substring policy");
        assert!(is_secret_variable("X-API-KEY"));
        assert!(!is_secret_variable("SSH_AUTH_SOCK"));
    }

    #[test]
    fn memory_sink_drops_the_oldest_line_and_counts_it() {
        let sink = MemoryLogSink::new(2);
        sink.log("a");
        sink.log("b");
        sink.log("c");
        assert_eq!(sink.lines(), vec!["b".to_string(), "c".to_string()]);
        assert_eq!(sink.dropped(), 1);
    }

    #[test]
    fn truncation_never_splits_a_character() {
        let text = "éééé";
        assert_eq!(text_floor_boundary(text, 3), 2);
        assert_eq!(text_floor_boundary(text, 1), 0);
        assert_eq!(text_floor_boundary(text, 8), 8);
        // The reader cap is bytes; a lossy string is cut at a boundary.
        let mut reader = std::io::Cursor::new("ééé\n".as_bytes().to_vec());
        match read_line(&mut reader, 3).unwrap() {
            ReadLine::Line { text, truncated } => {
                assert!(truncated);
                assert_eq!(text, format!("é{TRUNCATION_MARKER}"));
            }
            ReadLine::Eof => panic!("expected a line"),
        }
    }

    #[test]
    fn a_burst_window_always_makes_progress() {
        let window = BurstWindow::new(0, 0, 0);
        assert_eq!(window.max_lines, 1);
        assert_eq!(window.max_bytes, 1);
        assert_eq!(window.window_ms, 0);
    }

    #[test]
    fn a_long_line_is_cut_at_the_cap_with_a_marker() {
        let payload = format!("{}\n", "x".repeat(64));
        let mut reader = std::io::Cursor::new(payload.into_bytes());
        match read_line(&mut reader, 8).unwrap() {
            ReadLine::Line { text, truncated } => {
                assert!(truncated);
                assert_eq!(text, format!("xxxxxxxx{TRUNCATION_MARKER}"));
            }
            ReadLine::Eof => panic!("expected a line"),
        }
    }
}
