//! Monitor engine behaviour (T-MON-02, MON-06, MON-11, MON-13, MON-14).
//!
//! No network. Every test spawns this same test binary as the monitored child
//! with `ZERO_MONITOR_HELPER=1`; [`monitor_helper_process`] is a no-op unless
//! that variable is set, so a normal `cargo test` run skips it.

use std::ffi::OsStr;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use zero_agent::{
    BurstWindow, LogSink, MemoryLogSink, MonitorEngine, MonitorEvent, MonitorSpec, MonitorStatus,
    DEFAULT_LINE_CAP_BYTES, TRUNCATION_MARKER,
};

const HELPER_ENV: &str = "ZERO_MONITOR_HELPER";
const HELPER_MODE: &str = "ZERO_MONITOR_MODE";
const HELPER_SIGNAL: &str = "ZERO_MONITOR_SIGNAL";
const HELPER_TEST: &str = "monitor_helper_process";

// ---------------------------------------------------------------------------
// Child side
// ---------------------------------------------------------------------------

/// Child-side of every monitor test. Returns immediately unless the parent set
/// `ZERO_MONITOR_HELPER=1`.
#[test]
fn monitor_helper_process() {
    if std::env::var_os(HELPER_ENV).as_deref() != Some(OsStr::new("1")) {
        return;
    }
    let mode = std::env::var(HELPER_MODE).unwrap_or_default();
    let mut stdout = std::io::stdout();
    // libtest has already printed `test monitor_helper_process ... ` without a
    // newline; terminate that prefix so payload lines stay whole.
    let _ = writeln!(stdout);
    let _ = stdout.flush();

    match mode.as_str() {
        "burst" => {
            for index in 0..100 {
                let _ = writeln!(stdout, "OUT {index:03}");
            }
            let _ = stdout.flush();
            for index in 0..5 {
                eprintln!("STDERR {index}");
            }
        }
        "env" => {
            let openai = std::env::var_os("OPENAI_API_KEY").is_some();
            let ssh = std::env::var_os("SSH_AUTH_SOCK").is_some();
            let _ = writeln!(stdout, "ENV openai={} ssh={}", u8::from(openai), u8::from(ssh));
            let _ = stdout.flush();
        }
        "overlong" => {
            let _ = writeln!(stdout, "{}", "x".repeat(20_000));
            let _ = stdout.flush();
        }
        "stderrflood" => {
            for index in 0..40 {
                eprintln!("STDERR {index:02}");
            }
            let _ = writeln!(stdout, "FLOOD done");
            let _ = stdout.flush();
        }
        "mute" => {
            let signal = std::env::var(HELPER_SIGNAL).expect("mute helper needs a signal path");
            let done = format!("{signal}.done");
            wait_for_path(&signal, true);
            for index in 0..5 {
                let _ = writeln!(stdout, "MUTED {index}");
            }
            let _ = stdout.flush();
            std::fs::write(&done, b"done").expect("write the muted-burst marker");
            wait_for_path(&signal, false);
            for index in 0..5 {
                let _ = writeln!(stdout, "RESUMED {index}");
            }
            let _ = stdout.flush();
        }
        "idle" => {
            let _ = writeln!(stdout, "IDLE ready");
            let _ = stdout.flush();
            std::thread::sleep(Duration::from_millis(1_200));
        }
        "long" => {
            for index in 0..200 {
                let _ = writeln!(stdout, "TICK {index:03}");
                let _ = stdout.flush();
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        "many" => {
            for index in 0..30 {
                let _ = writeln!(stdout, "MANY {index:02}");
            }
            let _ = stdout.flush();
        }
        other => eprintln!("unknown helper mode `{other}`"),
    }
}

fn wait_for_path(path: &str, present: bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if Path::new(path).exists() == present {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("helper signal `{path}` did not become present={present}");
}

// ---------------------------------------------------------------------------
// Parent side helpers
// ---------------------------------------------------------------------------

fn helper_spec(mode: &str) -> MonitorSpec {
    let exe = std::env::current_exe().expect("current test executable");
    MonitorSpec::new("helper", "monitor-helper", exe.to_string_lossy().into_owned())
        .args(["--exact", HELPER_TEST, "--nocapture", "--test-threads=1"])
        .env(HELPER_ENV, "1")
        .env(HELPER_MODE, mode)
}

fn engine_with(sink: Arc<dyn LogSink>, window: BurstWindow) -> MonitorEngine {
    MonitorEngine::with_sink(sink).with_window(window)
}

/// Drain until the monitor is terminal, its stdout reader is at EOF, its
/// buffers are empty, and one more drain produced nothing.
fn collect_until_stopped(
    engine: &mut MonitorEngine,
    id: &str,
    timeout: Duration,
) -> (Vec<MonitorEvent>, Vec<String>) {
    let start = Instant::now();
    let mut now = 0i64;
    let mut events = Vec::new();
    loop {
        now += 5;
        let batch = engine.drain(now);
        let quiet = batch.is_empty();
        events.extend(batch);
        let terminal =
            matches!(engine.status(id), Some(MonitorStatus::Stopped | MonitorStatus::Failed));
        let settled = engine.stats(id).map(|stats| stats.eof && stats.pending_lines == 0).unwrap_or(true);
        if terminal && settled && quiet {
            break;
        }
        if start.elapsed() > timeout {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let lines = events.iter().flat_map(|event| event.lines.iter().cloned()).collect();
    (events, lines)
}

fn payload<'a>(lines: &'a [String], prefix: &str) -> Vec<&'a str> {
    lines.iter().filter_map(|line| line.strip_prefix(prefix)).collect()
}

fn wait_for_log(sink: &MemoryLogSink, count: usize, timeout: Duration) -> Vec<String> {
    let start = Instant::now();
    loop {
        let lines = sink.lines();
        if lines.len() >= count || start.elapsed() > timeout {
            return lines;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn set_var(name: &str, value: &str) {
    std::env::set_var(name, value);
}

fn restore_var(name: &str, previous: &Option<std::ffi::OsString>) {
    match previous {
        Some(value) => std::env::set_var(name, value),
        None => std::env::remove_var(name),
    }
}

// ---------------------------------------------------------------------------
// Burst (the T-MON-02 Done test)
// ---------------------------------------------------------------------------

#[test]
fn monitor_burst_of_one_hundred_lines_coalesces_without_loss() {
    let sink = Arc::new(MemoryLogSink::default());
    let mut engine = engine_with(sink.clone(), BurstWindow::new(200, 64 * 1024, 25));
    let handle = engine.start(helper_spec("burst"), 0).expect("start burst helper");

    let (events, lines) =
        collect_until_stopped(&mut engine, &handle.id, Duration::from_secs(15));

    let out = payload(&lines, "OUT ");
    assert_eq!(out.len(), 100, "every stdout line appears exactly once");
    for (index, value) in out.iter().enumerate() {
        assert_eq!(*value, format!("{index:03}"), "arrival order is preserved");
    }
    assert!(
        events.len() < 25,
        "100 lines in a few milliseconds must coalesce: got {} events",
        events.len()
    );
    assert!(events.iter().all(|event| event.line_count == event.lines.len()));
    assert_eq!(
        events.iter().map(|event| event.line_count).sum::<usize>(),
        lines.len(),
        "the event line counts account for every delivered line"
    );
    assert!(!lines.iter().any(|line| line.contains("STDERR")));
    let mut unique = out.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), out.len(), "a stdout line was delivered more than once");

    let logged = wait_for_log(&sink, 5, Duration::from_secs(5));
    for index in 0..5 {
        assert!(
            logged.iter().any(|line| line == &format!("STDERR {index}")),
            "stderr line {index} reaches the log sink only"
        );
    }
    let stats = engine.stats(&handle.id).unwrap();
    assert!(stats.stderr_lines >= 5);
    assert!(stats.stdout_lines as usize >= lines.len());
    assert_eq!(engine.status(&handle.id), Some(MonitorStatus::Stopped));
}

// ---------------------------------------------------------------------------
// Environment scrub
// ---------------------------------------------------------------------------

#[test]
fn monitor_environment_is_scrubbed_for_secret_markers() {
    let previous_openai = std::env::var_os("OPENAI_API_KEY");
    let previous_ssh = std::env::var_os("SSH_AUTH_SOCK");
    set_var("OPENAI_API_KEY", "sk-monitor-test-must-not-leak");
    set_var("SSH_AUTH_SOCK", "/tmp/zero-monitor-agent.sock");

    let sink = Arc::new(MemoryLogSink::default());
    let mut engine = engine_with(sink, BurstWindow::new(100, 1 << 20, 20));
    let handle = engine.start(helper_spec("env"), 0).expect("start env helper");
    let (_events, lines) =
        collect_until_stopped(&mut engine, &handle.id, Duration::from_secs(10));

    restore_var("OPENAI_API_KEY", &previous_openai);
    restore_var("SSH_AUTH_SOCK", &previous_ssh);

    let report = lines.iter().find(|line| line.starts_with("ENV ")).expect("env report line");
    assert_eq!(
        report, "ENV openai=0 ssh=1",
        "a marked variable is removed and the agent socket is exempt"
    );
}

// ---------------------------------------------------------------------------
// Mute
// ---------------------------------------------------------------------------

#[test]
fn monitor_mute_drops_output_and_unmute_resumes() {
    let dir = tempfile::tempdir().unwrap();
    let signal = dir.path().join("go");
    let done = dir.path().join("go.done");
    let signal_text = signal.to_string_lossy().into_owned();

    let sink = Arc::new(MemoryLogSink::default());
    let mut engine = engine_with(sink, BurstWindow::new(50, 1 << 20, 15));
    let spec = helper_spec("mute").env(HELPER_SIGNAL, signal_text);
    let handle = engine.start(spec, 0).expect("start mute helper");
    engine.mute(&handle.id, true).expect("mute");

    std::fs::write(&signal, b"go").expect("raise the helper signal");
    let start = Instant::now();
    while !done.exists() {
        assert!(start.elapsed() < Duration::from_secs(10), "helper never printed its muted burst");
        std::thread::sleep(Duration::from_millis(5));
    }

    let mut now = 100i64;
    let mut leaked = Vec::new();
    for _ in 0..5 {
        now += 20;
        leaked.extend(engine.drain(now));
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(leaked.is_empty(), "a muted monitor emitted {leaked:?}");

    std::fs::remove_file(&signal).expect("lower the helper signal");
    engine.mute(&handle.id, false).expect("unmute");
    let (_events, lines) =
        collect_until_stopped(&mut engine, &handle.id, Duration::from_secs(10));

    assert_eq!(payload(&lines, "RESUMED ").len(), 5, "unmute resumes the stream");
    assert!(payload(&lines, "MUTED ").is_empty(), "muted lines never surface");
    let stats = engine.stats(&handle.id).unwrap();
    assert!(stats.dropped_on_mute >= 5, "muted lines are counted, not silently lost");
    assert!(stats.stdout_lines >= 7, "the monitor kept reading while muted");
}

// ---------------------------------------------------------------------------
// Stop
// ---------------------------------------------------------------------------

#[test]
fn monitor_stop_kills_reaps_and_silences() {
    let sink = Arc::new(MemoryLogSink::default());
    let mut engine = engine_with(sink, BurstWindow::new(50, 1 << 20, 15));
    let handle = engine.start(helper_spec("long"), 0).expect("start long helper");

    let start = Instant::now();
    let mut now = 0i64;
    let mut events: Vec<MonitorEvent> = Vec::new();
    while events
        .iter()
        .flat_map(|event| event.lines.iter())
        .filter(|line| line.starts_with("TICK "))
        .count()
        < 3
    {
        now += 5;
        events.extend(engine.drain(now));
        assert!(start.elapsed() < Duration::from_secs(10), "the helper produced no ticks");
        std::thread::sleep(Duration::from_millis(5));
    }
    let delivered_before_stop = events.iter().map(|event| event.line_count).sum::<usize>();
    assert!(delivered_before_stop > 0);

    engine.stop(&handle.id, now).expect("stop");
    assert_eq!(engine.status(&handle.id), Some(MonitorStatus::Stopped));

    let mut after = Vec::new();
    for _ in 0..20 {
        now += 10;
        after.extend(engine.drain(now));
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(after.is_empty(), "no event is emitted after an explicit stop: {after:?}");
    let stats = engine.stats(&handle.id).unwrap();
    assert_eq!(stats.pending_lines, 0);
    assert!(stats.eof, "the stopped helper's readers reached EOF");
}

// ---------------------------------------------------------------------------
// Caps
// ---------------------------------------------------------------------------

#[test]
fn monitor_overlong_line_is_truncated_with_a_marker() {
    let sink = Arc::new(MemoryLogSink::default());
    let mut engine = engine_with(sink, BurstWindow::new(64, 1 << 20, 20));
    let handle = engine.start(helper_spec("overlong"), 0).expect("start overlong helper");
    let (_events, lines) =
        collect_until_stopped(&mut engine, &handle.id, Duration::from_secs(10));

    let long = lines.iter().find(|line| line.starts_with("xxxx")).expect("the long line");
    assert!(long.ends_with(TRUNCATION_MARKER), "the cap is marked: {:?}", &long[long.len() - 40..]);
    assert!(
        long.len() <= DEFAULT_LINE_CAP_BYTES + TRUNCATION_MARKER.len(),
        "a capped line stays within the byte budget: {} bytes",
        long.len()
    );
    assert!(engine.stats(&handle.id).unwrap().truncated_lines >= 1);
}

#[test]
fn monitor_stalled_sink_drops_the_oldest_stderr_with_a_counter() {
    let sink = Arc::new(StallingSink::default());
    let mut engine = MonitorEngine::with_sink(sink.clone())
        .with_window(BurstWindow::new(64, 1 << 20, 20))
        .with_stderr_queue(2);
    let handle = engine.start(helper_spec("stderrflood"), 0).expect("start stderr helper");
    let (events, lines) =
        collect_until_stopped(&mut engine, &handle.id, Duration::from_secs(10));

    assert!(lines.iter().any(|line| line.contains("FLOOD done")));
    let wait = Instant::now();
    let stats = loop {
        let stats = engine.stats(&handle.id).unwrap();
        if stats.stderr_lines >= 40 || wait.elapsed() > Duration::from_secs(10) {
            break stats;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert!(stats.stderr_lines >= 40, "the reader saw every stderr line: {}", stats.stderr_lines);
    assert!(stats.stderr_dropped > 0, "a stalled sink drops the oldest with a count");
    assert!(
        !events.iter().flat_map(|event| event.lines.iter()).any(|line| line.contains("STDERR")),
        "stderr never becomes an event"
    );

    sink.release();
    engine.stop(&handle.id, 1_000).expect("stop");
}

#[test]
fn monitor_per_drain_cap_keeps_the_rest_buffered() {
    let sink = Arc::new(MemoryLogSink::default());
    let mut engine = MonitorEngine::with_sink(sink)
        .with_window(BurstWindow::new(1, 1 << 20, 0))
        .with_max_events_per_drain(2);
    let handle = engine.start(helper_spec("many"), 0).expect("start many helper");

    let start = Instant::now();
    let mut now = 0i64;
    let mut all = Vec::new();
    let mut batches = 0;
    loop {
        now += 5;
        let batch = engine.drain(now);
        assert!(batch.len() <= 2, "one drain returned {} events", batch.len());
        if !batch.is_empty() {
            batches += 1;
        }
        all.extend(batch.iter().flat_map(|event| event.lines.iter().cloned()));
        let terminal =
            matches!(engine.status(&handle.id), Some(MonitorStatus::Stopped | MonitorStatus::Failed));
        let settled = engine
            .stats(&handle.id)
            .map(|stats| stats.eof && stats.pending_lines == 0)
            .unwrap_or(true);
        if terminal && settled && batch.is_empty() {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(10), "the drain cap stalled progress");
        std::thread::sleep(Duration::from_millis(2));
    }

    let many = payload(&all, "MANY ");
    assert_eq!(many.len(), 30, "a per-drain cap keeps the rest buffered");
    for (index, value) in many.iter().enumerate() {
        assert_eq!(*value, format!("{index:02}"));
    }
    assert!(batches >= 15, "the 30 events needed at least 15 two-event drains");
}

// ---------------------------------------------------------------------------
// Idle and timeout
// ---------------------------------------------------------------------------

#[test]
fn monitor_idle_emits_nothing() {
    let sink = Arc::new(MemoryLogSink::default());
    let mut engine = engine_with(sink, BurstWindow::new(50, 1 << 20, 15));
    let handle = engine.start(helper_spec("idle"), 0).expect("start idle helper");

    let start = Instant::now();
    let mut now = 0i64;
    let mut ready = false;
    while !ready {
        now += 5;
        for event in engine.drain(now) {
            ready |= event.lines.iter().any(|line| line == "IDLE ready");
        }
        assert!(start.elapsed() < Duration::from_secs(10), "the idle helper never reported ready");
        std::thread::sleep(Duration::from_millis(5));
    }

    for _ in 0..30 {
        now += 10;
        let events = engine.drain(now);
        assert!(events.is_empty(), "an idle monitor emits no events, got {events:?}");
        std::thread::sleep(Duration::from_millis(5));
    }

    engine.stop(&handle.id, now).expect("stop the idle helper");
    assert_eq!(engine.status(&handle.id), Some(MonitorStatus::Stopped));
    assert_eq!(engine.stats(&handle.id).unwrap().pending_lines, 0);
}

#[test]
fn monitor_timeout_kills_reaps_and_flushes_once() {
    let sink = Arc::new(MemoryLogSink::default());
    let mut engine = MonitorEngine::with_sink(sink)
        .with_window(BurstWindow::new(64, 1 << 20, 20))
        .with_timeout_ms(Some(250));
    let handle = engine.start(helper_spec("long"), 0).expect("start long helper");

    // Collect the first tick with the timeout clock stopped, then advance it
    // past the budget. This keeps process-startup latency out of the timeout.
    let start = Instant::now();
    let mut events: Vec<MonitorEvent> = Vec::new();
    let mut ticks = 0usize;
    while ticks == 0 {
        events.extend(engine.drain(0));
        ticks = events
            .iter()
            .flat_map(|event| event.lines.iter())
            .filter(|line| line.starts_with("TICK "))
            .count();
        assert!(start.elapsed() < Duration::from_secs(10), "the helper produced no ticks");
        std::thread::sleep(Duration::from_millis(5));
    }

    let mut now = 0i64;
    while engine.status(&handle.id) == Some(MonitorStatus::Running) {
        now = 300 + start.elapsed().as_millis() as i64;
        events.extend(engine.drain(now));
        assert!(start.elapsed() < Duration::from_secs(10), "the timeout never fired");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(engine.status(&handle.id), Some(MonitorStatus::Failed));
    let stats = engine.stats(&handle.id).unwrap();
    assert!(stats.timed_out, "the failure is attributed to the timeout");

    for _ in 0..40 {
        now += 25;
        let batch = engine.drain(now);
        let quiet = batch.is_empty();
        events.extend(batch);
        if quiet && engine.stats(&handle.id).unwrap().pending_lines == 0 {
            break;
        }
    }
    let ticks: Vec<&str> = events
        .iter()
        .flat_map(|event| event.lines.iter())
        .filter(|line| line.starts_with("TICK "))
        .map(String::as_str)
        .collect();
    assert!(!ticks.is_empty(), "final buffered stdout is emitted once");
    let mut sorted = ticks.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), ticks.len(), "the timeout flush does not repeat a line");

    engine.stop(&handle.id, now).expect("stop");
}

// ---------------------------------------------------------------------------
// A sink that never returns until released
// ---------------------------------------------------------------------------

#[derive(Default)]
struct StallingSink {
    released: Mutex<bool>,
    ready: Condvar,
}

impl StallingSink {
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.ready.notify_all();
    }
}

impl LogSink for StallingSink {
    fn log(&self, _line: &str) {
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.ready.wait(released).unwrap();
        }
    }
}
