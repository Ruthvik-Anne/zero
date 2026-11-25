//! Build tooling: traceability, architecture, docs index, protocol fixtures, and
//! the benchmark gate. Runs in CI and locally without extra dependencies.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

/// Deterministic heap probe used by the memory dimension (TST-07).
///
/// The gate runs on Windows locally and on Linux in CI, and RSS is not read the
/// same way on both. A counting global allocator measures peak live heap bytes
/// inside this process instead: it needs no dependency, works on every host, and
/// is deterministic for a fixed workload. It is a proxy for resident memory, not
/// a replacement for an OS RSS reading.
mod alloc_probe {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CURRENT: AtomicUsize = AtomicUsize::new(0);
    static PEAK: AtomicUsize = AtomicUsize::new(0);

    pub struct Counting;

    fn grow(bytes: usize) {
        let live = CURRENT.fetch_add(bytes, Ordering::Relaxed) + bytes;
        PEAK.fetch_max(live, Ordering::Relaxed);
    }

    fn shrink(bytes: usize) {
        CURRENT.fetch_sub(bytes, Ordering::Relaxed);
    }

    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let ptr = System.alloc(layout);
            if !ptr.is_null() {
                grow(layout.size());
            }
            ptr
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            let ptr = System.alloc_zeroed(layout);
            if !ptr.is_null() {
                grow(layout.size());
            }
            ptr
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            System.dealloc(ptr, layout);
            shrink(layout.size());
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let new_ptr = System.realloc(ptr, layout, new_size);
            if !new_ptr.is_null() {
                if new_size >= layout.size() {
                    grow(new_size - layout.size());
                } else {
                    shrink(layout.size() - new_size);
                }
            }
            new_ptr
        }
    }

    /// Reset the peak watermark to the live heap so one sample starts clean.
    pub fn reset_peak() {
        PEAK.store(CURRENT.load(Ordering::Relaxed), Ordering::Relaxed);
    }

    /// Peak live heap bytes observed since the last [`reset_peak`].
    pub fn peak_bytes() -> usize {
        PEAK.load(Ordering::Relaxed)
    }
}

#[global_allocator]
static GLOBAL_ALLOC: alloc_probe::Counting = alloc_probe::Counting;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "help".into());
    let rest: Vec<String> = args.collect();
    match cmd.as_str() {
        "check-traceability" => check_traceability(&rest),
        "check-arch" => check_arch(&rest),
        "check-docs" => check_docs(&rest),
        "check-parity" => check_parity(&rest),
        "parity-doc" => parity_doc(&rest),
        "docs-index" => docs_index(&rest),
        "errors-doc" => errors_doc(&rest),
        "paths-doc" => paths_doc(&rest),
        "protocol-fixtures" => protocol_fixtures(&rest),
        "bench" => bench(&rest),
        "help" | "--help" | "-h" => {
            print_help();
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("unknown xtask command `{other}`");
            print_help();
            ExitCode::from(2)
        }
    }
}

fn print_help() {
    println!(
        "xtask commands:
  check-traceability [--root DIR]   fail when requirements and tasks disagree
  check-arch [--root DIR]           fail on an upward crate edge or cycle
  check-docs [--root DIR]           run both checks
  check-parity [--root DIR]         fail when a Part 1/2/8 item has no assessed row
  parity-doc [--write]              render docs/parity.md from the parity data
  docs-index [--write]              render docs/requirements-index.md
  errors-doc [--write]              render docs/errors.md from the error enum
  paths-doc [--write]               render docs/data-directories.md from the table
  protocol-fixtures [--write]       write protocol/golden fixtures
  bench [--check|--record]          run startup/frame/attach/memory/session benchmarks"
    );
}

fn root(args: &[String]) -> PathBuf {
    let mut root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--root" && i + 1 < args.len() {
            root = PathBuf::from(&args[i + 1]);
            i += 1;
        }
        i += 1;
    }
    root
}

fn check_traceability(args: &[String]) -> ExitCode {
    let root = root(args);
    let features = match std::fs::read_to_string(root.join("features.md")) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("cannot read features.md: {e}");
            return ExitCode::FAILURE;
        }
    };
    let tasks = match std::fs::read_to_string(root.join("tasks.md")) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("cannot read tasks.md: {e}");
            return ExitCode::FAILURE;
        }
    };
    let report = zero_arch::check(&features, &tasks);
    println!(
        "traceability: {} requirements, {} tasks, {} areas",
        report.requirements,
        report.tasks,
        report.areas.len()
    );
    if !report.ok() {
        for e in report.errors() {
            eprintln!("FAIL {e}");
        }
        return ExitCode::FAILURE;
    }
    println!("traceability: OK");
    ExitCode::SUCCESS
}

fn check_arch(args: &[String]) -> ExitCode {
    let root = root(args);
    let report = zero_arch::check_workspace(&root);
    println!("architecture: {} crates, {} edges", report.crates.len(), report.edges.len());
    if !report.violations.is_empty() {
        for v in &report.violations {
            eprintln!("FAIL {v}");
        }
        return ExitCode::FAILURE;
    }
    println!("architecture: OK");
    ExitCode::SUCCESS
}

fn check_docs(args: &[String]) -> ExitCode {
    let t = check_traceability(args);
    if t != ExitCode::SUCCESS {
        return t;
    }
    check_arch(args)
}

fn parity_data_path(root: &Path) -> PathBuf {
    root.join("crates").join("zero-arch").join("data").join("parity.json")
}

fn load_parity_report(root: &Path) -> Result<zero_arch::parity::ParityReport, String> {
    let features = std::fs::read_to_string(root.join("features.md"))
        .map_err(|e| format!("cannot read features.md: {e}"))?;
    let data_path = parity_data_path(root);
    let data = std::fs::read_to_string(&data_path)
        .map_err(|e| format!("cannot read {}: {e}", data_path.display()))?;
    Ok(zero_arch::parity::check(&features, &data))
}

fn print_parity_summary(report: &zero_arch::parity::ParityReport) {
    use zero_arch::parity::State;
    println!(
        "parity: {} items ({} implemented, {} partial, {} deferred, {} out of scope, {} unassessed)",
        report.items,
        report.state_count(State::Implemented),
        report.state_count(State::Partial),
        report.state_count(State::Deferred),
        report.state_count(State::OutOfScope),
        report.state_count(State::Unassessed)
    );
}

fn check_parity(args: &[String]) -> ExitCode {
    let root = root(args);
    let report = match load_parity_report(&root) {
        Ok(report) => report,
        Err(e) => {
            eprintln!("FAIL {e}");
            return ExitCode::FAILURE;
        }
    };
    print_parity_summary(&report);
    if !report.ok {
        for e in &report.errors {
            eprintln!("FAIL {e}");
        }
        return ExitCode::FAILURE;
    }
    println!("parity: OK");
    ExitCode::SUCCESS
}

fn parity_doc(args: &[String]) -> ExitCode {
    let root = root(args);
    let report = match load_parity_report(&root) {
        Ok(report) => report,
        Err(e) => {
            eprintln!("FAIL {e}");
            return ExitCode::FAILURE;
        }
    };
    if !report.ok {
        for e in &report.errors {
            eprintln!("FAIL {e}");
        }
        eprintln!("refusing to render an incomplete parity audit");
        return ExitCode::FAILURE;
    }
    let out = zero_arch::parity::render_markdown(&report);
    let path = root.join("docs").join("parity.md");
    if args.iter().any(|a| a == "--write") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &out).unwrap();
        println!("wrote {} ({} items)", path.display(), report.items);
    } else {
        print!("{out}");
    }
    ExitCode::SUCCESS
}

fn docs_index(args: &[String]) -> ExitCode {
    let root = root(args);
    let features = std::fs::read_to_string(root.join("features.md")).expect("features.md");
    let tasks = std::fs::read_to_string(root.join("tasks.md")).expect("tasks.md");
    let reqs = zero_arch::parse_features(&features);
    let parsed = zero_arch::parse_tasks(&tasks);
    let areas: BTreeSet<String> = reqs.iter().map(|r| r.area.clone()).collect();
    let mut per_area: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for r in &reqs {
        per_area.entry(r.area.clone()).or_default().push(r.id.clone());
    }
    let mut out = String::new();
    out.push_str("# Requirement index\n\n");
    out.push_str("Generated by `cargo run -p xtask -- docs-index --write` from\n");
    out.push_str("`features.md` Part 10 and `tasks.md`. Every requirement area in Part 10\n");
    out.push_str("appears here; a missing area fails `xtask check-docs`.\n\n");
    out.push_str("| Area | Requirements | Tasks | Requirement IDs |\n|---|---|---|---|\n");
    for area in &areas {
        let ids = per_area.get(area).cloned().unwrap_or_default();
        let task_count = parsed
            .iter()
            .filter(|t| {
                t.refs.iter().any(|raw| {
                    let expanded = expand(raw);
                    expanded.iter().any(|id| ids.iter().any(|i| i == id))
                })
            })
            .count();
        out.push_str(&format!(
            "| `{area}` | {} | {} | {} |\n",
            ids.len(),
            task_count,
            ids.join(", ")
        ));
    }
    out.push_str(&format!(
        "\nTotals: {} requirements across {} areas, {} tasks.\n",
        reqs.len(),
        areas.len(),
        parsed.len()
    ));
    let path = root.join("docs").join("requirements-index.md");
    if args.iter().any(|a| a == "--write") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &out).unwrap();
        println!("wrote {}", path.display());
    } else {
        print!("{out}");
    }
    ExitCode::SUCCESS
}

fn expand(raw: &str) -> Vec<String> {
    let Some((a, b)) = raw.split_once("..") else {
        return vec![raw.to_string()];
    };
    let (Some((a_area, a_num)), Some((b_area, b_num))) = (split_id(a), split_id(b)) else {
        return vec![raw.to_string()];
    };
    if a_area != b_area {
        return vec![a.to_string(), b.to_string()];
    }
    let (lo, hi) = if a_num <= b_num { (a_num, b_num) } else { (b_num, a_num) };
    (lo..=hi).take(64).map(|n| format!("{a_area}-{n:02}")).collect()
}

fn split_id(s: &str) -> Option<(&str, u32)> {
    let (area, num) = s.rsplit_once('-')?;
    Some((area, num.parse().ok()?))
}

fn errors_doc(args: &[String]) -> ExitCode {
    let root = root(args);
    let mut out = String::new();
    out.push_str("# Error codes\n\n");
    out.push_str("Generated by `cargo run -p xtask -- errors-doc --write` from\n");
    out.push_str("`zero_types::ErrorCode`. Every code has exactly one remediation line.\n");
    out.push_str("A duplicate, undocumented, or stale code fails `error::tests`.\n\n");
    out.push_str("| Code | Remediation |\n|---|---|\n");
    for code in zero_types::ErrorCode::ALL {
        out.push_str(&format!("| `{}` | {} |\n", code.as_str(), code.remediation()));
    }
    let path = root.join("docs").join("errors.md");
    if args.iter().any(|a| a == "--write") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &out).unwrap();
        println!("wrote {} ({} codes)", path.display(), zero_types::ErrorCode::ALL.len());
    } else {
        print!("{out}");
    }
    ExitCode::SUCCESS
}

fn paths_doc(args: &[String]) -> ExitCode {
    let root = root(args);
    let mut out = String::new();
    out.push_str("# Data directories\n\n");
    out.push_str("Generated by `cargo run -p xtask -- paths-doc --write` from the one\n");
    out.push_str("resolution table in `zero_types::paths`. The test\n");
    out.push_str("`paths::tests::docs_table_matches_the_code` fails when this table drifts.\n\n");
    out.push_str(&zero_types::paths::render_table());
    out.push_str("\nLinux honours `XDG_DATA_HOME`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, and\n");
    out.push_str("`XDG_STATE_HOME`. Windows uses `LOCALAPPDATA` for data, cache, and state,\n");
    out.push_str("and `APPDATA` for config. macOS uses the standard `Library` locations.\n");
    let path = root.join("docs").join("data-directories.md");
    if args.iter().any(|a| a == "--write") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &out).unwrap();
        println!("wrote {}", path.display());
    } else {
        print!("{out}");
    }
    ExitCode::SUCCESS
}

fn protocol_fixtures(args: &[String]) -> ExitCode {
    let root = root(args);
    let dir = root.join("protocol").join("golden");
    std::fs::create_dir_all(&dir).unwrap();
    use zero_types::proto::{Frame, FrameKind};
    let frames = vec![
        Frame::new(FrameKind::Hello, "corr-hello", serde_json::json!({"agent":"zero","protocol":1})),
        Frame::new(
            FrameKind::Event,
            "corr-event",
            serde_json::json!({"entry":{"kind":"message","text":"hello"}}),
        )
        .with_session("sess-1")
        .with_cursor(2, 17),
        Frame::new(
            FrameKind::Command,
            "corr-command",
            serde_json::json!({"action":"session.rename","args":{"name":"demo"}}),
        )
        .with_session("sess-1")
        .with_cursor(2, 18),
        Frame::new(FrameKind::Error, "corr-error", serde_json::json!({"code":"zero.prv.auth"})),
    ];
    let mut bin = Vec::new();
    let mut json = Vec::new();
    for f in &frames {
        bin.extend_from_slice(&f.encode().unwrap());
        json.push(serde_json::to_value(f).unwrap());
    }
    // A second fixture covers the snapshot/approval/action path and chunk cursors.
    let more = vec![
        Frame::new(
            FrameKind::Attach,
            "corr-attach",
            serde_json::json!({"client":"line-mode","from":{"generation":2,"sequence":17}}),
        )
        .with_session("sess-1"),
        Frame::new(
            FrameKind::Snapshot,
            "corr-snapshot",
            serde_json::json!({"chunk":0,"total":1,"cells":"…"}),
        )
        .with_session("sess-1")
        .with_cursor(2, 17),
        Frame::new(
            FrameKind::Approval,
            "corr-approval",
            serde_json::json!({"approval":"ap-1","action":"fs.write","hash":"abc"}),
        ),
        Frame::new(
            FrameKind::Action,
            "corr-action",
            serde_json::json!({"id":"mode.set","surface":"tui"}),
        ),
    ];
    let mut bin2 = Vec::new();
    let mut json2 = Vec::new();
    for f in &more {
        bin2.extend_from_slice(&f.encode().unwrap());
        json2.push(serde_json::to_value(f).unwrap());
    }
    if args.iter().any(|a| a == "--write") {
        std::fs::write(dir.join("v1-frames.bin"), &bin).unwrap();
        std::fs::write(dir.join("v1-frames.json"), serde_json::to_vec_pretty(&json).unwrap()).unwrap();
        std::fs::write(dir.join("v1-stream.bin"), &bin2).unwrap();
        std::fs::write(dir.join("v1-stream.json"), serde_json::to_vec_pretty(&json2).unwrap()).unwrap();
        println!("wrote {} bytes of golden frames to {}", bin.len() + bin2.len(), dir.display());
    } else {
        println!("{} frames, {} bytes (use --write)", frames.len() + more.len(), bin.len() + bin2.len());
    }
    ExitCode::SUCCESS
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
struct Baselines {
    startup_ms: f64,
    frame_us: f64,
    attach_ms: f64,
    memory_mb: f64,
    session_bytes_1k: f64,
    tolerance: f64,
}

impl Baselines {
    /// Recorded dimensions in a fixed order; names line up with
    /// [`Measurements::values`].
    fn values(&self) -> [(&'static str, f64); 5] {
        [
            ("startup_ms", self.startup_ms),
            ("frame_us", self.frame_us),
            ("attach_ms", self.attach_ms),
            ("memory_mb", self.memory_mb),
            ("session_bytes_1k", self.session_bytes_1k),
        ]
    }
}

#[derive(Debug, Clone, Copy)]
struct Measurements {
    startup_ms: f64,
    frame_us: f64,
    attach_ms: f64,
    memory_mb: f64,
    session_bytes_1k: f64,
}

impl Measurements {
    fn values(&self) -> [(&'static str, f64); 5] {
        [
            ("startup_ms", self.startup_ms),
            ("frame_us", self.frame_us),
            ("attach_ms", self.attach_ms),
            ("memory_mb", self.memory_mb),
            ("session_bytes_1k", self.session_bytes_1k),
        ]
    }
}

/// Every dimension whose measured value exceeds `baseline * tolerance`.
fn regressions(baselines: &Baselines, measured: &Measurements) -> Vec<String> {
    let mut failed = Vec::new();
    for ((name, baseline), (measured_name, value)) in
        baselines.values().into_iter().zip(measured.values())
    {
        debug_assert_eq!(name, measured_name);
        let limit = baseline * baselines.tolerance;
        if value > limit {
            failed.push(format!("{name}: {value:.2} > {limit:.2} (baseline {baseline:.2})"));
        }
    }
    failed
}

/// Entries in the representative session used for the session-size budget.
const SESSION_ENTRIES: usize = 1_000;
/// Entries scanned for the peak-heap memory proxy.
const MEMORY_ENTRIES: usize = 20_000;

fn bench(args: &[String]) -> ExitCode {
    let root = root(args);
    let check = args.iter().any(|a| a == "--check");
    let record = args.iter().any(|a| a == "--record");

    let measured = Measurements {
        startup_ms: measure_startup(&root),
        frame_us: measure_frame(),
        attach_ms: measure_attach(),
        memory_mb: measure_memory_mb(MEMORY_ENTRIES),
        session_bytes_1k: measure_session_bytes_1k(SESSION_ENTRIES),
    };
    println!(
        "startup_ms={:.2} frame_us={:.2} attach_ms={:.2} memory_mb={:.2} session_bytes_1k={:.0}",
        measured.startup_ms,
        measured.frame_us,
        measured.attach_ms,
        measured.memory_mb,
        measured.session_bytes_1k
    );

    let path = root.join("bench").join("baselines.json");
    if record {
        let baselines = Baselines {
            // Timings are noisy, so the recorded budget keeps the existing 1.5x
            // headroom. The memory proxy and session size are deterministic, so
            // they are recorded at the measured value.
            startup_ms: measured.startup_ms * 1.5,
            frame_us: measured.frame_us * 1.5,
            attach_ms: measured.attach_ms * 1.5,
            memory_mb: measured.memory_mb,
            session_bytes_1k: measured.session_bytes_1k,
            tolerance: 4.0,
        };
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_vec_pretty(&baselines).unwrap()).unwrap();
        println!("recorded baselines to {}", path.display());
        return ExitCode::SUCCESS;
    }
    if !check {
        return ExitCode::SUCCESS;
    }
    let text = match std::fs::read_to_string(&path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FAIL cannot read {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let baselines: Baselines = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FAIL cannot parse {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let failed = regressions(&baselines, &measured);
    if failed.is_empty() {
        println!("benchmarks: OK against {}", path.display());
        ExitCode::SUCCESS
    } else {
        for f in failed {
            eprintln!("FAIL regression {f}");
        }
        ExitCode::FAILURE
    }
}

fn measure_startup(root: &Path) -> f64 {
    let exe = root.join("target").join("debug").join(if cfg!(windows) { "zero.exe" } else { "zero" });
    if !exe.exists() {
        println!("note: {} not built; startup measured as 0", exe.display());
        return 0.0;
    }
    // Warm-up: the first launch after a build pays for cold file cache and
    // scanner hooks, which is not a regression in Zero.
    let _ = std::process::Command::new(&exe).arg("--version").stdout(std::process::Stdio::null()).status();
    let mut samples = Vec::new();
    for _ in 0..9 {
        let start = Instant::now();
        let status = std::process::Command::new(&exe)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .status();
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        if status.map(|s| s.success()).unwrap_or(false) {
            samples.push(elapsed);
        }
    }
    median(&mut samples)
}

fn measure_frame() -> f64 {
    use zero_tui::Terminal;
    for _ in 0..50 {
        std::hint::black_box(zero_tui::Terminal::new(120, 40).text());
    }
    let mut samples = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        for _ in 0..500 {
            let mut t = Terminal::new(120, 40);
            t.feed("\u{1b}[2J\u{1b}[H");
            for row in 0..38 {
                t.feed(&format!("\u{1b}[{};1H\u{1b}[38;5;{}m│ message {row} … streaming tail", row + 1, 30 + row % 8));
            }
            t.feed("\u{1b}[40;1H\u{1b}[1;36msemi-auto\u{1b}[0m · model · budget");
            std::hint::black_box(t.text());
        }
        samples.push(start.elapsed().as_secs_f64() * 1_000_000.0 / 500.0);
    }
    median(&mut samples)
}

fn measure_attach() -> f64 {
    use zero_store::jsonl::{scan, Event, JsonlWriter};
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return 0.0,
    };
    let path = dir.path().join("attach.jsonl");
    let mut w = JsonlWriter::open(&path).unwrap();
    for i in 0..50_000u64 {
        w.append(&Event {
            seq: i,
            ts: i as i64,
            kind: "attach".into(),
            payload: serde_json::json!({"i": i}),
        })
        .unwrap();
    }
    std::hint::black_box(scan(&path).unwrap());
    let mut samples = Vec::new();
    for _ in 0..3 {
        let start = Instant::now();
        let report = scan(&path).unwrap();
        std::hint::black_box(&report);
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    median(&mut samples)
}

/// One representative session entry: the normalised event envelope with a
/// message-shaped payload, so the fixture resembles a real transcript line.
fn sample_event(seq: u64) -> zero_store::jsonl::Event {
    zero_store::jsonl::Event {
        seq,
        ts: 1_700_000_000_000 + seq as i64,
        kind: "message".into(),
        payload: serde_json::json!({
            "role": "assistant",
            "text": "streaming assistant message chunk for the representative session fixture",
            "tokens": 42,
            "entries": 7,
        }),
    }
}

/// Serialize `entries` sample records as JSONL: one event envelope per line.
fn serialize_session(entries: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for seq in 0..entries as u64 {
        out.extend_from_slice(&serde_json::to_vec(&sample_event(seq)).unwrap());
        out.push(b'\n');
    }
    out
}

fn write_session_file(path: &Path, entries: usize) -> std::io::Result<u64> {
    let bytes = serialize_session(entries);
    std::fs::write(path, &bytes)?;
    Ok(bytes.len() as u64)
}

/// Serialized session size in bytes for every 1,000 entries. Deterministic:
/// the same fixture and serializer always produce the same byte count.
fn measure_session_bytes_1k(entries: usize) -> f64 {
    if entries == 0 {
        return 0.0;
    }
    serialize_session(entries).len() as f64 * 1_000.0 / entries as f64
}

/// Peak live heap in MiB while a representative session file is scanned.
///
/// RSS is not portable (and needs a dependency to read on Windows), so the gate
/// records a deterministic allocation proxy instead: the largest live heap the
/// process holds during a harness run that loads `entries` records. The counting
/// allocator installed above covers the record vector, line buffers, and JSON
/// value allocations; the median of three samples removes a one-off outlier.
fn measure_memory_mb(entries: usize) -> f64 {
    use zero_store::jsonl::scan;
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return 0.0,
    };
    let path = dir.path().join("memory.jsonl");
    if write_session_file(&path, entries).is_err() {
        return 0.0;
    }
    // Warm-up: page in the file and grow any reusable allocations first.
    std::hint::black_box(scan(&path).unwrap());
    let mut samples = Vec::new();
    for _ in 0..3 {
        alloc_probe::reset_peak();
        let report = scan(&path).unwrap();
        std::hint::black_box(&report);
        samples.push(alloc_probe::peak_bytes() as f64 / (1024.0 * 1024.0));
        drop(report);
    }
    median(&mut samples)
}

fn median(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    values[values.len() / 2]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baselines() -> Baselines {
        Baselines {
            startup_ms: 100.0,
            frame_us: 1_000.0,
            attach_ms: 500.0,
            memory_mb: 40.0,
            session_bytes_1k: 200_000.0,
            tolerance: 4.0,
        }
    }

    fn within_budget() -> Measurements {
        Measurements {
            startup_ms: 110.0,
            frame_us: 1_100.0,
            attach_ms: 550.0,
            memory_mb: 45.0,
            session_bytes_1k: 210_000.0,
        }
    }

    #[test]
    fn measurements_within_budget_pass() {
        assert!(regressions(&baselines(), &within_budget()).is_empty());
    }

    #[test]
    fn a_synthetic_over_budget_memory_value_fails() {
        let baselines = baselines();
        let mut measured = within_budget();
        measured.memory_mb = baselines.memory_mb * baselines.tolerance + 0.1;
        let failed = regressions(&baselines, &measured);
        assert_eq!(failed.len(), 1);
        assert!(failed[0].starts_with("memory_mb:"));
    }

    #[test]
    fn a_synthetic_over_budget_session_size_value_fails() {
        let baselines = baselines();
        let mut measured = within_budget();
        measured.session_bytes_1k = baselines.session_bytes_1k * baselines.tolerance + 1.0;
        let failed = regressions(&baselines, &measured);
        assert_eq!(failed.len(), 1);
        assert!(failed[0].starts_with("session_bytes_1k:"));
    }

    #[test]
    fn the_limit_is_exclusive() {
        let baselines = baselines();
        let mut measured = within_budget();
        measured.memory_mb = baselines.memory_mb * baselines.tolerance;
        assert!(regressions(&baselines, &measured).is_empty());
        measured.memory_mb = baselines.memory_mb * baselines.tolerance + 0.001;
        assert_eq!(regressions(&baselines, &measured).len(), 1);
    }

    #[test]
    fn every_budgeted_dimension_is_checked() {
        let baselines = baselines();
        let mut measured = within_budget();
        measured.startup_ms = baselines.startup_ms * baselines.tolerance + 1.0;
        measured.frame_us = baselines.frame_us * baselines.tolerance + 1.0;
        measured.attach_ms = baselines.attach_ms * baselines.tolerance + 1.0;
        measured.memory_mb = baselines.memory_mb * baselines.tolerance + 1.0;
        measured.session_bytes_1k = baselines.session_bytes_1k * baselines.tolerance + 1.0;
        assert_eq!(regressions(&baselines, &measured).len(), 5);
    }

    #[test]
    fn session_size_is_deterministic_and_per_thousand() {
        let one_k = measure_session_bytes_1k(SESSION_ENTRIES);
        assert_eq!(one_k, serialize_session(SESSION_ENTRIES).len() as f64);
        assert_eq!(one_k, measure_session_bytes_1k(SESSION_ENTRIES));
        assert!(one_k > 0.0);

        // Adding entries does not change the per-1,000-entry size materially.
        let two_k = measure_session_bytes_1k(2 * SESSION_ENTRIES);
        assert!((two_k - one_k).abs() / one_k < 0.05);
        assert_eq!(measure_session_bytes_1k(0), 0.0);
    }

    #[test]
    fn session_file_round_trips_through_the_event_scanner() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.jsonl");
        let bytes = write_session_file(&path, 25).unwrap();
        assert_eq!(bytes, std::fs::metadata(&path).unwrap().len());
        let report = zero_store::jsonl::scan(&path).unwrap();
        assert_eq!(report.records.len(), 25);
        assert_eq!(report.torn_tail_bytes, 0);
        assert_eq!(report.records[24], sample_event(24));
    }

    #[test]
    fn memory_probe_reports_a_positive_peak() {
        let mb = measure_memory_mb(500);
        assert!(mb > 0.0, "peak live heap was {mb} MiB");
    }

    #[test]
    fn baselines_file_has_every_dimension() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("bench")
            .join("baselines.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        for key in [
            "startup_ms",
            "frame_us",
            "attach_ms",
            "memory_mb",
            "session_bytes_1k",
            "tolerance",
        ] {
            let n = value
                .get(key)
                .and_then(|v| v.as_f64())
                .unwrap_or_else(|| panic!("{key} is missing or not a number"));
            assert!(n >= 0.0, "{key} is negative");
        }
        let baselines: Baselines = serde_json::from_str(&text).unwrap();
        assert!(baselines.tolerance >= 1.0);
        assert!(baselines.memory_mb > 0.0);
        assert!(baselines.session_bytes_1k > 0.0);
    }
}
