//! Held-out evaluation suite (SI-01, SI-05, SI-10; T-SI-01).
//!
//! A self-improvement candidate is measured on tasks it has never seen. The
//! suite is a versioned document of tasks; each task is a prompt, a fixture
//! (relative file contents to seed a fresh workspace with), and a list of
//! checks that only the trusted evaluator may read.
//!
//! # Visibility split (SI-05)
//!
//! [`EvalSuite`] holds the scoring key in [`EvalTask::checks`]. The candidate
//! runner is handed [`public_view`], which is a [`PublicSuite`] of
//! [`PublicTask`] values. `PublicTask` has no `checks` field at all: the key is
//! excluded by the type, not by a runtime filter, so a serialized public view
//! cannot leak an expected string. [`run_suite`] builds the public view itself
//! and never passes the suite to the runner.
//!
//! # Trust root (SI-05)
//!
//! [`load_suite`] canonicalizes both the suite and the caller's trusted root
//! and refuses a suite outside that root or reachable through a symlink. A
//! candidate that can write files cannot replace the holdout it is measured
//! on.
//!
//! # Offline (SI-01, FND-13)
//!
//! The module performs no socket I/O and holds no provider or router. A runner
//! is any implementation of [`CandidateRunner`]; the tests in this file assert
//! the module source never names a network API, and [`run_suite`] writes only
//! under the caller's scratch root.
//!
//! # Hashing and versions (SI-05)
//!
//! [`suite_hash`] is BLAKE3 over the canonical bytes of the document. A caller
//! pins that hash out of band and calls [`verify_hash`] (or
//! [`load_suite_verified`]) so an edited suite with a stale hash is refused.
//! `schema_version` is the wire format; `suite_version` names the task set.
//! Both are covered by the hash, and an unknown schema is a typed
//! `SchemaVersion` error.
//!
//! # Reports (SI-02)
//!
//! [`EvalReport`] carries counts and per-task outcomes only. A failing check
//! records a stable label and, for file checks, the fixture path; it never
//! echoes the prompt, the expected text, or the candidate's output.
//! [`compare`] turns a baseline report plus a candidate report into
//! regressions and improvements for the loop in T-SI-02.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use zero_types::error::{ErrorCode, Result, ZeroError};
use zero_types::id::{Clock, SystemClock};

/// Wire schema of an [`EvalSuite`] document.
pub const EVAL_SUITE_SCHEMA_VERSION: u32 = 1;
/// Domain separator mixed into the canonical bytes before the document.
pub const SUITE_HASH_PREFIX: &str = "zero.eval-suite.v1";
/// Upper bound on a suite file read by [`load_suite`], in bytes.
pub const MAX_SUITE_BYTES: u64 = 1_048_576;
/// Upper bound on tasks in one suite.
pub const MAX_TASKS: usize = 256;
/// Upper bound on fixture files in one task.
pub const MAX_FILES_PER_TASK: usize = 64;
/// Upper bound on one fixture file, in bytes.
pub const MAX_FILE_BYTES: usize = 65_536;
/// Upper bound on the fixture bytes of one task, in bytes.
pub const MAX_FIXTURE_BYTES: usize = 262_144;
/// Upper bound on the fixture bytes of a whole suite, in bytes.
pub const MAX_SUITE_FIXTURE_BYTES: usize = 4_194_304;
/// Upper bound on checks in one task.
pub const MAX_CHECKS_PER_TASK: usize = 32;
/// Upper bound on a task prompt, in bytes.
pub const MAX_PROMPT_BYTES: usize = 8_192;
/// Upper bound on a task id, in bytes.
pub const MAX_ID_BYTES: usize = 64;
/// Upper bound on a suite version, in bytes.
pub const MAX_VERSION_BYTES: usize = 64;
/// Upper bound on a fixture or check path, in bytes.
pub const MAX_PATH_BYTES: usize = 512;
/// Upper bound on a needle or expected output fragment, in bytes.
pub const MAX_NEEDLE_BYTES: usize = 4_096;
/// Upper bound on a candidate file read during scoring, in bytes.
pub const MAX_CANDIDATE_FILE_BYTES: u64 = 1_048_576;

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

/// Files seeded into a fresh workspace before the runner starts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fixture {
    /// Relative path to contents. The [`BTreeMap`] keeps the order canonical.
    #[serde(default)]
    pub files: BTreeMap<String, String>,
}

/// One check applied to a candidate result.
///
/// The enum is internally tagged (`"kind": "exit_code"`), so every variant is a
/// named-field struct: serde does not support tuple variants in an internally
/// tagged enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Check {
    /// The runner's exit code must equal `code`.
    ExitCode { code: i32 },
    /// The file at `path` in the workspace must contain `needle`.
    FileContains { path: String, needle: String },
    /// The file or directory at `path` must not exist.
    FileAbsent { path: String },
    /// `stdout` must contain `text`.
    OutputContains { text: String },
}

impl Check {
    /// Stable label used in a [`FailedCheck`], never including the expected
    /// text.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ExitCode { .. } => "exit_code",
            Self::FileContains { .. } => "file_contains",
            Self::FileAbsent { .. } => "file_absent",
            Self::OutputContains { .. } => "output_contains",
        }
    }
}

/// One held-out task. `checks` is part of the scoring key and is absent from
/// [`PublicTask`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalTask {
    pub id: String,
    pub prompt: String,
    #[serde(default)]
    pub fixture: Fixture,
    #[serde(default)]
    pub checks: Vec<Check>,
}

/// A versioned held-out suite. Only the trusted evaluator holds this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalSuite {
    pub schema_version: u32,
    pub suite_version: String,
    pub created_ms: i64,
    pub tasks: Vec<EvalTask>,
}

impl EvalSuite {
    /// Canonical bytes hashed by [`suite_hash`].
    ///
    /// The document has no floating-point values and fixture files live in a
    /// [`BTreeMap`], so the compact JSON projection is stable for equal
    /// values. The versioned domain separator prevents a hash of another
    /// document type being accepted as a suite hash.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(SUITE_HASH_PREFIX.as_bytes());
        bytes.push(b'\n');
        bytes.extend_from_slice(
            &serde_json::to_vec(self).expect("an eval suite has no unserializable value"),
        );
        bytes
    }
}

/// BLAKE3 over [`EvalSuite::canonical_bytes`], lowercase hex.
pub fn suite_hash(suite: &EvalSuite) -> String {
    blake3::hash(&suite.canonical_bytes()).to_hex().to_string()
}

/// Check a pinned hash against the suite. A stale hash is a typed
/// `TamperDetected`; a malformed hash is `InvalidInput`.
pub fn verify_hash(suite: &EvalSuite, expected: &str) -> Result<()> {
    let expected = expected.trim();
    if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid(
            "a pinned eval suite hash is 64 hexadecimal characters",
        ));
    }
    if suite_hash(suite) != expected.to_ascii_lowercase() {
        return Err(ZeroError::new(
            ErrorCode::TamperDetected,
            "eval suite hash does not match the pinned hash",
        ));
    }
    Ok(())
}

/// Validate a suite in memory: schema, version, task ids, fixture paths and
/// sizes, and checks.
pub fn validate_suite(suite: &EvalSuite) -> Result<()> {
    if suite.schema_version != EVAL_SUITE_SCHEMA_VERSION {
        return Err(ZeroError::new(
            ErrorCode::SchemaVersion,
            format!(
                "eval suite schema version {} is not {EVAL_SUITE_SCHEMA_VERSION}",
                suite.schema_version
            ),
        ));
    }
    validate_suite_version(&suite.suite_version)?;
    if suite.tasks.is_empty() {
        return Err(invalid("eval suite has no tasks"));
    }
    if suite.tasks.len() > MAX_TASKS {
        return Err(limit(format!(
            "eval suite has {} tasks; the cap is {MAX_TASKS}",
            suite.tasks.len()
        )));
    }

    let mut ids = BTreeSet::new();
    let mut fixture_bytes = 0usize;
    for task in &suite.tasks {
        validate_task(task)?;
        if !ids.insert(task.id.as_str()) {
            return Err(invalid(format!("duplicate eval task id `{}`", task.id)));
        }
        fixture_bytes += task.fixture.files.values().map(String::len).sum::<usize>();
    }
    if fixture_bytes > MAX_SUITE_FIXTURE_BYTES {
        return Err(limit(format!(
            "eval suite fixtures total {fixture_bytes} bytes; the cap is {MAX_SUITE_FIXTURE_BYTES}"
        )));
    }
    Ok(())
}

fn validate_suite_version(version: &str) -> Result<()> {
    if version.is_empty() || version.len() > MAX_VERSION_BYTES {
        return Err(invalid(format!(
            "an eval suite version is 1..={MAX_VERSION_BYTES} bytes"
        )));
    }
    if !version
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
    {
        return Err(invalid(format!(
            "eval suite version `{version}` may contain only ASCII letters, digits, `.`, `-`, `_`, and `+`"
        )));
    }
    Ok(())
}

fn validate_task_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > MAX_ID_BYTES {
        return Err(invalid(format!(
            "an eval task id is 1..={MAX_ID_BYTES} bytes"
        )));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(invalid(format!(
            "eval task id `{id}` may contain only ASCII letters, digits, `-`, `_`, and `.`"
        )));
    }
    Ok(())
}

fn validate_task(task: &EvalTask) -> Result<()> {
    validate_task_id(&task.id)?;
    if task.prompt.trim().is_empty() {
        return Err(invalid(format!(
            "eval task `{}` has an empty prompt",
            task.id
        )));
    }
    if task.prompt.len() > MAX_PROMPT_BYTES {
        return Err(limit(format!(
            "eval task `{}` prompt is {} bytes; the cap is {MAX_PROMPT_BYTES}",
            task.id,
            task.prompt.len()
        )));
    }
    if task.fixture.files.len() > MAX_FILES_PER_TASK {
        return Err(limit(format!(
            "eval task `{}` has {} fixture files; the cap is {MAX_FILES_PER_TASK}",
            task.id,
            task.fixture.files.len()
        )));
    }

    let mut task_bytes = 0usize;
    for (path, contents) in &task.fixture.files {
        safe_relative_path(path)?;
        if contents.len() > MAX_FILE_BYTES {
            return Err(limit(format!(
                "fixture file `{path}` is {} bytes; the cap is {MAX_FILE_BYTES}",
                contents.len()
            )));
        }
        task_bytes += contents.len();
    }
    if task_bytes > MAX_FIXTURE_BYTES {
        return Err(limit(format!(
            "eval task `{}` fixtures total {task_bytes} bytes; the cap is {MAX_FIXTURE_BYTES}",
            task.id
        )));
    }

    if task.checks.is_empty() {
        return Err(invalid(format!("eval task `{}` has no checks", task.id)));
    }
    if task.checks.len() > MAX_CHECKS_PER_TASK {
        return Err(limit(format!(
            "eval task `{}` has {} checks; the cap is {MAX_CHECKS_PER_TASK}",
            task.id,
            task.checks.len()
        )));
    }
    for check in &task.checks {
        validate_check(check)?;
    }
    Ok(())
}

fn validate_check(check: &Check) -> Result<()> {
    match check {
        Check::ExitCode { .. } => Ok(()),
        Check::FileContains { path, needle } => {
            safe_relative_path(path)?;
            if needle.is_empty() {
                return Err(invalid("a file_contains check needs a non-empty needle"));
            }
            if needle.len() > MAX_NEEDLE_BYTES {
                return Err(limit(format!(
                    "a file_contains needle is {} bytes; the cap is {MAX_NEEDLE_BYTES}",
                    needle.len()
                )));
            }
            Ok(())
        }
        Check::FileAbsent { path } => safe_relative_path(path).map(|_| ()),
        Check::OutputContains { text } => {
            if text.is_empty() {
                return Err(invalid("an output_contains check needs non-empty text"));
            }
            if text.len() > MAX_NEEDLE_BYTES {
                return Err(limit(format!(
                    "an output_contains text is {} bytes; the cap is {MAX_NEEDLE_BYTES}",
                    text.len()
                )));
            }
            Ok(())
        }
    }
}

/// A relative fixture path that cannot escape the workspace.
///
/// Absolute paths, drive prefixes, `.`/`..` components, empty components, a
/// NUL byte, and over-long paths are refused. Both `/` and `\` are treated as
/// separators so a suite behaves the same on every platform.
pub fn safe_relative_path(path: &str) -> Result<PathBuf> {
    if path.is_empty() {
        return Err(invalid("a fixture path is not empty"));
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(limit(format!(
            "a fixture path is {} bytes; the cap is {MAX_PATH_BYTES}",
            path.len()
        )));
    }
    if path.contains('\0') || path.contains(':') {
        return Err(invalid(format!(
            "fixture path `{path}` is not a portable relative path"
        )));
    }

    let mut relative = PathBuf::new();
    for part in path.split(['/', '\\']) {
        if part.is_empty() || part == "." || part == ".." {
            return Err(invalid(format!(
                "fixture path `{path}` is not a plain relative path"
            )));
        }
        relative.push(part);
    }
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(invalid(format!(
            "fixture path `{path}` is not a relative path"
        )));
    }
    Ok(relative)
}

// ---------------------------------------------------------------------------
// Public view
// ---------------------------------------------------------------------------

/// A task as the candidate sees it: no checks, no expected text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicTask {
    pub id: String,
    pub prompt: String,
    pub fixture: Fixture,
}

/// The candidate-visible projection of a suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSuite {
    pub tasks: Vec<PublicTask>,
}

/// Project a suite to what a candidate may read. The checks stay behind.
pub fn public_view(suite: &EvalSuite) -> PublicSuite {
    PublicSuite {
        tasks: suite
            .tasks
            .iter()
            .map(|task| PublicTask {
                id: task.id.clone(),
                prompt: task.prompt.clone(),
                fixture: task.fixture.clone(),
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Load and validate a suite from `path`, which must resolve inside
/// `trusted_root`.
///
/// The path is canonicalized, a symlink at `path` is refused, and the read is
/// bounded before parsing. The returned suite is validated.
pub fn load_suite(path: &Path, trusted_root: &Path) -> Result<EvalSuite> {
    let root = trusted_root.canonicalize().map_err(|error| {
        ZeroError::new(
            ErrorCode::NotFound,
            format!("trusted eval root `{}`: {error}", trusted_root.display()),
        )
    })?;
    if !root.is_dir() {
        return Err(invalid(format!(
            "trusted eval root `{}` is not a directory",
            trusted_root.display()
        )));
    }

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(ZeroError::new(
            ErrorCode::PermissionDenied,
            format!(
                "eval suite `{}` is a symlink; symlinks are not followed",
                path.display()
            ),
        ));
    }
    let canonical = path.canonicalize()?;
    if canonical == root {
        return Err(invalid(format!(
            "eval suite `{}` is the trusted root, not a suite file",
            path.display()
        )));
    }
    if !canonical.starts_with(&root) {
        return Err(ZeroError::new(
            ErrorCode::PermissionDenied,
            format!(
                "eval suite `{}` is outside the trusted root `{}`",
                path.display(),
                trusted_root.display()
            ),
        ));
    }
    let metadata = std::fs::metadata(&canonical)?;
    if !metadata.is_file() {
        return Err(invalid(format!(
            "eval suite `{}` is not a file",
            path.display()
        )));
    }
    if metadata.len() > MAX_SUITE_BYTES {
        return Err(limit(format!(
            "eval suite is {} bytes; the cap is {MAX_SUITE_BYTES}",
            metadata.len()
        )));
    }

    let file = File::open(&canonical)?;
    let mut bytes = Vec::new();
    file.take(MAX_SUITE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SUITE_BYTES {
        return Err(limit(format!(
            "eval suite grew past {MAX_SUITE_BYTES} bytes while it was read"
        )));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| ZeroError::new(ErrorCode::Serialization, "eval suite is not UTF-8"))?;
    let suite: EvalSuite = serde_json::from_str(text)?;
    validate_suite(&suite)?;
    Ok(suite)
}

/// [`load_suite`] plus [`verify_hash`] against a pinned digest.
pub fn load_suite_verified(
    path: &Path,
    trusted_root: &Path,
    expected_hash: &str,
) -> Result<EvalSuite> {
    let suite = load_suite(path, trusted_root)?;
    verify_hash(&suite, expected_hash)?;
    Ok(suite)
}

// ---------------------------------------------------------------------------
// Offline runner
// ---------------------------------------------------------------------------

/// What a candidate returned for one task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CandidateOutput {
    pub fn new(exit_code: i32, stdout: impl Into<String>, stderr: impl Into<String>) -> Self {
        Self {
            exit_code,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }
}

/// The only interface the evaluator gives a candidate.
///
/// The runner receives one [`PublicTask`] and a freshly created workspace. It
/// cannot see [`EvalTask::checks`], and it must not be given the suite itself.
pub trait CandidateRunner {
    fn run(&self, task: &PublicTask, workspace: &Path) -> Result<CandidateOutput>;
}

/// One failed check. `detail` never contains the task prompt, the expected
/// text, or the candidate's output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailedCheck {
    pub index: usize,
    pub detail: String,
}

/// Outcome for one task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskResult {
    pub id: String,
    pub passed: bool,
    pub failed_checks: Vec<FailedCheck>,
}

/// Scores for one suite run. No prompts and no expected text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalReport {
    pub suite_version: String,
    pub passed: usize,
    pub failed: usize,
    pub task_results: Vec<TaskResult>,
    pub started: i64,
    pub finished: i64,
}

impl EvalReport {
    /// The task result for `id`, if the report has one.
    pub fn task(&self, id: &str) -> Option<&TaskResult> {
        self.task_results.iter().find(|result| result.id == id)
    }
}

/// Run every task on a fresh workspace under `scratch_root`.
///
/// Each workspace is created, never reused: an existing `task-NNNN-<id>`
/// directory is refused instead of deleted. Fixture paths are re-validated and
/// written under the workspace only. A runner error fails that task; it does
/// not abort the run.
pub fn run_suite(
    suite: &EvalSuite,
    runner: &dyn CandidateRunner,
    scratch_root: &Path,
) -> Result<EvalReport> {
    run_suite_with_clock(suite, runner, scratch_root, &SystemClock)
}

/// [`run_suite`] with an injected clock, so a test can produce an identical
/// report twice.
pub fn run_suite_with_clock(
    suite: &EvalSuite,
    runner: &dyn CandidateRunner,
    scratch_root: &Path,
    clock: &dyn Clock,
) -> Result<EvalReport> {
    validate_suite(suite)?;
    let started = clock.now().0;
    std::fs::create_dir_all(scratch_root)?;

    let public = public_view(suite);
    let mut task_results = Vec::with_capacity(public.tasks.len());
    for (index, (task, visible)) in suite.tasks.iter().zip(public.tasks.iter()).enumerate() {
        let id = &task.id;
        let workspace = scratch_root.join(format!("task-{index:04}-{id}"));
        create_fresh_workspace(&workspace)?;
        for (relative, contents) in &visible.fixture.files {
            write_fixture_file(&workspace, relative, contents)?;
        }

        let (passed, failed_checks) = match runner.run(visible, &workspace) {
            Ok(output) => evaluate(task, &workspace, &output),
            Err(error) => {
                let code = error.code();
                (
                    false,
                    vec![FailedCheck {
                        index: task.checks.len(),
                        detail: format!("runner_error: {code}"),
                    }],
                )
            }
        };
        task_results.push(TaskResult {
            id: task.id.clone(),
            passed,
            failed_checks,
        });
    }

    let failed = task_results.iter().filter(|result| !result.passed).count();
    let passed = task_results.len() - failed;
    Ok(EvalReport {
        suite_version: suite.suite_version.clone(),
        passed,
        failed,
        task_results,
        started,
        finished: clock.now().0,
    })
}

fn create_fresh_workspace(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(ZeroError::new(
            ErrorCode::AlreadyExists,
            format!(
                "evaluation workspace `{}` already exists; pass a fresh scratch root",
                path.display()
            ),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path)?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn write_fixture_file(workspace: &Path, relative: &str, contents: &str) -> Result<()> {
    let relative = safe_relative_path(relative)?;
    if contents.len() > MAX_FILE_BYTES {
        return Err(limit(format!(
            "fixture file is {} bytes; the cap is {MAX_FILE_BYTES}",
            contents.len()
        )));
    }
    let target = workspace.join(&relative);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = File::create(&target)?;
    file.write_all(contents.as_bytes())?;
    file.flush()?;
    Ok(())
}

fn evaluate(
    task: &EvalTask,
    workspace: &Path,
    output: &CandidateOutput,
) -> (bool, Vec<FailedCheck>) {
    let mut failed = Vec::new();
    for (index, check) in task.checks.iter().enumerate() {
        if let Err(detail) = evaluate_check(check, workspace, output) {
            failed.push(FailedCheck { index, detail });
        }
    }
    (failed.is_empty(), failed)
}

fn evaluate_check(
    check: &Check,
    workspace: &Path,
    output: &CandidateOutput,
) -> std::result::Result<(), String> {
    match check {
        Check::ExitCode { code } => {
            if output.exit_code == *code {
                Ok(())
            } else {
                let actual = output.exit_code;
                Err(format!("exit_code: expected {code}, got {actual}"))
            }
        }
        Check::FileContains { path, needle } => {
            let resolved = resolve_existing(workspace, path)?;
            let text = read_bounded(&resolved)?;
            if text.contains(needle) {
                Ok(())
            } else {
                Err(format!(
                    "file_contains: `{path}` does not contain the expected text"
                ))
            }
        }
        Check::FileAbsent { path } => {
            let target = safe_relative_path(path)
                .map_err(|_| format!("file_absent: `{path}` is not a safe path"))?;
            match std::fs::symlink_metadata(workspace.join(target)) {
                Ok(_) => Err(format!("file_absent: `{path}` exists")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(_) => Err(format!("file_absent: `{path}` could not be inspected")),
            }
        }
        Check::OutputContains { text } => {
            if output.stdout.contains(text) {
                Ok(())
            } else {
                Err("output_contains: stdout does not contain the expected text".to_string())
            }
        }
    }
}

fn resolve_existing(workspace: &Path, relative: &str) -> std::result::Result<PathBuf, String> {
    let relative = safe_relative_path(relative)
        .map_err(|_| format!("file_contains: `{relative}` is not a safe path"))?;
    let joined = workspace.join(relative);
    let canonical = joined
        .canonicalize()
        .map_err(|_| "file_contains: the checked file is missing".to_string())?;
    let root = workspace
        .canonicalize()
        .map_err(|_| "file_contains: the workspace is missing".to_string())?;
    if !canonical.starts_with(&root) {
        return Err("file_contains: the checked file escapes the workspace".to_string());
    }
    Ok(canonical)
}

fn read_bounded(path: &Path) -> std::result::Result<String, String> {
    let file =
        File::open(path).map_err(|_| "file_contains: the checked file is missing".to_string())?;
    let mut bytes = Vec::new();
    file.take(MAX_CANDIDATE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "file_contains: the checked file could not be read".to_string())?;
    if bytes.len() as u64 > MAX_CANDIDATE_FILE_BYTES {
        return Err("file_contains: the checked file exceeds the read cap".to_string());
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

// ---------------------------------------------------------------------------
// Comparison (SI-02)
// ---------------------------------------------------------------------------

/// Task ids that changed outcome between two runs of the same suite version.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delta {
    /// Tasks that passed in the baseline and no longer do, in baseline order.
    pub regressions: Vec<String>,
    /// Tasks that failed in the baseline and now pass, in baseline order.
    pub improvements: Vec<String>,
}

/// Compare a baseline report with a candidate report.
///
/// Both reports must come from the same `suite_version`; comparing across
/// versions is not evidence, and the caller keeps the pinned suite hash for
/// that reason. A baseline task missing from the candidate counts as a
/// regression. A task that only the candidate has is ignored: it has no
/// baseline evidence.
pub fn compare(baseline: &EvalReport, candidate: &EvalReport) -> Delta {
    let by_id: BTreeMap<&str, &TaskResult> = candidate
        .task_results
        .iter()
        .map(|result| (result.id.as_str(), result))
        .collect();
    let mut delta = Delta::default();
    for base in &baseline.task_results {
        match by_id.get(base.id.as_str()) {
            Some(candidate_result) if !base.passed && candidate_result.passed => {
                delta.improvements.push(base.id.clone());
            }
            Some(candidate_result) if base.passed && !candidate_result.passed => {
                delta.regressions.push(base.id.clone());
            }
            Some(_) => {}
            None if base.passed => delta.regressions.push(base.id.clone()),
            None => {}
        }
    }
    delta
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
    use zero_types::id::FakeClock;

    fn suite(tasks: Vec<EvalTask>) -> EvalSuite {
        EvalSuite {
            schema_version: EVAL_SUITE_SCHEMA_VERSION,
            suite_version: "si-1.0.0".to_string(),
            created_ms: 1_700_000_000_000,
            tasks,
        }
    }

    fn task(id: &str) -> EvalTask {
        EvalTask {
            id: id.to_string(),
            prompt: format!("solve {id}"),
            fixture: Fixture::default(),
            checks: vec![Check::ExitCode { code: 0 }],
        }
    }

    fn report(version: &str, outcomes: &[(&str, bool)]) -> EvalReport {
        let task_results: Vec<TaskResult> = outcomes
            .iter()
            .map(|(id, passed)| TaskResult {
                id: (*id).to_string(),
                passed: *passed,
                failed_checks: Vec::new(),
            })
            .collect();
        let failed = task_results.iter().filter(|result| !result.passed).count();
        EvalReport {
            suite_version: version.to_string(),
            passed: task_results.len() - failed,
            failed,
            task_results,
            started: 0,
            finished: 0,
        }
    }

    fn write_suite(root: &Path, name: &str, suite: &EvalSuite) -> PathBuf {
        let path = root.join(name);
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(suite).expect("serialize suite"),
        )
        .expect("write suite");
        path
    }

    // ----- suite loading and validation -----------------------------------

    #[test]
    fn suite_loads_validates_and_round_trips() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("trusted");
        std::fs::create_dir_all(&root).expect("trusted root");

        let mut original = suite(vec![task("write-answer")]);
        original.tasks[0]
            .fixture
            .files
            .insert("input.txt".to_string(), "hello\n".to_string());
        original.tasks[0].checks.push(Check::FileContains {
            path: "answer.txt".to_string(),
            needle: "42".to_string(),
        });
        let path = write_suite(&root, "suite.json", &original);

        let loaded = load_suite(&path, &root).expect("load");
        assert_eq!(loaded, original);
        validate_suite(&loaded).expect("valid");

        let hash = suite_hash(&loaded);
        assert_eq!(hash.len(), 64);
        assert_eq!(
            suite_hash(&original),
            hash,
            "the hash ignores map iteration order"
        );
        verify_hash(&loaded, &hash).expect("matching hash");
        verify_hash(&loaded, &hash.to_ascii_uppercase()).expect("hex is case-insensitive");

        let verified = load_suite_verified(&path, &root, &hash).expect("verified load");
        assert_eq!(verified, loaded);
    }

    #[test]
    fn public_view_carries_no_scoring_key() {
        let mut held_out = task("held-out");
        held_out
            .fixture
            .files
            .insert("input.txt".to_string(), "data".to_string());
        held_out.checks = vec![
            Check::ExitCode { code: 0 },
            Check::FileContains {
                path: "answer.txt".to_string(),
                needle: "SECRET-EXPECTED".to_string(),
            },
            Check::FileAbsent {
                path: "leftover.tmp".to_string(),
            },
            Check::OutputContains {
                text: "SECRET-EXPECTED".to_string(),
            },
        ];
        let document = suite(vec![held_out]);

        let public = public_view(&document);
        let json = serde_json::to_string(&public).expect("serialize public view");
        assert!(
            !json.contains("checks"),
            "the public view names no checks field"
        );
        assert!(
            !json.contains("SECRET-EXPECTED"),
            "expected text never reaches the public view"
        );
        assert!(
            !json.contains("kind"),
            "no check kind reaches the public view"
        );

        assert_eq!(public.tasks.len(), 1);
        assert_eq!(public.tasks[0].id, document.tasks[0].id);
        assert_eq!(public.tasks[0].prompt, document.tasks[0].prompt);
        assert_eq!(public.tasks[0].fixture, document.tasks[0].fixture);
        assert_eq!(
            document.tasks[0].checks.len(),
            4,
            "the evaluator keeps the key"
        );
    }

    #[test]
    fn load_refuses_paths_outside_the_trusted_root() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("trusted");
        std::fs::create_dir_all(&root).expect("trusted root");
        let outside = dir.path().join("outside.json");
        std::fs::write(
            &outside,
            serde_json::to_vec(&suite(vec![task("one")])).expect("serialize"),
        )
        .expect("write");

        let error = load_suite(&outside, &root).expect_err("outside the root");
        assert_eq!(error.code(), ErrorCode::PermissionDenied);

        let traversal = root.join("..").join("outside.json");
        let error = load_suite(&traversal, &root).expect_err("traversal escapes the root");
        assert_eq!(error.code(), ErrorCode::PermissionDenied);

        let error = load_suite(&root, &root).expect_err("a directory is not a suite");
        assert_eq!(error.code(), ErrorCode::InvalidInput);

        #[cfg(unix)]
        {
            let link = root.join("link.json");
            std::os::unix::fs::symlink(&outside, &link).expect("symlink");
            let error = load_suite(&link, &root).expect_err("symlinks are not followed");
            assert_eq!(error.code(), ErrorCode::PermissionDenied);
        }
    }

    #[test]
    fn load_is_bounded_before_it_parses() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("trusted");
        std::fs::create_dir_all(&root).expect("trusted root");
        let path = root.join("huge.json");
        std::fs::write(&path, vec![b' '; MAX_SUITE_BYTES as usize + 1]).expect("write");
        let error = load_suite(&path, &root).expect_err("oversized suite");
        assert_eq!(error.code(), ErrorCode::LimitExceeded);
    }

    #[test]
    fn unknown_schema_and_bad_versions_are_typed() {
        let mut future = suite(vec![task("one")]);
        future.schema_version = EVAL_SUITE_SCHEMA_VERSION + 1;
        let error = validate_suite(&future).expect_err("future schema");
        assert_eq!(error.code(), ErrorCode::SchemaVersion);

        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("trusted");
        std::fs::create_dir_all(&root).expect("trusted root");
        let path = write_suite(&root, "future.json", &future);
        let error = load_suite(&path, &root).expect_err("future schema on load");
        assert_eq!(error.code(), ErrorCode::SchemaVersion);

        future.schema_version = EVAL_SUITE_SCHEMA_VERSION;
        future.suite_version = String::new();
        assert_eq!(
            validate_suite(&future).expect_err("empty version").code(),
            ErrorCode::InvalidInput
        );

        future.suite_version = "si 1.0".to_string();
        assert_eq!(
            validate_suite(&future)
                .expect_err("space in version")
                .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn duplicate_task_ids_are_refused() {
        let mut duplicated = suite(vec![task("same"), task("same")]);
        let error = validate_suite(&duplicated).expect_err("duplicate id");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("duplicate"), "{}", error.message());

        duplicated.tasks[1].id = "other".to_string();
        validate_suite(&duplicated).expect("unique ids");
    }

    #[test]
    fn suite_bounds_are_enforced() {
        let too_many = suite(
            (0..=MAX_TASKS)
                .map(|index| task(&format!("t{index}")))
                .collect(),
        );
        assert_eq!(
            validate_suite(&too_many)
                .expect_err("too many tasks")
                .code(),
            ErrorCode::LimitExceeded
        );

        let mut too_many_files = suite(vec![task("files")]);
        for index in 0..=MAX_FILES_PER_TASK {
            too_many_files.tasks[0]
                .fixture
                .files
                .insert(format!("f{index}.txt"), "x".to_string());
        }
        assert_eq!(
            validate_suite(&too_many_files)
                .expect_err("too many files")
                .code(),
            ErrorCode::LimitExceeded
        );

        let mut oversized = suite(vec![task("big")]);
        oversized.tasks[0]
            .fixture
            .files
            .insert("big.txt".to_string(), "x".repeat(MAX_FILE_BYTES + 1));
        assert_eq!(
            validate_suite(&oversized).expect_err("file cap").code(),
            ErrorCode::LimitExceeded
        );

        let mut long_prompt = suite(vec![task("long")]);
        long_prompt.tasks[0].prompt = "p".repeat(MAX_PROMPT_BYTES + 1);
        assert_eq!(
            validate_suite(&long_prompt).expect_err("prompt cap").code(),
            ErrorCode::LimitExceeded
        );

        let mut many_checks = suite(vec![task("checks")]);
        many_checks.tasks[0].checks = vec![Check::ExitCode { code: 0 }; MAX_CHECKS_PER_TASK + 1];
        assert_eq!(
            validate_suite(&many_checks).expect_err("check cap").code(),
            ErrorCode::LimitExceeded
        );

        // 17 tasks x 64 files x 4 KiB = 4.25 MiB, over the 4 MiB suite total.
        let mut heavy = suite(Vec::new());
        for index in 0..17 {
            let mut heavy_task = task(&format!("heavy{index}"));
            for file in 0..64 {
                heavy_task
                    .fixture
                    .files
                    .insert(format!("f{file}.txt"), "x".repeat(4096));
            }
            heavy.tasks.push(heavy_task);
        }
        assert_eq!(
            validate_suite(&heavy)
                .expect_err("suite fixture cap")
                .code(),
            ErrorCode::LimitExceeded
        );

        let empty = suite(Vec::new());
        assert_eq!(
            validate_suite(&empty).expect_err("no tasks").code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn tampered_suite_with_a_stale_hash_is_refused() {
        let original = suite(vec![task("one")]);
        let pinned = suite_hash(&original);

        let mut edited = original.clone();
        edited.tasks[0].prompt.push_str(" then do more");
        assert_ne!(suite_hash(&edited), pinned);

        let error = verify_hash(&edited, &pinned).expect_err("stale hash");
        assert_eq!(error.code(), ErrorCode::TamperDetected);

        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("trusted");
        std::fs::create_dir_all(&root).expect("trusted root");
        let path = write_suite(&root, "edited.json", &edited);
        let error = load_suite_verified(&path, &root, &pinned).expect_err("stale hash on load");
        assert_eq!(error.code(), ErrorCode::TamperDetected);

        let error = verify_hash(&edited, "not-a-hash").expect_err("malformed hash");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
    }

    // ----- offline runner -------------------------------------------------

    struct RecordingRunner {
        seen: RefCell<Vec<String>>,
    }

    impl CandidateRunner for RecordingRunner {
        fn run(&self, task: &PublicTask, workspace: &Path) -> Result<CandidateOutput> {
            let json = serde_json::to_string(task)?;
            assert!(
                !json.contains("checks"),
                "the runner must not receive checks"
            );
            assert!(
                !json.contains("SECRET-EXPECTED"),
                "the runner must not receive the key"
            );
            assert!(
                workspace.join("input.txt").exists(),
                "the fixture is written first"
            );
            let id = &task.id;
            assert!(workspace.ends_with(format!("task-0000-{id}")));
            self.seen.borrow_mut().push(json);
            Ok(CandidateOutput::new(0, "", ""))
        }
    }

    #[test]
    fn runner_receives_only_public_tasks() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut held_out = task("visible");
        held_out
            .fixture
            .files
            .insert("input.txt".to_string(), "data".to_string());
        held_out.checks.push(Check::FileContains {
            path: "answer.txt".to_string(),
            needle: "SECRET-EXPECTED".to_string(),
        });
        let runner = RecordingRunner {
            seen: RefCell::new(Vec::new()),
        };

        let report =
            run_suite(&suite(vec![held_out]), &runner, &dir.path().join("scratch")).expect("run");
        assert_eq!(report.failed, 1, "the missing answer file fails the check");
        assert_eq!(runner.seen.borrow().len(), 1);
        assert!(!runner.seen.borrow()[0].contains("SECRET-EXPECTED"));
    }

    struct CheckRunner;

    impl CandidateRunner for CheckRunner {
        fn run(&self, task: &PublicTask, workspace: &Path) -> Result<CandidateOutput> {
            if task.id == "passing" {
                std::fs::write(workspace.join("answer.txt"), "the answer is 42\n")?;
                Ok(CandidateOutput::new(0, "done\n", ""))
            } else {
                std::fs::write(workspace.join("leftover.tmp"), "x")?;
                Ok(CandidateOutput::new(7, "nope\n", "bad\n"))
            }
        }
    }

    #[test]
    fn every_check_kind_passes_and_fails() {
        let checks = vec![
            Check::ExitCode { code: 0 },
            Check::FileContains {
                path: "answer.txt".to_string(),
                needle: "42".to_string(),
            },
            Check::FileAbsent {
                path: "leftover.tmp".to_string(),
            },
            Check::OutputContains {
                text: "done".to_string(),
            },
        ];
        let mut passing = task("passing");
        passing.checks = checks.clone();
        let mut failing = task("failing");
        failing.checks = checks;
        let suite = suite(vec![passing, failing]);

        let dir = tempfile::tempdir().expect("temp dir");
        let report = run_suite(&suite, &CheckRunner, &dir.path().join("scratch")).expect("run");
        assert_eq!(report.passed, 1);
        assert_eq!(report.failed, 1);
        assert_eq!(report.task_results[0].id, "passing");
        assert!(report.task_results[0].passed);
        assert!(report.task_results[0].failed_checks.is_empty());
        assert_eq!(report.task_results[1].id, "failing");
        assert!(!report.task_results[1].passed);
        let indices: Vec<usize> = report.task_results[1]
            .failed_checks
            .iter()
            .map(|failed| failed.index)
            .collect();
        assert_eq!(indices, vec![0, 1, 2, 3]);
        let details: String = report.task_results[1]
            .failed_checks
            .iter()
            .map(|failed| failed.detail.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        assert!(
            details.contains("exit_code: expected 0, got 7"),
            "{details}"
        );
        assert!(details.contains("file_contains"), "{details}");
        assert!(
            details.contains("file_absent: `leftover.tmp` exists"),
            "{details}"
        );
        assert!(details.contains("output_contains"), "{details}");
        assert!(
            !details.contains("42"),
            "the expected text is not echoed: {details}"
        );
        assert!(
            !details.contains("done"),
            "the expected text is not echoed: {details}"
        );
        assert!(
            !details.contains("solve failing"),
            "the prompt is not echoed: {details}"
        );
    }

    #[test]
    fn fixture_paths_cannot_escape_the_workspace() {
        for (index, bad) in [
            "../escape.txt",
            "..\\escape.txt",
            "/abs.txt",
            "C:\\abs.txt",
            "a/../../escape.txt",
            "",
        ]
        .into_iter()
        .enumerate()
        {
            let dir = tempfile::tempdir().expect("temp dir");
            let scratch = dir.path().join(format!("scratch{index}"));
            let mut escaping = task(&format!("escape{index}"));
            escaping
                .fixture
                .files
                .insert(bad.to_string(), "x".to_string());
            let error = run_suite(&suite(vec![escaping]), &CheckRunner, &scratch).expect_err(bad);
            assert_eq!(error.code(), ErrorCode::InvalidInput, "{bad}");
            assert!(!dir.path().join("escape.txt").exists(), "{bad}");
        }

        assert_eq!(
            safe_relative_path("a/b.txt").expect("plain"),
            PathBuf::from("a").join("b.txt")
        );
        assert_eq!(
            safe_relative_path("a\\b.txt").expect("plain"),
            PathBuf::from("a").join("b.txt")
        );
        assert_eq!(
            safe_relative_path("..").expect_err("parent").code(),
            ErrorCode::InvalidInput
        );
    }

    struct ErrorRunner;

    impl CandidateRunner for ErrorRunner {
        fn run(&self, _task: &PublicTask, _workspace: &Path) -> Result<CandidateOutput> {
            Err(ZeroError::new(
                ErrorCode::Io,
                "runner detail that must not reach the report",
            ))
        }
    }

    #[test]
    fn runner_errors_fail_the_task_without_echoing_details() {
        let dir = tempfile::tempdir().expect("temp dir");
        let report = run_suite(
            &suite(vec![task("one")]),
            &ErrorRunner,
            &dir.path().join("scratch"),
        )
        .expect("run");
        assert_eq!(report.failed, 1);
        assert_eq!(report.task_results[0].failed_checks.len(), 1);
        let detail = &report.task_results[0].failed_checks[0].detail;
        assert_eq!(detail, "runner_error: zero.fnd.io");
        let json = serde_json::to_string(&report).expect("serialize report");
        assert!(!json.contains("runner detail"), "{json}");
        assert!(!json.contains("solve one"), "{json}");
    }

    #[test]
    fn an_existing_workspace_is_not_deleted() {
        let dir = tempfile::tempdir().expect("temp dir");
        let scratch = dir.path().join("scratch");
        let workspace = scratch.join("task-0000-one");
        std::fs::create_dir_all(&workspace).expect("existing workspace");
        std::fs::write(workspace.join("keep.txt"), "keep").expect("keep file");

        let error = run_suite(&suite(vec![task("one")]), &CheckRunner, &scratch)
            .expect_err("reuse is refused");
        assert_eq!(error.code(), ErrorCode::AlreadyExists);
        assert!(workspace.join("keep.txt").exists(), "nothing was deleted");
    }

    #[test]
    fn reports_are_deterministic_and_ordered() {
        let checks = vec![
            Check::ExitCode { code: 0 },
            Check::OutputContains {
                text: "done".to_string(),
            },
        ];
        let mut passing = task("passing");
        passing.checks = checks.clone();
        let mut failing = task("second");
        failing.checks = checks;
        let suite = suite(vec![passing, failing]);

        let dir = tempfile::tempdir().expect("temp dir");
        let clock = FakeClock::at(1_000);
        let left = run_suite_with_clock(&suite, &CheckRunner, &dir.path().join("left"), &clock)
            .expect("left");
        let right = run_suite_with_clock(&suite, &CheckRunner, &dir.path().join("right"), &clock)
            .expect("right");

        assert_eq!(left, right);
        assert_eq!(
            serde_json::to_string(&left).expect("left json"),
            serde_json::to_string(&right).expect("right json")
        );
        assert_eq!(left.started, 1_000);
        assert_eq!(left.finished, 1_000);
        assert_eq!(left.suite_version, "si-1.0.0");
        assert_eq!(left.passed, 1);
        assert_eq!(left.failed, 1);
        let ids: Vec<&str> = left
            .task_results
            .iter()
            .map(|result| result.id.as_str())
            .collect();
        assert_eq!(
            ids,
            vec!["passing", "second"],
            "suite order is report order"
        );
        assert!(!serde_json::to_string(&left)
            .expect("json")
            .contains("solve passing"));
        assert!(!left.task("second").expect("second").passed);
    }

    #[test]
    fn compare_reports_regressions_and_improvements() {
        let baseline = report("si-1.0.0", &[("a", true), ("b", false), ("c", true)]);
        let candidate = report("si-1.0.0", &[("a", false), ("b", true), ("c", true)]);
        let delta = compare(&baseline, &candidate);
        assert_eq!(delta.regressions, vec!["a"]);
        assert_eq!(delta.improvements, vec!["b"]);

        let partial = report("si-1.0.0", &[("b", true)]);
        let delta = compare(&baseline, &partial);
        assert_eq!(
            delta.regressions,
            vec!["a", "c"],
            "a missing result is not evidence of a pass"
        );
        assert_eq!(delta.improvements, vec!["b"]);

        let unchanged = compare(&baseline, &baseline);
        assert!(unchanged.regressions.is_empty());
        assert!(unchanged.improvements.is_empty());

        let extra = report(
            "si-1.0.0",
            &[("a", true), ("b", false), ("c", true), ("new", true)],
        );
        let delta = compare(&baseline, &extra);
        assert!(
            delta.improvements.is_empty(),
            "a new passing task has no baseline evidence"
        );
    }

    #[test]
    fn the_module_holds_no_network_or_router_api() {
        let source = include_str!("eval_suite.rs");
        let banned = [
            ["std::", "net"].concat(),
            ["Tcp", "Stream"].concat(),
            ["Udp", "Socket"].concat(),
            ["req", "west"].concat(),
            ["hyper", "::"].concat(),
            ["http", "://"].concat(),
            ["zero_model", "::", "router"].concat(),
        ];
        for token in banned {
            assert!(
                !source.contains(&token),
                "eval_suite must stay offline; found `{token}`"
            );
        }
    }
}
