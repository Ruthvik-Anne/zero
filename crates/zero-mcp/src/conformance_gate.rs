//! Release conformance gate for MCP and protocol fixtures (T-TST-08, TST-10,
//! MCP-19).
//!
//! [`evaluate`] loads every MCP conformance fixture and replays it through
//! [`crate::conformance::run`], then loads every protocol golden fixture and
//! checks it against [`zero_types::proto`]. A gate passes only when every
//! fixture loaded, every MCP exchange passed, both MCP revisions are covered,
//! and every required protocol fixture class is covered.
//!
//! [`assert_gate`] is the release entry point: it evaluates the checked-in
//! fixtures and returns a typed [`GateError`] listing every problem, so a
//! missing fixture class can never be mistaken for a passing suite.
//!
//! Inputs are explicit ([`GateInputs`]), so tests can point the gate at
//! temporary directories without touching the checked-in fixtures. The MCP
//! fixtures live in `tests/fixtures/conformance/`; the protocol goldens live in
//! `protocol/golden/` at the workspace root.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

use serde_json::Value;
use zero_types::proto::{decode_all, Frame};

use crate::conformance::{self, ConformanceError, ConformanceFixture};
use crate::revision::McpRevision;

/// Protocol golden fixture classes the gate requires. The class is the file
/// stem of the JSON projection (`v1-frames` for `v1-frames.json`).
pub const REQUIRED_PROTOCOL_CLASSES: &[&str] = &["v1-frames", "v1-stream"];

/// One protocol golden fixture: a JSON projection and its fixture class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolFixture {
    /// Fixture class, normally the JSON file stem.
    pub class: String,
    /// Path to the JSON projection; a sibling `.bin` is checked when present.
    pub json: PathBuf,
}

/// The fixture set a gate run evaluates.
///
/// [`GateInputs::default`] carries no fixtures but the full required-coverage
/// sets, so it fails honestly instead of passing vacuously.
#[derive(Debug, Clone)]
pub struct GateInputs {
    /// MCP conformance fixture files.
    pub mcp_fixtures: Vec<PathBuf>,
    /// Protocol golden fixtures, each with its class.
    pub protocol_fixtures: Vec<ProtocolFixture>,
    /// Revisions that must be covered by at least one replayed fixture.
    pub required_revisions: Vec<McpRevision>,
    /// Protocol fixture classes that must be present.
    pub required_protocol_classes: Vec<String>,
}

impl Default for GateInputs {
    fn default() -> Self {
        Self {
            mcp_fixtures: Vec::new(),
            protocol_fixtures: Vec::new(),
            required_revisions: McpRevision::ALL.to_vec(),
            required_protocol_classes: REQUIRED_PROTOCOL_CLASSES
                .iter()
                .map(|class| (*class).to_string())
                .collect(),
        }
    }
}

impl GateInputs {
    /// The checked-in fixtures: `tests/fixtures/conformance/` and
    /// `protocol/golden/`.
    pub fn checked_in() -> Self {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        Self::from_dirs(
            manifest.join("tests/fixtures/conformance"),
            manifest.join("../../protocol/golden"),
        )
    }

    /// Discover every JSON fixture in the given directories.
    ///
    /// A directory that cannot be read yields no fixtures, which the gate
    /// reports as a missing fixture class rather than silently passing.
    pub fn from_dirs(mcp_dir: impl AsRef<Path>, protocol_dir: impl AsRef<Path>) -> Self {
        let mcp_fixtures = scan_json_files(mcp_dir.as_ref());
        let protocol_fixtures = scan_json_files(protocol_dir.as_ref())
            .into_iter()
            .map(|json| ProtocolFixture {
                class: json
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or_default()
                    .to_string(),
                json,
            })
            .collect();
        Self {
            mcp_fixtures,
            protocol_fixtures,
            ..Self::default()
        }
    }
}

fn scan_json_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|extension| extension.to_str()) == Some("json"))
        .collect();
    paths.sort();
    paths
}

/// Aggregate result of one gate run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateReport {
    /// Number of MCP fixture files the gate attempted.
    pub mcp_fixtures: usize,
    /// Revisions covered by a replayed fixture.
    pub mcp_revisions: BTreeSet<McpRevision>,
    /// Number of protocol fixture files the gate attempted.
    pub protocol_fixtures: usize,
    /// True only when `failures` is empty.
    pub ok: bool,
    /// Every problem, in evaluation order.
    pub failures: Vec<GateFailure>,
}

/// A typed gate problem. Every variant names the missing class or failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateFailure {
    /// No MCP conformance fixture was found.
    NoMcpFixtures,
    /// No protocol golden fixture was found.
    NoProtocolFixtures,
    /// A required MCP revision has no replayed fixture.
    MissingRevision {
        /// Revision that is not covered.
        revision: McpRevision,
    },
    /// A fixture declares a revision the client does not speak.
    UnknownRevision {
        /// Fixture path.
        path: PathBuf,
        /// Revision string from the fixture.
        revision: String,
    },
    /// A fixture could not be read or parsed as fixture JSON.
    MalformedFixture {
        /// Fixture path.
        path: PathBuf,
        /// Underlying I/O or serde detail.
        detail: String,
    },
    /// A fixture parsed but failed structural validation before replay.
    RejectedFixture {
        /// Fixture path.
        path: PathBuf,
        /// Validation detail.
        detail: String,
    },
    /// A fixture replayed but one exchange did not meet its expectation.
    ExchangeFailed {
        /// Fixture name from the fixture.
        fixture: String,
        /// Exchange name.
        exchange: String,
        /// Mismatch detail.
        detail: String,
    },
    /// A required protocol fixture class is absent.
    MissingProtocolClass {
        /// Class that is not covered.
        class: String,
    },
    /// A protocol fixture could not be read, parsed, or decoded.
    ProtocolDecode {
        /// Fixture path.
        path: PathBuf,
        /// Underlying detail.
        detail: String,
    },
    /// The canonical JSON projection changed after a round trip.
    ProtocolProjection {
        /// Fixture path.
        path: PathBuf,
        /// Which frame and how it changed.
        detail: String,
    },
}

impl fmt::Display for GateFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GateFailure::NoMcpFixtures => {
                f.write_str("missing MCP fixture class: no conformance fixture was found")
            }
            GateFailure::NoProtocolFixtures => {
                f.write_str("missing protocol fixture class: no protocol golden was found")
            }
            GateFailure::MissingRevision { revision } => write!(
                f,
                "missing MCP fixture class: revision `{revision}` is not covered"
            ),
            GateFailure::UnknownRevision { path, revision } => write!(
                f,
                "unknown MCP revision `{revision}` in fixture `{}`",
                path.display()
            ),
            GateFailure::MalformedFixture { path, detail } => {
                write!(f, "malformed fixture `{}`: {detail}", path.display())
            }
            GateFailure::RejectedFixture { path, detail } => {
                write!(f, "fixture `{}` was rejected: {detail}", path.display())
            }
            GateFailure::ExchangeFailed {
                fixture,
                exchange,
                detail,
            } => write!(
                f,
                "fixture `{fixture}` exchange `{exchange}` failed: {detail}"
            ),
            GateFailure::MissingProtocolClass { class } => {
                write!(f, "missing protocol fixture class: `{class}`")
            }
            GateFailure::ProtocolDecode { path, detail } => {
                write!(
                    f,
                    "protocol fixture `{}` did not decode: {detail}",
                    path.display()
                )
            }
            GateFailure::ProtocolProjection { path, detail } => write!(
                f,
                "protocol fixture `{}` projection is not stable: {detail}",
                path.display()
            ),
        }
    }
}

/// The typed error returned by [`assert_gate`] and [`assert_gate_with`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateError {
    /// Every problem found by the run.
    pub failures: Vec<GateFailure>,
}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "conformance gate failed with {} problem(s):",
            self.failures.len()
        )?;
        for failure in &self.failures {
            write!(f, "\n  - {failure}")?;
        }
        Ok(())
    }
}

impl std::error::Error for GateError {}

/// Evaluate the given fixtures and report every problem.
pub fn evaluate(inputs: &GateInputs) -> GateReport {
    let mut failures = Vec::new();
    let mut revisions = BTreeSet::new();

    if inputs.mcp_fixtures.is_empty() {
        failures.push(GateFailure::NoMcpFixtures);
    }
    for path in &inputs.mcp_fixtures {
        match ConformanceFixture::load(path) {
            Ok(fixture) => match conformance::run(&fixture) {
                Ok(report) => {
                    revisions.insert(report.revision);
                    for exchange in &report.exchanges {
                        if let Some(failure) = &exchange.failure {
                            failures.push(GateFailure::ExchangeFailed {
                                fixture: report.fixture.clone(),
                                exchange: exchange.name.clone(),
                                detail: failure.detail.clone(),
                            });
                        }
                    }
                }
                Err(error) => push_conformance_error(&mut failures, path, error),
            },
            Err(error) => push_conformance_error(&mut failures, path, error),
        }
    }
    for revision in &inputs.required_revisions {
        if !revisions.contains(revision) {
            failures.push(GateFailure::MissingRevision {
                revision: *revision,
            });
        }
    }

    if inputs.protocol_fixtures.is_empty() {
        failures.push(GateFailure::NoProtocolFixtures);
    }
    let mut classes = BTreeSet::new();
    for fixture in &inputs.protocol_fixtures {
        classes.insert(fixture.class.clone());
        if let Err(failure) = check_protocol_fixture(fixture) {
            failures.push(failure);
        }
    }
    for class in &inputs.required_protocol_classes {
        if !classes.contains(class) {
            failures.push(GateFailure::MissingProtocolClass {
                class: class.clone(),
            });
        }
    }

    GateReport {
        mcp_fixtures: inputs.mcp_fixtures.len(),
        mcp_revisions: revisions,
        protocol_fixtures: inputs.protocol_fixtures.len(),
        ok: failures.is_empty(),
        failures,
    }
}

/// Evaluate the checked-in fixtures and return a typed error on any problem.
pub fn assert_gate() -> Result<GateReport, GateError> {
    assert_gate_with(&GateInputs::checked_in())
}

/// Evaluate explicit fixtures; the typed-error form of [`evaluate`].
pub fn assert_gate_with(inputs: &GateInputs) -> Result<GateReport, GateError> {
    let report = evaluate(inputs);
    if report.ok {
        Ok(report)
    } else {
        Err(GateError {
            failures: report.failures.clone(),
        })
    }
}

fn push_conformance_error(failures: &mut Vec<GateFailure>, path: &Path, error: ConformanceError) {
    let detail = error.to_string();
    match &error {
        ConformanceError::UnsupportedRevision { revision, .. } => {
            failures.push(GateFailure::UnknownRevision {
                path: path.to_path_buf(),
                revision: revision.clone(),
            });
        }
        ConformanceError::Read { .. } | ConformanceError::Parse { .. } => {
            failures.push(GateFailure::MalformedFixture {
                path: path.to_path_buf(),
                detail,
            });
        }
        _ => failures.push(GateFailure::RejectedFixture {
            path: path.to_path_buf(),
            detail,
        }),
    }
}

fn check_protocol_fixture(fixture: &ProtocolFixture) -> Result<(), GateFailure> {
    let path = &fixture.json;
    let decode = |detail: String| GateFailure::ProtocolDecode {
        path: path.clone(),
        detail,
    };

    let text = std::fs::read_to_string(path)
        .map_err(|error| decode(format!("could not read: {error}")))?;
    let projections: Vec<Value> = serde_json::from_str(&text)
        .map_err(|error| decode(format!("not a JSON array of frames: {error}")))?;
    if projections.is_empty() {
        return Err(decode("fixture contains no frames".to_string()));
    }

    let mut frames = Vec::with_capacity(projections.len());
    for (index, projection) in projections.iter().enumerate() {
        let frame: Frame = serde_json::from_value(projection.clone())
            .map_err(|error| decode(format!("frame {index} is not a protocol frame: {error}")))?;
        let canonical = serde_json::to_value(&frame)
            .map_err(|error| decode(format!("frame {index} could not be projected: {error}")))?;
        if &canonical != projection {
            return Err(GateFailure::ProtocolProjection {
                path: path.clone(),
                detail: format!(
                    "frame {index} changed when projected: {canonical} != {projection}"
                ),
            });
        }
        let encoded = frame
            .encode()
            .map_err(|error| decode(format!("frame {index} could not be encoded: {error}")))?;
        let (decoded, used) = Frame::decode(&encoded)
            .map_err(|error| decode(format!("frame {index} could not be decoded: {error}")))?;
        if decoded != frame || used != encoded.len() {
            return Err(decode(format!(
                "frame {index} did not round-trip through the binary codec"
            )));
        }
        frames.push(frame);
    }

    let mut stream = Vec::new();
    for frame in &frames {
        let encoded = frame
            .encode()
            .map_err(|error| decode(format!("frame stream could not be encoded: {error}")))?;
        stream.extend_from_slice(&encoded);
    }
    let decoded = decode_all(&stream)
        .map_err(|error| decode(format!("frame stream could not be decoded: {error}")))?;
    if decoded != frames {
        return Err(decode(
            "the decoded frame stream does not match its JSON projection".to_string(),
        ));
    }

    let binary = path.with_extension("bin");
    if binary.exists() {
        let bytes = std::fs::read(&binary)
            .map_err(|error| decode(format!("could not read `{}`: {error}", binary.display())))?;
        let decoded = decode_all(&bytes).map_err(|error| {
            decode(format!(
                "`{}` could not be decoded: {error}",
                binary.display()
            ))
        })?;
        if decoded != frames {
            return Err(decode(format!(
                "`{}` does not match its JSON projection",
                binary.display()
            )));
        }
    }

    Ok(())
}
