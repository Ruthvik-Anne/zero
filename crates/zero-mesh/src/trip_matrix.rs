//! Teleport failure matrix (T-TEL-08, TEL-08, TEL-10, TEL-13, TEL-14).
//!
//! A teleport trip is exercised through four fixtures against the real modules:
//!
//! - **Interrupted** — a bundle is written part-way, the writer is dropped, and
//!   [`BundleWriter::resume`](crate::bundle::BundleWriter::resume) finishes it.
//!   The chunk files are re-read from disk, verified, and restored; the result
//!   is byte-identical to the source and a second restore writes nothing.
//! - **Unreachable source** — an injected [`SourceProbe`] reports the source
//!   offline. The target refuses with [`ErrorCode::Unavailable`] and a reason,
//!   writes nothing, and its already-restored local snapshot still verifies.
//! - **Forced takeover** — an expired source lease is handed to the target with
//!   [`fence::handoff`](crate::fence::handoff), which advances the generation.
//!   The new holder writes and restores; the stale holder's write, restore, and
//!   release are refused, and its resume cursor forces a snapshot instead of
//!   replaying effects.
//! - **Return trip** — a snapshot is remapped and re-signed A→B, then B→A. The
//!   components return byte-identically, the original device key verifies the
//!   final snapshot, and a first-leg lease generation is refused by the second
//!   leg's fence.
//!
//! There is no socket in this module. [`SourceProbe`] is the network and
//! availability seam; a probe that reports the source reachable makes the
//! unreachable-source fixture fail honestly rather than pretending it ran.
//! [`run_matrix`] creates only scratch state under the caller's root, and
//! [`assert_all_four`] is the typed gate over a report.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, ZeroError};

use crate::bundle::{build, Bundle, BundleReader, BundleWriter, ChunkConfig, Excluded};
use crate::fence::{assert_can_write, handoff, release, resume, HolderId, Lease, ResumeCursor};
use crate::identity::KeyPair;
use crate::portability::{remap_snapshot_report, PathMap};
use crate::restore::{restore as apply_restore, RestoreOptions, RestorePlan, RestoreReport};
use crate::snapshot::{self, Component, ComponentBlob, Snapshot};

/// Directory under [`TripRequest::root`] that holds the matrix scratch state.
pub const TRIP_MATRIX_DIR: &str = "trip-matrix";

const CHUNK_BYTES: usize = 512;
const MAX_CHUNKS: usize = 1024;
const LEASE_TTL_MS: i64 = 30_000;
const PROJECT_ID: &str = "trip-matrix";
const SOURCE_ROOT: &str = r"C:\work\proj";
const TARGET_ROOT: &str = "/home/alice/proj";

type Result<T, E = ZeroError> = std::result::Result<T, E>;

/// The four failure fixtures T-TEL-08 requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Fixture {
    /// A checkpointed bundle resumes and restores byte-identically.
    Interrupted,
    /// An unreachable source is refused without damaging local state.
    UnreachableSource,
    /// A forced lease takeover fences the stale holder off.
    ForcedTakeover,
    /// A→B→A restores state and identity and refuses the first leg's generation.
    ReturnTrip,
}

impl Fixture {
    /// Every fixture, in deterministic order.
    pub const ALL: [Fixture; 4] = [
        Fixture::Interrupted,
        Fixture::UnreachableSource,
        Fixture::ForcedTakeover,
        Fixture::ReturnTrip,
    ];

    /// Stable lower-case label, also the fixture's scratch directory name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Fixture::Interrupted => "interrupted",
            Fixture::UnreachableSource => "unreachable-source",
            Fixture::ForcedTakeover => "forced-takeover",
            Fixture::ReturnTrip => "return-trip",
        }
    }
}

impl fmt::Display for Fixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How far a trip goes. A one-way trip cannot satisfy T-TEL-08's four-fixture
/// gate because the return leg is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    /// Source to target only.
    Forward,
    /// Source to target and back to the source.
    Return,
}

/// What an injected [`SourceProbe`] reports about the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceAvailability {
    /// The source can be reached by the transfer path.
    Reachable,
    /// The source cannot be reached by the transfer path.
    Unreachable,
}

/// The network and availability seam. No socket is opened by this module.
pub trait SourceProbe {
    /// Report the source's availability for this trip.
    fn availability(&self) -> SourceAvailability;
}

/// A fixed probe for tests and scripted runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScriptedSource {
    available: bool,
}

impl ScriptedSource {
    /// A probe that always reports the source reachable.
    pub const fn reachable() -> Self {
        Self { available: true }
    }

    /// A probe that always reports the source unreachable.
    pub const fn unreachable() -> Self {
        Self { available: false }
    }
}

impl SourceProbe for ScriptedSource {
    fn availability(&self) -> SourceAvailability {
        if self.available {
            SourceAvailability::Reachable
        } else {
            SourceAvailability::Unreachable
        }
    }
}

/// Inputs for one matrix run, plus the scratch root the fixtures may write to.
#[derive(Debug, Clone, Copy)]
pub struct TripRequest<'a> {
    /// Caller-supplied trip id. It names the scratch directory and the lease.
    pub id: &'a str,
    /// Source device label, used in the unreachable refusal.
    pub source: &'a str,
    /// Target device label.
    pub target: &'a str,
    /// Forward-only or return trip.
    pub direction: Direction,
    /// Existing scratch directory the harness may write under.
    pub root: &'a Path,
    /// Caller clock in milliseconds.
    pub now_ms: i64,
}

/// One fixture's run inside a [`Trip`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureRun {
    /// Which fixture ran.
    pub fixture: Fixture,
    /// True only when every check in the fixture passed.
    pub passed: bool,
    /// Human-readable result or failure reason.
    pub notes: Vec<String>,
    /// Stable `key=value` facts for the evidence table.
    pub evidence: Vec<String>,
}

/// A teleport trip: its identity plus the fixture runs that were executed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trip {
    /// Caller-supplied trip id.
    pub id: String,
    /// Source device label.
    pub source: String,
    /// Target device label.
    pub target: String,
    /// Forward-only or return trip.
    pub direction: Direction,
    /// Fixture runs, in [`Fixture::ALL`] order, without skipped fixtures.
    pub fixtures: Vec<FixtureRun>,
}

impl Trip {
    /// The run for one fixture, when the fixture executed.
    pub fn fixture(&self, fixture: Fixture) -> Option<&FixtureRun> {
        self.fixtures.iter().find(|run| run.fixture == fixture)
    }

    /// Flatten the trip into the report T-TEL-08's gate consumes.
    pub fn report(&self) -> TripMatrixReport {
        let mut report = TripMatrixReport {
            outcomes: self
                .fixtures
                .iter()
                .map(|run| TripOutcome {
                    fixture: run.fixture,
                    passed: run.passed,
                    notes: run.notes.clone(),
                    evidence: run.evidence.clone(),
                })
                .collect(),
            ok: false,
        };
        report.recompute_ok();
        report
    }
}

/// The result of one matrix fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TripOutcome {
    /// Which fixture this outcome belongs to.
    pub fixture: Fixture,
    /// True only when the fixture passed.
    pub passed: bool,
    /// Human-readable result or failure reason.
    pub notes: Vec<String>,
    /// Stable `key=value` facts for the evidence table.
    pub evidence: Vec<String>,
}

/// The whole matrix: one outcome per executed fixture and the four-fixture gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TripMatrixReport {
    /// Executed fixture outcomes.
    pub outcomes: Vec<TripOutcome>,
    /// True only when all four fixtures are present, unique, and passing.
    pub ok: bool,
}

impl TripMatrixReport {
    /// The outcome for one fixture, when it ran.
    pub fn outcome(&self, fixture: Fixture) -> Option<&TripOutcome> {
        self.outcomes
            .iter()
            .find(|outcome| outcome.fixture == fixture)
    }

    /// Recompute [`Self::ok`] from the outcomes.
    ///
    /// This is what makes a hand-edited report (a removed or failed fixture) an
    /// honest failure rather than a stale boolean.
    pub fn recompute_ok(&mut self) {
        let mut seen = BTreeSet::new();
        self.ok = self.outcomes.len() == Fixture::ALL.len()
            && self
                .outcomes
                .iter()
                .all(|outcome| outcome.passed && seen.insert(outcome.fixture));
    }
}

/// A typed failure of the four-fixture gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TripMatrixError {
    /// A required fixture did not run.
    Missing(Fixture),
    /// A fixture appears more than once.
    Duplicate(Fixture),
    /// A fixture ran and failed.
    Failed {
        /// The failing fixture.
        fixture: Fixture,
        /// The fixture's notes, including the refusal or mismatch.
        notes: Vec<String>,
    },
    /// The report is internally inconsistent (`ok` disagrees with the outcomes).
    Inconsistent,
}

impl TripMatrixError {
    /// The fixture this error names, when it names one.
    pub const fn fixture(&self) -> Option<Fixture> {
        match self {
            TripMatrixError::Missing(fixture)
            | TripMatrixError::Duplicate(fixture)
            | TripMatrixError::Failed { fixture, .. } => Some(*fixture),
            TripMatrixError::Inconsistent => None,
        }
    }

    /// The stable error code for this gate failure.
    pub const fn code(&self) -> ErrorCode {
        match self {
            TripMatrixError::Failed { .. } => ErrorCode::Internal,
            TripMatrixError::Missing(_)
            | TripMatrixError::Duplicate(_)
            | TripMatrixError::Inconsistent => ErrorCode::InvalidInput,
        }
    }
}

impl fmt::Display for TripMatrixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TripMatrixError::Missing(fixture) => {
                write!(f, "the failure matrix is missing the `{fixture}` fixture")
            }
            TripMatrixError::Duplicate(fixture) => {
                write!(
                    f,
                    "the failure matrix ran the `{fixture}` fixture more than once"
                )
            }
            TripMatrixError::Failed { fixture, notes } => {
                write!(f, "the `{fixture}` fixture failed: {}", notes.join("; "))
            }
            TripMatrixError::Inconsistent => {
                f.write_str("the failure matrix report's `ok` flag disagrees with its outcomes")
            }
        }
    }
}

impl std::error::Error for TripMatrixError {}

/// Require all four fixtures to be present, unique, and passing.
///
/// A skipped fixture is [`TripMatrixError::Missing`] and a failed fixture is
/// [`TripMatrixError::Failed`], both naming the fixture. The check reads the
/// outcomes, not only [`TripMatrixReport::ok`], so a report with a stale flag
/// cannot pass.
pub fn assert_all_four(report: &TripMatrixReport) -> std::result::Result<(), TripMatrixError> {
    for fixture in Fixture::ALL {
        let mut matches = report
            .outcomes
            .iter()
            .filter(|outcome| outcome.fixture == fixture);
        let Some(outcome) = matches.next() else {
            return Err(TripMatrixError::Missing(fixture));
        };
        if matches.next().is_some() {
            return Err(TripMatrixError::Duplicate(fixture));
        }
        if !outcome.passed {
            return Err(TripMatrixError::Failed {
                fixture,
                notes: outcome.notes.clone(),
            });
        }
    }
    if !report.ok {
        return Err(TripMatrixError::Inconsistent);
    }
    Ok(())
}

/// Run the failure matrix and return the trip record with every executed
/// fixture.
///
/// This is the same run as [`run_matrix`], kept as a [`Trip`] so a caller can
/// inspect the fixture runs directly instead of the flattened report.
pub fn run_trip(request: &TripRequest<'_>, probe: &dyn SourceProbe) -> Trip {
    let mut trip = Trip {
        id: request.id.to_string(),
        source: request.source.to_string(),
        target: request.target.to_string(),
        direction: request.direction,
        fixtures: Vec::new(),
    };
    for fixture in Fixture::ALL {
        if fixture == Fixture::ReturnTrip && request.direction == Direction::Forward {
            continue;
        }
        trip.fixtures.push(run_fixture(request, fixture, probe));
    }
    trip
}

/// Run the failure matrix against the real bundle, restore, fence, and
/// portability modules, with [`SourceProbe`] injected for availability.
///
/// A [`Direction::Forward`] request runs the first three fixtures and leaves
/// the return leg missing, so [`assert_all_four`] reports
/// [`TripMatrixError::Missing`]. A [`Direction::Return`] request runs all four.
/// Fixture failures are recorded in the report rather than returned, so one
/// broken fixture does not hide the others.
pub fn run_matrix(request: &TripRequest<'_>, probe: &dyn SourceProbe) -> TripMatrixReport {
    run_trip(request, probe).report()
}

fn run_fixture(request: &TripRequest<'_>, fixture: Fixture, probe: &dyn SourceProbe) -> FixtureRun {
    let dir = fixture_dir(request, fixture);
    let result = fs::create_dir_all(&dir)
        .map_err(ZeroError::from)
        .and_then(|()| match fixture {
            Fixture::Interrupted => fixture_interrupted(request, &dir),
            Fixture::UnreachableSource => fixture_unreachable(request, &dir, probe),
            Fixture::ForcedTakeover => fixture_forced_takeover(request, &dir),
            Fixture::ReturnTrip => fixture_return_trip(request, &dir),
        });
    match result {
        Ok(evidence) => FixtureRun {
            fixture,
            passed: true,
            notes: vec![format!("the `{fixture}` fixture passed")],
            evidence,
        },
        Err(error) => FixtureRun {
            fixture,
            passed: false,
            notes: vec![format!("{}: {}", error.code(), error.message())],
            evidence: Vec::new(),
        },
    }
}

fn fixture_dir(request: &TripRequest<'_>, fixture: Fixture) -> PathBuf {
    request
        .root
        .join(TRIP_MATRIX_DIR)
        .join(safe_segment(request.id))
        .join(fixture.as_str())
}

/// A bounded, path-safe directory component. The trip id is caller text, so it
/// never reaches the filesystem verbatim.
fn safe_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len().min(64));
    for ch in value.chars().take(64) {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "trip".to_string()
    } else {
        out
    }
}

fn chunk_config() -> Result<ChunkConfig> {
    ChunkConfig::new(CHUNK_BYTES, MAX_CHUNKS)
}

fn pattern(len: usize, seed: usize) -> Vec<u8> {
    (0..len).map(|index| ((index + seed) % 251) as u8).collect()
}

fn workspace_files() -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    files.insert("src/main.rs".to_string(), pattern(1300, 7));
    files.insert("notes.txt".to_string(), b"teleport trip matrix\n".to_vec());
    files.insert("data/values.bin".to_string(), pattern(1200, 31));
    files
}

fn restore_plan(files: &BTreeMap<String, Vec<u8>>, now_ms: i64) -> Result<RestorePlan> {
    let bundle = build(
        files.clone(),
        Vec::<Excluded>::new(),
        chunk_config()?,
        now_ms,
    )?;
    RestorePlan::from_bundle(&bundle, BTreeMap::new(), None)
}

fn assert_restored(files: &BTreeMap<String, Vec<u8>>, root: &Path) -> Result<()> {
    for (path, expected) in files {
        let actual = fs::read(root.join(path)).map_err(|error| {
            ZeroError::new(
                ErrorCode::Io,
                format!("cannot read the restored `{path}`: {error}"),
            )
        })?;
        if actual != *expected {
            return Err(ZeroError::new(
                ErrorCode::TamperDetected,
                format!("the restored `{path}` is not byte-identical to the source"),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixture 1: interrupted transfer.
// ---------------------------------------------------------------------------

fn fixture_interrupted(request: &TripRequest<'_>, dir: &Path) -> Result<Vec<String>> {
    let bundle_dir = dir.join("bundle");
    let restored_root = dir.join("restored");
    let files = workspace_files();
    let bundle = build(
        files.clone(),
        Vec::<Excluded>::new(),
        chunk_config()?,
        request.now_ms,
    )?;
    let total_chunks = bundle.manifest.chunk_hashes().len();

    let mut writer = BundleWriter::create(&bundle_dir, &bundle.manifest)?;
    let mut interrupted_after = 0usize;
    for _ in 0..2 {
        if writer.write_one_pending(&bundle.chunks)?.is_none() {
            return Err(ZeroError::new(
                ErrorCode::Internal,
                "the interrupted fixture needs at least two chunks",
            ));
        }
        interrupted_after = writer.written().len();
    }
    if interrupted_after != 2 || writer.is_complete() {
        return Err(ZeroError::new(
            ErrorCode::Internal,
            "the interrupted writer did not stop between chunks",
        ));
    }
    drop(writer);

    let mut resumed = BundleWriter::resume(&bundle_dir)?;
    if resumed.written().len() != interrupted_after {
        return Err(ZeroError::new(
            ErrorCode::TamperDetected,
            "the checkpoint lost chunks across the interruption",
        ));
    }
    let finished = resumed.write_pending(&bundle.chunks)?;
    if !finished.complete {
        return Err(ZeroError::new(
            ErrorCode::Internal,
            "the resumed writer reported an incomplete bundle",
        ));
    }
    if finished.already_present != interrupted_after as u64 {
        return Err(ZeroError::new(
            ErrorCode::Internal,
            "the resumed writer rewrote chunks that were already durable",
        ));
    }

    // Rebuild the bundle from the checkpointed files on disk, not from the
    // in-memory copy, so the restore proves the durable state.
    let reader = BundleReader::open(&bundle_dir)?;
    let verified = reader.verify()?;
    let manifest = reader.manifest().clone();
    let mut chunks = BTreeMap::new();
    for hash in manifest.chunk_hashes() {
        chunks.insert(hash.clone(), reader.read_chunk(&hash)?);
    }
    let checkpointed = Bundle { manifest, chunks };
    let plan = RestorePlan::from_bundle(&checkpointed, BTreeMap::new(), None)?;
    let first = apply_restore(&plan, &restored_root, RestoreOptions::default())?;
    assert_restored(&files, &restored_root)?;
    if first.restored.len() != files.len() {
        return Err(ZeroError::new(
            ErrorCode::Internal,
            "the first restore did not write every workspace file",
        ));
    }

    // A repeat restore must be a no-op: no duplicate effects.
    let second = apply_restore(&plan, &restored_root, RestoreOptions::default())?;
    if !second.restored.is_empty() || second.skipped_identical != plan.entries.len() as u64 {
        return Err(ZeroError::new(
            ErrorCode::Internal,
            format!(
                "the repeat restore was not a no-op: restored={} skipped={} entries={}",
                second.restored.len(),
                second.skipped_identical,
                plan.entries.len()
            ),
        ));
    }

    Ok(vec![
        format!("chunks={total_chunks}"),
        format!("interrupted_after={interrupted_after}"),
        format!("resume_written={}", finished.written),
        format!("resume_already_present={}", finished.already_present),
        format!("verified_chunks={}", verified.chunks),
        format!("restored_files={}", first.restored.len()),
        format!("skipped_identical={}", second.skipped_identical),
        "byte_identical=true".to_string(),
    ])
}

// ---------------------------------------------------------------------------
// Fixture 2: unreachable source.
// ---------------------------------------------------------------------------

fn fixture_unreachable(
    request: &TripRequest<'_>,
    dir: &Path,
    probe: &dyn SourceProbe,
) -> Result<Vec<String>> {
    if probe.availability() != SourceAvailability::Unreachable {
        return Err(ZeroError::new(
            ErrorCode::Internal,
            "the unreachable-source fixture needs an unreachable probe; the source reported reachable, so the fixture was not exercised",
        ));
    }

    let local_root = dir.join("local");
    let key = KeyPair::generate()?;
    let local = local_snapshot(request.now_ms, &key)?;
    let restored = snapshot::restore(
        &local,
        &local_root,
        key.public_key_b64().as_str(),
        request.now_ms,
    )?;
    let hash_before = snapshot::manifest_hash(&local)?;
    let entries_before = directory_entries(dir)?;

    let refused = attempt_pull(probe, request.source);
    let error = match refused {
        Ok(_) => {
            return Err(ZeroError::new(
                ErrorCode::Internal,
                "an unreachable source produced a silent success",
            ))
        }
        Err(error) => error,
    };
    if error.code() != ErrorCode::Unavailable {
        return Err(ZeroError::new(
            ErrorCode::Internal,
            format!(
                "an unreachable source was refused as `{}` instead of `{}`",
                error.code(),
                ErrorCode::Unavailable
            ),
        ));
    }
    if directory_entries(dir)? != entries_before {
        return Err(ZeroError::new(
            ErrorCode::Internal,
            "the refused transfer wrote into the target",
        ));
    }

    // The local snapshot must still verify and its component files must still
    // match the signed manifest.
    snapshot::verify(&local, key.public_key_b64().as_str())?;
    let hash_after = snapshot::manifest_hash(&local)?;
    if hash_before != hash_after {
        return Err(ZeroError::new(
            ErrorCode::TamperDetected,
            "the local snapshot changed after the refused transfer",
        ));
    }
    for (component, path) in &restored.components {
        let bytes = fs::read(path)?;
        if local.blobs.get(component) != Some(&bytes) {
            return Err(ZeroError::new(
                ErrorCode::TamperDetected,
                format!(
                    "the local `{}` component changed after the refusal",
                    component.as_str()
                ),
            ));
        }
    }

    Ok(vec![
        format!("refused_code={}", error.code()),
        format!("local_snapshot_hash={hash_after}"),
        format!("local_components={}", restored.components.len()),
        "local_snapshot_unchanged=true".to_string(),
        "target_writes=0".to_string(),
    ])
}

fn local_snapshot(now_ms: i64, key: &KeyPair) -> Result<Snapshot> {
    snapshot::create(
        PROJECT_ID,
        [
            ComponentBlob::new(Component::Session, b"session: local snapshot\n".to_vec()),
            ComponentBlob::new(Component::Kernel, b"kernel: local checkpoint\n".to_vec()),
            ComponentBlob::new(Component::Manifest, b"manifest: local workspace\n".to_vec()),
        ],
        now_ms,
        key,
    )
}

/// The transfer seam's fetch. With no socket, this is where availability is
/// consulted; it writes nothing on either path.
fn attempt_pull(probe: &dyn SourceProbe, source: &str) -> Result<Vec<u8>> {
    match probe.availability() {
        SourceAvailability::Unreachable => Err(ZeroError::new(
            ErrorCode::Unavailable,
            format!(
                "source `{source}` is unreachable; the target kept its local snapshot and did not start a transfer"
            ),
        )),
        SourceAvailability::Reachable => Ok(Vec::new()),
    }
}

fn directory_entries(dir: &Path) -> Result<BTreeSet<String>> {
    let mut entries = BTreeSet::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        entries.insert(entry.file_name().to_string_lossy().into_owned());
    }
    Ok(entries)
}

// ---------------------------------------------------------------------------
// Fixture 3: forced takeover.
// ---------------------------------------------------------------------------

fn fixture_forced_takeover(request: &TripRequest<'_>, dir: &Path) -> Result<Vec<String>> {
    let target_root = dir.join("target");
    let stale_root = dir.join("stale-restore");
    fs::create_dir_all(&target_root)?;

    let holder_a = HolderId::new("node-a")?;
    let holder_b = HolderId::new("node-b")?;
    let resource = format!("teleport/{}/workspace", safe_segment(request.id));
    let source_lease = Lease::new(&resource, holder_a.clone(), request.now_ms, LEASE_TTL_MS)?;
    let takeover_ms = source_lease.expires_ms;
    if source_lease.verify(takeover_ms).is_ok() {
        return Err(ZeroError::new(
            ErrorCode::Internal,
            "the forced takeover did not start from an expired source lease",
        ));
    }

    // The forced takeover advances the generation without a live source.
    let target_lease = handoff(&source_lease, holder_b, takeover_ms, LEASE_TTL_MS)?;
    if target_lease.generation <= source_lease.generation {
        return Err(ZeroError::new(
            ErrorCode::Internal,
            "the forced takeover did not advance the lease generation",
        ));
    }
    assert_can_write(&target_lease, target_lease.generation, takeover_ms)?;
    fs::write(target_root.join("owner.txt"), b"node-b")?;

    // The stale source cannot write, restore, or release.
    let stale_write = assert_can_write(&target_lease, source_lease.generation, takeover_ms);
    let stale_code = match stale_write {
        Ok(()) => {
            return Err(ZeroError::new(
                ErrorCode::Internal,
                "the stale source was allowed to write after the takeover",
            ))
        }
        Err(error) => error.code(),
    };
    if stale_code != ErrorCode::SessionLeaseHeld {
        return Err(ZeroError::new(
            ErrorCode::Internal,
            format!("the stale write was refused as `{stale_code}`, not `zero.ses.lease_held`"),
        ));
    }
    let stale_release = release(&target_lease, &holder_a);
    if stale_release.is_ok() {
        return Err(ZeroError::new(
            ErrorCode::Internal,
            "the stale source released the new holder's lease",
        ));
    }

    // A stale cursor may not replay effects; it must take a snapshot.
    let cursor = ResumeCursor {
        generation: source_lease.generation,
        sequence: 7,
    };
    let stale_resume = resume(&target_lease, &cursor, 9)?;
    if !stale_resume.snapshot || stale_resume.replays_effect(7) {
        return Err(ZeroError::new(
            ErrorCode::Internal,
            "the stale source's cursor could replay effects after the takeover",
        ));
    }

    let files = workspace_files();
    let plan = restore_plan(&files, request.now_ms)?;
    let refused = gated_restore(
        &target_lease,
        source_lease.generation,
        takeover_ms,
        &plan,
        &stale_root,
    );
    match refused {
        Ok(_) => {
            return Err(ZeroError::new(
                ErrorCode::Internal,
                "the stale source restored files after the takeover",
            ))
        }
        Err(error) if error.code() == ErrorCode::SessionLeaseHeld => {}
        Err(error) => return Err(error),
    }
    if stale_root.exists() {
        return Err(ZeroError::new(
            ErrorCode::Internal,
            "the refused stale restore created its target directory",
        ));
    }

    // The new holder may restore through the same gate.
    let written = gated_restore(
        &target_lease,
        target_lease.generation,
        takeover_ms,
        &plan,
        &target_root,
    )?;
    if written.restored.is_empty() {
        return Err(ZeroError::new(
            ErrorCode::Internal,
            "the new holder's restore wrote nothing",
        ));
    }
    assert_restored(&files, &target_root)?;

    Ok(vec![
        format!("old_generation={}", source_lease.generation),
        format!("new_generation={}", target_lease.generation),
        "forced_after_expiry=true".to_string(),
        format!("stale_write_code={stale_code}"),
        format!(
            "stale_release_code={}",
            stale_release.expect_err("checked above").code()
        ),
        "stale_resume_forces_snapshot=true".to_string(),
        "stale_restore_written=false".to_string(),
        format!("new_holder_restored_files={}", written.restored.len()),
    ])
}

fn gated_restore(
    lease: &Lease,
    generation: crate::fence::LeaseGeneration,
    now_ms: i64,
    plan: &RestorePlan,
    root: &Path,
) -> Result<RestoreReport> {
    assert_can_write(lease, generation, now_ms)?;
    apply_restore(plan, root, RestoreOptions::default())
}

// ---------------------------------------------------------------------------
// Fixture 4: return trip.
// ---------------------------------------------------------------------------

fn fixture_return_trip(request: &TripRequest<'_>, dir: &Path) -> Result<Vec<String>> {
    let first_root = dir.join("a-first");
    let middle_root = dir.join("b");
    let final_root = dir.join("a-again");
    let key_a = KeyPair::generate()?;
    let key_b = KeyPair::generate()?;

    let forward = PathMap::new(SOURCE_ROOT, TARGET_ROOT, true)?;
    let backward = PathMap::new(TARGET_ROOT, SOURCE_ROOT, false)?;
    let original = return_snapshot(request.now_ms, &key_a)?;

    let files = workspace_files();
    let plan = restore_plan(&files, request.now_ms)?;
    apply_restore(&plan, &first_root, RestoreOptions::default())?;
    assert_restored(&files, &first_root)?;

    // Leg 1: A -> B, re-signed for B's device key.
    let leg_one = remap_snapshot_report(&original, std::slice::from_ref(&forward), &key_b)?;
    if leg_one.remapped.is_empty() {
        return Err(ZeroError::new(
            ErrorCode::Internal,
            "the first leg remapped no component",
        ));
    }
    snapshot::verify(&leg_one.snapshot, key_b.public_key_b64().as_str())?;
    if snapshot::verify(&leg_one.snapshot, key_a.public_key_b64().as_str()).is_ok() {
        return Err(ZeroError::new(
            ErrorCode::Internal,
            "the first leg still verified under the source device key",
        ));
    }
    for component in crate::portability::REMAPPABLE_COMPONENTS {
        let bytes = leg_one.snapshot.blobs.get(&component).ok_or_else(|| {
            ZeroError::new(
                ErrorCode::Internal,
                format!(
                    "the first leg dropped the `{}` component",
                    component.as_str()
                ),
            )
        })?;
        let text = std::str::from_utf8(bytes).map_err(|_| {
            ZeroError::new(
                ErrorCode::TamperDetected,
                format!("the remapped `{}` is not UTF-8", component.as_str()),
            )
        })?;
        if text.contains(SOURCE_ROOT) {
            return Err(ZeroError::new(
                ErrorCode::Internal,
                format!(
                    "the first leg left the source root in `{}`",
                    component.as_str()
                ),
            ));
        }
    }
    apply_restore(&plan, &middle_root, RestoreOptions::default())?;
    assert_restored(&files, &middle_root)?;

    // Leg 2: B -> A, re-signed for A's device key.
    let leg_two =
        remap_snapshot_report(&leg_one.snapshot, std::slice::from_ref(&backward), &key_a)?;
    snapshot::verify(&leg_two.snapshot, key_a.public_key_b64().as_str())?;
    if snapshot::verify(&leg_two.snapshot, key_b.public_key_b64().as_str()).is_ok() {
        return Err(ZeroError::new(
            ErrorCode::Internal,
            "the return leg verified under the intermediate device key",
        ));
    }
    if leg_two.snapshot.blobs != original.blobs {
        return Err(ZeroError::new(
            ErrorCode::Internal,
            "the return trip did not restore the original components byte-identically",
        ));
    }
    if leg_two.snapshot.manifest.snapshot_id != original.manifest.snapshot_id {
        return Err(ZeroError::new(
            ErrorCode::Internal,
            "the return trip changed the snapshot id",
        ));
    }
    apply_restore(&plan, &final_root, RestoreOptions::default())?;
    assert_restored(&files, &final_root)?;

    // The first leg's generation must be stale on the return leg.
    let holder_a = HolderId::new("node-a")?;
    let holder_b = HolderId::new("node-b")?;
    let resource = format!("teleport/{}/workspace", safe_segment(request.id));
    let first_leg = Lease::new(&resource, holder_a.clone(), request.now_ms, LEASE_TTL_MS)?;
    let second_leg = handoff(&first_leg, holder_b, request.now_ms, LEASE_TTL_MS)?;
    let third_leg = handoff(&second_leg, holder_a, request.now_ms, LEASE_TTL_MS)?;
    let stale = assert_can_write(&third_leg, second_leg.generation, request.now_ms);
    let stale_code = match stale {
        Ok(()) => {
            return Err(ZeroError::new(
                ErrorCode::Internal,
                "the first leg's generation wrote after the return leg",
            ))
        }
        Err(error) => error.code(),
    };
    if stale_code != ErrorCode::SessionLeaseHeld {
        return Err(ZeroError::new(
            ErrorCode::Internal,
            format!("the stale generation was refused as `{stale_code}`"),
        ));
    }
    let stale_cursor = ResumeCursor {
        generation: second_leg.generation,
        sequence: 3,
    };
    let stale_resume = resume(&third_leg, &stale_cursor, 5)?;
    if !stale_resume.snapshot {
        return Err(ZeroError::new(
            ErrorCode::Internal,
            "the first leg's cursor could replay after the return leg",
        ));
    }
    assert_can_write(&third_leg, third_leg.generation, request.now_ms)?;

    Ok(vec![
        format!("first_leg_generation={}", second_leg.generation),
        format!("second_leg_generation={}", third_leg.generation),
        format!(
            "remapped={}",
            leg_one
                .remapped
                .iter()
                .map(|component| component.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ),
        "state_equal=true".to_string(),
        "identity_resigned=true".to_string(),
        format!("stale_generation_code={stale_code}"),
        "stale_resume_forces_snapshot=true".to_string(),
        "workspace_byte_identical=true".to_string(),
    ])
}

fn return_snapshot(now_ms: i64, key: &KeyPair) -> Result<Snapshot> {
    let session = format!("transcript: cwd={SOURCE_ROOT}\n").into_bytes();
    let kernel = format!("kernel: cwd={SOURCE_ROOT}\n").into_bytes();
    let manifest = format!("manifest: path={SOURCE_ROOT}\\src\\main.rs\n").into_bytes();
    snapshot::create(
        PROJECT_ID,
        [
            ComponentBlob::new(Component::Session, session),
            ComponentBlob::new(Component::Kernel, kernel),
            ComponentBlob::new(Component::Manifest, manifest),
        ],
        now_ms,
        key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const NOW: i64 = 1_700_000_000_000;

    fn request(root: &TempDir, direction: Direction) -> TripRequest<'_> {
        TripRequest {
            id: "trip-42",
            source: "node-a",
            target: "node-b",
            direction,
            root: root.path(),
            now_ms: NOW,
        }
    }

    fn full_report(root: &TempDir) -> TripMatrixReport {
        run_matrix(
            &request(root, Direction::Return),
            &ScriptedSource::unreachable(),
        )
    }

    fn evidence<'a>(outcome: &'a TripOutcome, key: &str) -> Option<&'a str> {
        outcome.evidence.iter().find_map(|entry| {
            let (name, value) = entry.split_once('=')?;
            (name == key).then_some(value)
        })
    }

    #[test]
    fn the_interrupted_fixture_resumes_byte_identically() {
        let root = TempDir::new().expect("tempdir");
        let report = full_report(&root);
        let outcome = report
            .outcome(Fixture::Interrupted)
            .expect("interrupted fixture");
        assert!(outcome.passed, "{:?}", outcome.notes);
        assert_eq!(evidence(outcome, "byte_identical"), Some("true"));
        assert_eq!(evidence(outcome, "interrupted_after"), Some("2"));
        assert_eq!(evidence(outcome, "resume_already_present"), Some("2"));

        let restored =
            fixture_dir(&request(&root, Direction::Return), Fixture::Interrupted).join("restored");
        assert_eq!(
            fs::read(restored.join("src/main.rs")).expect("main"),
            pattern(1300, 7)
        );
        assert_eq!(
            fs::read(restored.join("data/values.bin")).expect("values"),
            pattern(1200, 31)
        );
    }

    #[test]
    fn the_unreachable_fixture_refuses_and_keeps_the_local_snapshot() {
        let root = TempDir::new().expect("tempdir");
        let report = full_report(&root);
        let outcome = report
            .outcome(Fixture::UnreachableSource)
            .expect("unreachable fixture");
        assert!(outcome.passed, "{:?}", outcome.notes);
        assert_eq!(
            evidence(outcome, "refused_code"),
            Some(ErrorCode::Unavailable.as_str())
        );
        assert_eq!(evidence(outcome, "target_writes"), Some("0"));
        assert_eq!(evidence(outcome, "local_snapshot_unchanged"), Some("true"));
        assert!(fixture_dir(
            &request(&root, Direction::Return),
            Fixture::UnreachableSource
        )
        .join("local")
        .exists());
    }

    #[test]
    fn the_forced_takeover_fixture_blocks_the_stale_holder() {
        let root = TempDir::new().expect("tempdir");
        let report = full_report(&root);
        let outcome = report
            .outcome(Fixture::ForcedTakeover)
            .expect("takeover fixture");
        assert!(outcome.passed, "{:?}", outcome.notes);
        assert_eq!(evidence(outcome, "old_generation"), Some("1"));
        assert_eq!(evidence(outcome, "new_generation"), Some("2"));
        assert_eq!(
            evidence(outcome, "stale_write_code"),
            Some(ErrorCode::SessionLeaseHeld.as_str())
        );
        assert_eq!(evidence(outcome, "stale_restore_written"), Some("false"));

        let target =
            fixture_dir(&request(&root, Direction::Return), Fixture::ForcedTakeover).join("target");
        assert_eq!(
            fs::read(target.join("owner.txt")).expect("owner"),
            b"node-b"
        );
    }

    #[test]
    fn the_return_trip_fixture_restores_state_and_refuses_the_stale_generation() {
        let root = TempDir::new().expect("tempdir");
        let report = full_report(&root);
        let outcome = report.outcome(Fixture::ReturnTrip).expect("return fixture");
        assert!(outcome.passed, "{:?}", outcome.notes);
        assert_eq!(evidence(outcome, "state_equal"), Some("true"));
        assert_eq!(evidence(outcome, "identity_resigned"), Some("true"));
        assert_eq!(evidence(outcome, "first_leg_generation"), Some("2"));
        assert_eq!(evidence(outcome, "second_leg_generation"), Some("3"));
        assert_eq!(
            evidence(outcome, "stale_generation_code"),
            Some(ErrorCode::SessionLeaseHeld.as_str())
        );

        let final_root =
            fixture_dir(&request(&root, Direction::Return), Fixture::ReturnTrip).join("a-again");
        assert_eq!(
            fs::read(final_root.join("notes.txt")).expect("notes"),
            b"teleport trip matrix\n"
        );
    }

    #[test]
    fn the_failure_matrix_reports_ok_when_all_four_pass() {
        let root = TempDir::new().expect("tempdir");
        let report = full_report(&root);
        assert!(report.ok);
        assert_eq!(report.outcomes.len(), 4);
        assert!(report.outcomes.iter().all(|outcome| outcome.passed));
        assert_eq!(assert_all_four(&report), Ok(()));
    }

    #[test]
    fn a_skipped_fixture_flips_ok_and_is_named() {
        let root = TempDir::new().expect("tempdir");
        let report = run_matrix(
            &request(&root, Direction::Forward),
            &ScriptedSource::unreachable(),
        );
        assert_eq!(report.outcomes.len(), 3);
        assert!(!report.ok);
        assert!(matches!(
            assert_all_four(&report),
            Err(TripMatrixError::Missing(Fixture::ReturnTrip))
        ));
    }

    #[test]
    fn a_forced_failure_flips_ok_and_is_named() {
        let root = TempDir::new().expect("tempdir");
        let mut report = full_report(&root);
        assert!(report.ok);
        let outcome = report
            .outcomes
            .iter_mut()
            .find(|outcome| outcome.fixture == Fixture::ForcedTakeover)
            .expect("takeover outcome");
        outcome.passed = false;
        outcome.notes.push("injected fixture failure".to_string());
        report.recompute_ok();
        assert!(!report.ok);
        match assert_all_four(&report) {
            Err(TripMatrixError::Failed { fixture, notes }) => {
                assert_eq!(fixture, Fixture::ForcedTakeover);
                assert!(notes.iter().any(|note| note.contains("injected")));
            }
            other => panic!("unexpected gate result: {other:?}"),
        }
    }
}
