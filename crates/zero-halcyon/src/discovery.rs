//! Halcyon mode discovery and the workspace trust gate (HAL-01, HAL-02, HAL-12).
//!
//! Halcyon activates only when a `.halcyon-mode` file is present *and* the
//! workspace that owns it is trusted. Discovery is structural: it locates the
//! file and bounds its size. Parsing, signature verification, expiry, and
//! project binding live in [`crate::verify`] (T-HAL-02); [`activation`] here is
//! the structural, explicitly unverified path.
//!
//! Rules:
//!
//! - Distances are measured from the start directory: the directory itself is
//!   distance 0, its immediate child directories and its parent are distance 1,
//!   and each further ancestor adds one.
//! - The nearest `.halcyon-mode` wins. A unique candidate at the smallest
//!   distance is returned; two or more candidates at that distance are
//!   [`Discovery::Conflict`], which disables the mode with a reason instead of
//!   picking one. In particular, an immediate-child file and a parent file both
//!   sit at distance 1 and therefore conflict.
//! - Never follow a symlinked mode file or a symlinked directory in the walk.
//!   A link-like mode file or walk directory is refused with `zero.pol.denied`.
//!   A link-like immediate child is inspected and excluded: it cannot own this
//!   workspace's mode file, so it is never followed and never a candidate.
//! - When a home boundary is supplied, the start must be inside it and the walk
//!   stops at home, so an ancestor above home is never consulted.
//! - The trust gate runs before any file contents are read. An untrusted
//!   workspace is [`Activation::Inert`] even when a syntactically valid file is
//!   present (HAL-12).

use std::fs::{self, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use zero_types::{ErrorCode, ZeroError};

/// Name of the mode file.
pub const MODE_FILE_NAME: &str = ".halcyon-mode";

/// Upper bound used by callers that do not supply their own size cap.
pub const DEFAULT_MAX_MODE_FILE_BYTES: u64 = 64 * 1024;

/// The reason reported when discovery finds a file but trust refuses it.
pub const UNTRUSTED_REASON: &str = "workspace is not trusted";

/// A discovered `.halcyon-mode` file and the workspace root that owns it.
///
/// The root is the directory containing the file. Trust is evaluated against
/// this root, so a mode file can only ever enable the workspace it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeFile {
    path: PathBuf,
    root: PathBuf,
}

impl ModeFile {
    /// Canonical path of the `.halcyon-mode` file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Canonical directory that contains the file and is used for trust.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Read the mode file, refusing links, non-regular files, and anything
    /// larger than `max_bytes`.
    ///
    /// The metadata check is repeated before opening, and the read is capped at
    /// `max_bytes + 1` so a file that grows between the checks is still refused
    /// rather than partially accepted. Parsing and signature checks are
    /// deliberately out of scope (T-HAL-02).
    pub fn read_bounded(&self, max_bytes: u64) -> Result<Vec<u8>, ZeroError> {
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|error| io_error("cannot inspect the mode file", &self.path, error))?;
        if is_link_like(&metadata) {
            return Err(denied(format!(
                "{} is a symlink or reparse point; refusing to read the mode file",
                self.path.display()
            )));
        }
        if !metadata.is_file() {
            return Err(invalid(format!(
                "{} is not a regular file",
                self.path.display()
            )));
        }
        if metadata.len() > max_bytes {
            return Err(limit(format!(
                "{} is {} bytes, above the {} byte limit",
                self.path.display(),
                metadata.len(),
                max_bytes
            )));
        }

        let file = fs::File::open(&self.path)
            .map_err(|error| io_error("cannot open the mode file", &self.path, error))?;
        let mut bytes = Vec::new();
        file.take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| io_error("cannot read the mode file", &self.path, error))?;
        if bytes.len() as u64 > max_bytes {
            return Err(limit(format!(
                "{} grew past the {} byte limit while being read",
                self.path.display(),
                max_bytes
            )));
        }
        Ok(bytes)
    }
}

/// Result of the nearest-file search around the start directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Discovery {
    /// The unique nearest mode file, with the workspace root that contains it.
    Found(ModeFile),
    /// No mode file exists from the start directory up to the boundary.
    Absent,
    /// Two or more mode files sit at the same nearest distance. The mode stays
    /// disabled; `reason` explains the tie and `candidates` lists the paths.
    Conflict {
        /// Candidate mode-file paths, sorted for a deterministic report.
        candidates: Vec<PathBuf>,
        /// Human-readable reason exposed through [`Activation::reason`].
        reason: String,
    },
}

impl Discovery {
    /// The discovered file, when present.
    pub fn mode_file(&self) -> Option<&ModeFile> {
        match self {
            Discovery::Found(file) => Some(file),
            Discovery::Absent | Discovery::Conflict { .. } => None,
        }
    }

    /// True when a mode file was found. Trust has not been evaluated yet.
    pub fn is_found(&self) -> bool {
        matches!(self, Discovery::Found(_))
    }

    /// True when same-distance candidates prevented a unique choice.
    pub fn is_conflict(&self) -> bool {
        matches!(self, Discovery::Conflict { .. })
    }

    /// True when nothing was found.
    pub fn is_absent(&self) -> bool {
        matches!(self, Discovery::Absent)
    }

    /// Every candidate path at the nearest distance, sorted.
    ///
    /// One entry for [`Discovery::Found`], every conflicting path for
    /// [`Discovery::Conflict`], and empty for [`Discovery::Absent`].
    pub fn candidate_paths(&self) -> Vec<PathBuf> {
        match self {
            Discovery::Found(file) => vec![file.path().to_path_buf()],
            Discovery::Conflict { candidates, .. } => candidates.clone(),
            Discovery::Absent => Vec::new(),
        }
    }
}

/// Workspace trust decision. Implementations must be free of file reads:
/// `trusted` is consulted before any mode-file content is touched.
pub trait TrustGate {
    /// Whether the workspace rooted at `root` is trusted to enable the mode.
    fn trusted(&self, root: &Path) -> bool;
}

/// Default gate: nothing is trusted (HAL-12).
#[derive(Debug, Clone, Copy, Default)]
pub struct UntrustedWorkspace;

impl TrustGate for UntrustedWorkspace {
    fn trusted(&self, _root: &Path) -> bool {
        false
    }
}

/// Test and host helper: an explicit set of trusted, canonical workspace roots.
///
/// Matching is exact and does not inherit: trusting a parent directory does not
/// trust a project inside it, so a hostile sibling or child repository cannot
/// be enabled by a nearby trust decision.
#[derive(Debug, Clone, Default)]
pub struct TrustedRoots {
    roots: Vec<PathBuf>,
}

impl TrustedRoots {
    /// Build a set from roots, canonicalising each where possible.
    pub fn new<I, P>(roots: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        let roots = roots
            .into_iter()
            .map(|root| {
                let root = root.into();
                fs::canonicalize(&root).unwrap_or(root)
            })
            .collect();
        Self { roots }
    }

    /// The canonical roots held by this gate.
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }
}

impl TrustGate for TrustedRoots {
    fn trusted(&self, root: &Path) -> bool {
        let root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
        self.roots.iter().any(|trusted| trusted == &root)
    }
}

/// Final decision after discovery and trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Activation {
    /// No mode file was found, or same-distance candidates conflicted. The
    /// optional reason is present for a conflict (HAL-02).
    Disabled { reason: Option<String> },
    /// A mode file was found but the workspace is not trusted (HAL-12).
    Inert { reason: String },
    /// A unique nearest mode file was found in a trusted workspace.
    Enabled(ModeFile),
}

impl Activation {
    /// True only for [`Activation::Enabled`].
    pub fn is_enabled(&self) -> bool {
        matches!(self, Activation::Enabled(_))
    }

    /// True for [`Activation::Inert`].
    pub fn is_inert(&self) -> bool {
        matches!(self, Activation::Inert { .. })
    }

    /// True for [`Activation::Disabled`].
    pub fn is_disabled(&self) -> bool {
        matches!(self, Activation::Disabled { .. })
    }

    /// The reported reason: the conflict explanation when a tie disabled the
    /// mode, or the trust reason when the workspace is inert.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Activation::Disabled { reason } => reason.as_deref(),
            Activation::Inert { reason } => Some(reason),
            Activation::Enabled(_) => None,
        }
    }

    /// The enabled mode file, if any.
    pub fn mode_file(&self) -> Option<&ModeFile> {
        match self {
            Activation::Enabled(file) => Some(file),
            Activation::Disabled { .. } | Activation::Inert { .. } => None,
        }
    }
}

/// Apply the trust gate to a discovery result.
///
/// **Structural only.** This function does not read, parse, or verify the mode
/// file, so [`Activation::Enabled`] here means "a unique file exists in a
/// trusted root", not "the file is authentic". Use
/// [`crate::verify::activation_verified`] when the mode must be verified
/// (HAL-02, HAL-03, HAL-05); it keeps this path for T-HAL-01 tests and hosts
/// that need only the structural decision.
///
/// A conflict disables the mode with its tie reason and never consults the
/// gate. A found file in an untrusted workspace becomes [`Activation::Inert`];
/// the gate is consulted before any content is read, and an absent file is
/// [`Activation::Disabled`] without a reason.
pub fn activation<G: TrustGate + ?Sized>(discovery: Discovery, gate: &G) -> Activation {
    match discovery {
        Discovery::Absent => Activation::Disabled { reason: None },
        Discovery::Conflict { reason, .. } => Activation::Disabled {
            reason: Some(reason),
        },
        Discovery::Found(file) => {
            if gate.trusted(file.root()) {
                Activation::Enabled(file)
            } else {
                Activation::Inert {
                    reason: UNTRUSTED_REASON.to_string(),
                }
            }
        }
    }
}

/// Find the nearest `.halcyon-mode` around `start`.
///
/// Distances are measured from `start`: distance 0 is the directory itself,
/// distance 1 is every immediate child directory plus the parent, and each
/// further ancestor adds one. The first distance that yields candidates wins;
/// more than one candidate at that distance is [`Discovery::Conflict`].
///
/// `start` is canonicalised. When `home` is supplied it is canonicalised too,
/// `start` must live inside it, and the walk stops at `home` without ascending
/// above it. Every directory between the start and the found file is checked
/// for links, and the mode file itself must be a regular file.
pub fn discover(start: &Path, home: Option<&Path>) -> Result<Discovery, ZeroError> {
    let start_absolute = absolute(start)?;
    let start_metadata = fs::symlink_metadata(&start_absolute)
        .map_err(|error| io_error("cannot inspect the start directory", start, error))?;
    if is_link_like(&start_metadata) {
        return Err(denied(format!(
            "{} is a symlink or reparse point; the discovery walk does not follow it",
            start.display()
        )));
    }
    if !start_metadata.is_dir() {
        return Err(invalid(format!(
            "{} is not a directory",
            start.display()
        )));
    }

    // Check symlinked ancestors between the supplied path and the home
    // boundary. System-level links above home (for example `/var` on macOS)
    // are not part of the workspace and must not block discovery.
    reject_symlink_ancestors_within(&start_absolute, home)?;

    let start_canonical = fs::canonicalize(&start_absolute)
        .map_err(|error| io_error("cannot resolve the start directory", start, error))?;
    let home_canonical = match home {
        Some(home) => {
            let home_canonical = fs::canonicalize(home)
                .map_err(|error| io_error("cannot resolve the home boundary", home, error))?;
            if !home_canonical.is_dir() {
                return Err(invalid(format!(
                    "home boundary {} is not a directory",
                    home.display()
                )));
            }
            if !start_canonical.starts_with(&home_canonical) {
                return Err(invalid(format!(
                    "{} is outside the home boundary {}",
                    start.display(),
                    home.display()
                )));
            }
            Some(home_canonical)
        }
        None => None,
    };

    // Distance 0: the working directory itself. It is unique by definition, so
    // it wins without inspecting children or ancestors.
    if let Some(file) = inspect_mode_file(&start_canonical)? {
        return Ok(Discovery::Found(file));
    }

    // Distance 1: immediate child directories and the parent, when the home
    // boundary permits. Both sets are the same distance, so any two candidates
    // are a conflict rather than a silent pick.
    let mut candidates = Vec::new();
    for child in immediate_child_directories(&start_canonical)? {
        if let Some(file) = inspect_mode_file(&child)? {
            candidates.push(file);
        }
    }
    let parent = ancestor_within(&start_canonical, home_canonical.as_deref());
    if let Some(parent) = parent {
        if let Some(file) = inspect_mode_file(parent)? {
            candidates.push(file);
        }
    }
    if candidates.len() > 1 {
        return Ok(conflict_discovery(1, candidates));
    }
    if let Some(file) = candidates.pop() {
        return Ok(Discovery::Found(file));
    }

    // Distances 2..n: each ancestor level holds exactly one directory, so no tie
    // is possible. Stop at home or the filesystem root.
    let mut current = match parent {
        Some(parent) => parent.to_path_buf(),
        None => return Ok(Discovery::Absent),
    };
    while let Some(ancestor) = ancestor_within(&current, home_canonical.as_deref()) {
        if let Some(file) = inspect_mode_file(ancestor)? {
            return Ok(Discovery::Found(file));
        }
        current = ancestor.to_path_buf();
    }

    Ok(Discovery::Absent)
}

/// Inspect `<directory>/.halcyon-mode` without following links.
///
/// `Ok(None)` means the entry does not exist. A link-like or non-regular entry
/// is a typed error, so a malformed child is reported instead of ignored.
fn inspect_mode_file(directory: &Path) -> Result<Option<ModeFile>, ZeroError> {
    let candidate = directory.join(MODE_FILE_NAME);
    match fs::symlink_metadata(&candidate) {
        Ok(metadata) => {
            if is_link_like(&metadata) {
                return Err(denied(format!(
                    "{} is a symlink or reparse point; refusing a linked mode file",
                    candidate.display()
                )));
            }
            if !metadata.is_file() {
                return Err(invalid(format!(
                    "{} is not a regular file",
                    candidate.display()
                )));
            }
            Ok(Some(ModeFile {
                path: candidate,
                root: directory.to_path_buf(),
            }))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(
            "cannot inspect a mode file in the discovery walk",
            &candidate,
            error,
        )),
    }
}

/// Immediate child directories of `start`, excluding link-like entries.
///
/// A symlink or junction child is an inspection record, not an error and not a
/// candidate: it cannot own this workspace's mode file, and following it could
/// leave the workspace. An unreadable child, by contrast, is a typed error
/// because a nearer candidate cannot be ruled out.
fn immediate_child_directories(start: &Path) -> Result<Vec<PathBuf>, ZeroError> {
    let entries = fs::read_dir(start)
        .map_err(|error| io_error("cannot list immediate child directories", start, error))?;
    let mut children = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|error| io_error("cannot read a directory entry", start, error))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| io_error("cannot inspect an immediate child", &path, error))?;
        if is_link_like(&metadata) {
            continue;
        }
        if metadata.is_dir() {
            children.push(path);
        }
    }
    children.sort();
    Ok(children)
}

/// The parent of `path`, or `None` when `path` is the home boundary or a root.
fn ancestor_within<'a>(path: &'a Path, home: Option<&Path>) -> Option<&'a Path> {
    if home == Some(path) {
        return None;
    }
    path.parent()
}

fn conflict_discovery(distance: usize, candidates: Vec<ModeFile>) -> Discovery {
    let mut candidates: Vec<PathBuf> = candidates
        .into_iter()
        .map(|file| file.path().to_path_buf())
        .collect();
    candidates.sort();
    let listed = candidates
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Discovery::Conflict {
        reason: format!(
            "same-distance Halcyon mode files conflict at distance {distance} ({} candidates): {listed}; refusing to choose",
            candidates.len()
        ),
        candidates,
    }
}

fn absolute(path: &Path) -> Result<PathBuf, ZeroError> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let current = std::env::current_dir().map_err(|error| {
        invalid(format!(
            "cannot resolve the working directory for {}: {error}",
            path.display()
        ))
    })?;
    Ok(current.join(path))
}

/// Reject any symlink or reparse point among the ancestors of `path`.
/// Reject symlinked ancestors only between `path` and the home boundary.
///
/// System-level links above home (for example `/var` on macOS) are not part of
/// the workspace and must not disable discovery.
fn reject_symlink_ancestors_within(path: &Path, home: Option<&Path>) -> Result<(), ZeroError> {
    let Some(home) = home else {
        return Ok(());
    };
    let home = absolute(home)?;
    if !path.starts_with(&home) {
        return Ok(());
    }
    let mut current = Some(path);
    while let Some(dir) = current {
        if !dir.has_root() {
            break;
        }
        match fs::symlink_metadata(dir) {
            Ok(metadata) => {
                if is_link_like(&metadata) {
                    return Err(denied(format!(
                        "{} is a symlink or reparse point; the discovery walk does not follow it",
                        dir.display()
                    )));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(io_error(
                    "cannot inspect a directory in the discovery walk",
                    dir,
                    error,
                ));
            }
        }
        if dir == home {
            break;
        }
        current = dir.parent();
    }
    Ok(())
}

#[cfg(windows)]
fn is_link_like(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    /// `FILE_ATTRIBUTE_REPARSE_POINT`: junctions and other reparse points do not
    /// report `is_symlink()`, so they are refused explicitly.
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_link_like(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn io_error(context: &str, path: &Path, error: io::Error) -> ZeroError {
    let code = match error.kind() {
        io::ErrorKind::NotFound => ErrorCode::NotFound,
        io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        _ => ErrorCode::Io,
    };
    ZeroError::new(code, format!("{context} {}: {error}", path.display()))
}

fn denied(message: String) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyDenied, message)
}

fn invalid(message: String) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn limit(message: String) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    struct Fixture {
        _dir: TempDir,
        home: PathBuf,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home");
        fs::create_dir_all(&home).expect("home directory");
        Fixture { _dir: dir, home }
    }

    fn write(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("write fixture file");
    }

    fn canonical(path: &Path) -> PathBuf {
        fs::canonicalize(path).expect("canonical fixture path")
    }

    fn found(discovery: Discovery) -> ModeFile {
        match discovery {
            Discovery::Found(file) => file,
            Discovery::Absent => panic!("expected a mode file"),
            Discovery::Conflict { candidates, reason } => {
                panic!("expected a mode file, got a conflict at {candidates:?}: {reason}")
            }
        }
    }

    #[cfg(unix)]
    fn try_symlink_file(target: &Path, link: &Path) -> bool {
        std::os::unix::fs::symlink(target, link).is_ok()
    }

    #[cfg(windows)]
    fn try_symlink_file(target: &Path, link: &Path) -> bool {
        std::os::windows::fs::symlink_file(target, link).is_ok()
    }

    #[cfg(not(any(unix, windows)))]
    fn try_symlink_file(_target: &Path, _link: &Path) -> bool {
        false
    }

    #[cfg(unix)]
    fn try_symlink_dir(target: &Path, link: &Path) -> bool {
        std::os::unix::fs::symlink(target, link).is_ok()
    }

    #[cfg(windows)]
    fn try_symlink_dir(target: &Path, link: &Path) -> bool {
        std::os::windows::fs::symlink_dir(target, link).is_ok()
    }

    #[cfg(not(any(unix, windows)))]
    fn try_symlink_dir(_target: &Path, _link: &Path) -> bool {
        false
    }

    #[test]
    fn nearest_mode_file_wins_over_an_ancestor() {
        let fixture = fixture();
        let child = fixture.home.join("child");
        let deep = child.join("deep");
        fs::create_dir_all(&deep).expect("deep directory");
        write(&fixture.home.join(MODE_FILE_NAME), b"outer");
        write(&child.join(MODE_FILE_NAME), b"inner");

        let file = found(discover(&deep, Some(&fixture.home)).expect("discovery"));

        assert_eq!(file.path(), canonical(&child.join(MODE_FILE_NAME)));
        assert_eq!(file.root(), canonical(&child));
        assert_eq!(file.read_bounded(64).expect("read"), b"inner");
    }

    #[test]
    fn an_immediate_child_is_found_and_enabled_when_trusted() {
        let fixture = fixture();
        let child = fixture.home.join("child-project");
        fs::create_dir_all(&child).expect("child project");
        write(&child.join(MODE_FILE_NAME), b"mode = halcyon\n");

        let discovery = discover(&fixture.home, Some(&fixture.home)).expect("discovery");

        assert_eq!(
            discovery.candidate_paths(),
            vec![canonical(&child.join(MODE_FILE_NAME))]
        );
        let file = found(discovery);
        assert_eq!(file.root(), canonical(&child));

        let activation = activation(Discovery::Found(file), &TrustedRoots::new([child.clone()]));
        assert!(activation.is_enabled());
        assert_eq!(activation.mode_file().expect("enabled").root(), canonical(&child));
    }

    #[test]
    fn the_working_directory_beats_a_child_and_an_ancestor() {
        let fixture = fixture();
        let child = fixture.home.join("child");
        fs::create_dir_all(&child).expect("child");
        write(&fixture.home.join(MODE_FILE_NAME), b"working-directory");
        write(&child.join(MODE_FILE_NAME), b"child");
        write(
            &fixture.home.parent().expect("parent").join(MODE_FILE_NAME),
            b"ancestor",
        );

        let file = found(discover(&fixture.home, Some(&fixture.home)).expect("discovery"));

        assert_eq!(file.path(), canonical(&fixture.home.join(MODE_FILE_NAME)));
        assert_eq!(
            file.read_bounded(64).expect("read"),
            b"working-directory"
        );
    }

    #[test]
    fn two_immediate_children_are_a_conflict_without_reading_content() {
        let fixture = fixture();
        let first = fixture.home.join("a-project");
        let second = fixture.home.join("b-project");
        fs::create_dir_all(&first).expect("first child");
        fs::create_dir_all(&second).expect("second child");
        write(&first.join(MODE_FILE_NAME), b"first");
        write(&second.join(MODE_FILE_NAME), b"second");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [first.join(MODE_FILE_NAME), second.join(MODE_FILE_NAME)] {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).expect("chmod");
            }
        }

        // Conflict detection is metadata-only, so the two unreadable files still
        // produce a conflict instead of a content error.
        let discovery = discover(&fixture.home, Some(&fixture.home)).expect("discovery");
        assert!(discovery.is_conflict());
        let mut expected = vec![
            canonical(&first.join(MODE_FILE_NAME)),
            canonical(&second.join(MODE_FILE_NAME)),
        ];
        expected.sort();
        assert_eq!(discovery.candidate_paths(), expected);

        let activation = activation(discovery, &TrustedRoots::new([fixture.home.clone()]));

        assert!(activation.is_disabled());
        let reason = activation.reason().expect("conflict reason");
        assert!(reason.contains("same-distance"), "{reason}");
        assert!(reason.contains("2 candidates"), "{reason}");
        assert!(activation.mode_file().is_none());
    }

    #[test]
    fn a_child_and_the_parent_at_distance_one_conflict() {
        let fixture = fixture();
        let work = fixture.home.join("work");
        let sub = work.join("sub");
        fs::create_dir_all(&sub).expect("nested child");
        write(&fixture.home.join(MODE_FILE_NAME), b"parent");
        write(&sub.join(MODE_FILE_NAME), b"child");

        let discovery = discover(&work, Some(&fixture.home)).expect("discovery");

        // The parent and the immediate child both sit at distance 1; HAL-01
        // makes that a conflict rather than a silent parent-first pick.
        assert!(discovery.is_conflict());
        assert_eq!(discovery.candidate_paths().len(), 2);
        let activation = activation(discovery, &TrustedRoots::new([fixture.home.clone()]));
        assert!(activation.is_disabled());
        assert!(
            activation
                .reason()
                .expect("reason")
                .contains("same-distance"),
            "{:?}",
            activation.reason()
        );
    }

    #[test]
    fn a_symlinked_child_is_not_followed() {
        let fixture = fixture();
        let outside = fixture
            .home
            .parent()
            .expect("parent")
            .join("outside-child");
        fs::create_dir_all(&outside).expect("outside child");
        write(&outside.join(MODE_FILE_NAME), b"outside");
        let link = fixture.home.join("linked-child");
        if !try_symlink_dir(&outside, &link) {
            eprintln!("skipped: this host does not allow creating directory symlinks");
            return;
        }

        let discovery = discover(&fixture.home, Some(&fixture.home)).expect("discovery");

        assert!(
            discovery.is_absent(),
            "a linked child must not contribute a candidate: {discovery:?}"
        );
        assert!(!activation(discovery, &TrustedRoots::new([outside])).is_enabled());
    }

    #[cfg(windows)]
    #[test]
    fn a_junction_child_is_not_followed() {
        use std::process::Command;

        let fixture = fixture();
        let outside = fixture
            .home
            .parent()
            .expect("parent")
            .join("outside-child");
        fs::create_dir_all(&outside).expect("outside child");
        write(&outside.join(MODE_FILE_NAME), b"outside");
        let junction = fixture.home.join("junction-child");
        let output = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&outside)
            .output()
            .expect("run mklink");
        if !output.status.success() || !junction.exists() {
            eprintln!(
                "skipped: mklink /J unavailable: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let discovery = discover(&fixture.home, Some(&fixture.home)).expect("discovery");
        let _ = fs::remove_dir(&junction);

        assert!(
            discovery.is_absent(),
            "a junction child must not contribute a candidate: {discovery:?}"
        );
    }

    #[test]
    fn an_untrusted_child_stays_inert() {
        let fixture = fixture();
        let child = fixture.home.join("child");
        fs::create_dir_all(&child).expect("child");
        write(&child.join(MODE_FILE_NAME), b"mode = halcyon\n");
        let discovery = discover(&fixture.home, Some(&fixture.home)).expect("discovery");
        assert!(discovery.is_found());

        // Trusting the parent does not extend to the child workspace.
        let trusted_parent = activation(discovery.clone(), &TrustedRoots::new([fixture.home.clone()]));
        assert!(trusted_parent.is_inert());
        assert!(!trusted_parent.is_enabled());
        assert_eq!(trusted_parent.reason(), Some(UNTRUSTED_REASON));

        let default_gate = activation(discovery, &UntrustedWorkspace);
        assert!(default_gate.is_inert());
    }

    #[test]
    fn absent_everywhere_stays_disabled() {
        let fixture = fixture();
        let deep = fixture.home.join("a").join("b");
        fs::create_dir_all(&deep).expect("deep directory");
        let discovery = discover(&deep, Some(&fixture.home)).expect("discovery");

        assert!(discovery.is_absent());
        assert!(discovery.candidate_paths().is_empty());
        let activation = activation(discovery, &TrustedRoots::new([fixture.home.clone()]));
        assert!(activation.is_disabled());
        assert_eq!(activation.reason(), None);
        assert!(activation.mode_file().is_none());
    }

    #[test]
    fn a_missing_mode_file_is_absent_not_an_error() {        let fixture = fixture();
        let deep = fixture.home.join("a").join("b");
        fs::create_dir_all(&deep).expect("deep directory");

        assert_eq!(
            discover(&deep, Some(&fixture.home)).expect("discovery"),
            Discovery::Absent
        );
    }

    #[test]
    fn a_symlinked_mode_file_is_rejected_and_reported() {
        let fixture = fixture();
        let real = fixture.home.join("real-mode");
        write(&real, b"mode");
        let link = fixture.home.join(MODE_FILE_NAME);
        if !try_symlink_file(&real, &link) {
            // Creating symlinks needs developer mode or an elevated Windows
            // session; the refusal path is covered on hosts that allow it.
            eprintln!("skipped: this host does not allow creating file symlinks");
            return;
        }

        let error = discover(&fixture.home, Some(&fixture.home)).expect_err("symlink refused");

        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("symlink"), "{}", error.message());
        assert!(error.message().contains(MODE_FILE_NAME));
    }

    #[test]
    fn a_symlinked_directory_in_the_walk_is_rejected() {
        let fixture = fixture();
        let real = fixture.home.join("real");
        let sub = real.join("sub");
        fs::create_dir_all(&sub).expect("real subtree");
        write(&sub.join(MODE_FILE_NAME), b"hidden");
        let link = fixture.home.join("link");
        if !try_symlink_dir(&real, &link) {
            eprintln!("skipped: this host does not allow creating directory symlinks");
            return;
        }

        let error = discover(&link.join("sub"), Some(&fixture.home)).expect_err("symlink refused");

        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("symlink"), "{}", error.message());
    }

    #[cfg(windows)]
    #[test]
    fn a_junction_directory_in_the_walk_is_rejected() {
        use std::process::Command;

        let fixture = fixture();
        let real = fixture.home.join("real");
        let sub = real.join("sub");
        fs::create_dir_all(&sub).expect("real subtree");
        write(&sub.join(MODE_FILE_NAME), b"hidden");
        let junction = fixture.home.join("junction");
        // Junctions need no elevation, unlike symlinks, and Rust reports them
        // as reparse points rather than `is_symlink`.
        let output = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&real)
            .output()
            .expect("run mklink");
        if !output.status.success() || !junction.exists() {
            eprintln!(
                "skipped: mklink /J unavailable: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let error = discover(&junction.join("sub"), Some(&fixture.home))
            .expect_err("junction refused");
        let _ = fs::remove_dir(&junction);

        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(
            error.message().contains("reparse point") || error.message().contains("symlink"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn the_home_boundary_stops_the_walk() {
        let fixture = fixture();
        let deep = fixture.home.join("a").join("b");
        fs::create_dir_all(&deep).expect("deep directory");
        // Above home: this file must never be consulted.
        write(
            &fixture.home.parent().expect("parent").join(MODE_FILE_NAME),
            b"above-home",
        );

        assert_eq!(
            discover(&deep, Some(&fixture.home)).expect("discovery"),
            Discovery::Absent
        );
    }

    #[test]
    fn a_start_outside_home_is_refused() {
        let fixture = fixture();
        let outside = fixture
            .home
            .parent()
            .expect("parent")
            .join("outside-project");
        fs::create_dir_all(&outside).expect("outside directory");

        let error = discover(&outside, Some(&fixture.home)).expect_err("outside home refused");

        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("outside the home boundary"));
    }

    #[test]
    fn an_untrusted_workspace_is_inert_even_with_a_valid_file() {
        let fixture = fixture();
        write(&fixture.home.join(MODE_FILE_NAME), b"mode = halcyon\n");
        let discovery = discover(&fixture.home, Some(&fixture.home)).expect("discovery");
        assert!(discovery.is_found());

        let activation = activation(discovery, &UntrustedWorkspace);

        assert!(!activation.is_enabled());
        assert!(activation.is_inert());
        assert_eq!(activation.reason(), Some(UNTRUSTED_REASON));
        assert!(activation.mode_file().is_none());
    }

    #[test]
    fn a_trusted_workspace_with_a_file_enables_the_mode() {
        let fixture = fixture();
        write(&fixture.home.join(MODE_FILE_NAME), b"mode = halcyon\n");
        let gate = TrustedRoots::new([fixture.home.clone()]);

        let activation = activation(
            discover(&fixture.home, Some(&fixture.home)).expect("discovery"),
            &gate,
        );

        assert!(activation.is_enabled());
        assert_eq!(
            activation.mode_file().expect("enabled file").path(),
            canonical(&fixture.home.join(MODE_FILE_NAME))
        );
    }

    #[test]
    fn a_hostile_repo_cannot_flip_the_gate() {
        let fixture = fixture();
        let hostile = fixture
            .home
            .parent()
            .expect("parent")
            .join("hostile-repo");
        fs::create_dir_all(&hostile).expect("hostile directory");
        write(&hostile.join(MODE_FILE_NAME), b"mode = halcyon\nsigned = true\n");
        let trusted_project = fixture.home.join("my-project");
        fs::create_dir_all(&trusted_project).expect("trusted project");
        let gate = TrustedRoots::new([trusted_project]);

        assert!(!gate.trusted(&hostile));
        assert!(!UntrustedWorkspace.trusted(&hostile));

        let activation = activation(discover(&hostile, None).expect("discovery"), &gate);

        assert!(!activation.is_enabled());
        assert!(activation.is_inert());
        assert_eq!(activation.reason(), Some(UNTRUSTED_REASON));
    }

    #[test]
    fn an_oversized_mode_file_is_refused() {
        let fixture = fixture();
        write(&fixture.home.join(MODE_FILE_NAME), b"0123456789");
        let file = found(discover(&fixture.home, Some(&fixture.home)).expect("discovery"));

        let error = file.read_bounded(4).expect_err("oversized file refused");

        assert_eq!(error.code(), ErrorCode::LimitExceeded);
        assert!(error.message().contains("limit"));
    }

    #[test]
    fn a_mode_file_exactly_at_the_limit_is_read() {
        let fixture = fixture();
        write(&fixture.home.join(MODE_FILE_NAME), b"0123456789");
        let file = found(discover(&fixture.home, Some(&fixture.home)).expect("discovery"));

        assert_eq!(file.read_bounded(10).expect("read"), b"0123456789");
        assert!(file.read_bounded(0).is_err());
    }

    #[test]
    fn a_directory_named_like_a_mode_file_is_refused() {
        let fixture = fixture();
        fs::create_dir_all(fixture.home.join(MODE_FILE_NAME)).expect("mode directory");

        let error = discover(&fixture.home, Some(&fixture.home)).expect_err("directory refused");

        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("not a regular file"));
    }

    #[test]
    fn a_directory_named_like_a_mode_file_in_a_child_is_refused() {
        let fixture = fixture();
        let child = fixture.home.join("child");
        fs::create_dir_all(child.join(MODE_FILE_NAME)).expect("mode directory in child");

        let error = discover(&fixture.home, Some(&fixture.home)).expect_err("directory refused");

        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_child_is_a_typed_error() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = fixture();
        let child = fixture.home.join("child");
        fs::create_dir_all(&child).expect("child");
        fs::set_permissions(&child, fs::Permissions::from_mode(0o000)).expect("chmod");

        let error = discover(&fixture.home, Some(&fixture.home))
            .expect_err("unreadable child is not ignored");

        assert_eq!(error.code(), ErrorCode::PermissionDenied);
        fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).expect("restore mode");
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_mode_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = fixture();
        let path = fixture.home.join(MODE_FILE_NAME);
        write(&path, b"mode = halcyon\n");
        let file = found(discover(&fixture.home, Some(&fixture.home)).expect("discovery"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).expect("chmod");

        let error = file.read_bounded(64).expect_err("unreadable file refused");

        assert_eq!(error.code(), ErrorCode::PermissionDenied);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("restore mode");
    }

    #[cfg(unix)]
    #[test]
    fn an_untrusted_file_is_never_opened() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = fixture();
        let path = fixture.home.join(MODE_FILE_NAME);
        write(&path, b"mode = halcyon\n");
        let discovery = discover(&fixture.home, Some(&fixture.home)).expect("discovery");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).expect("chmod");

        // The gate is evaluated before any read, so an unreadable but present
        // file still yields a clean Inert result rather than a read error.
        let activation = activation(discovery, &UntrustedWorkspace);

        assert!(activation.is_inert());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("restore mode");
    }

    #[test]
    fn a_missing_start_directory_is_a_typed_error() {
        let fixture = fixture();
        let missing = fixture.home.join("missing");

        let error = discover(&missing, Some(&fixture.home)).expect_err("missing start refused");

        assert_eq!(error.code(), ErrorCode::NotFound);
    }

    #[test]
    fn trusted_roots_match_exactly_and_do_not_inherit() {
        let fixture = fixture();
        let trusted = fixture.home.join("trusted");
        let child = trusted.join("child");
        fs::create_dir_all(&child).expect("child");
        let gate = TrustedRoots::new([trusted.clone()]);

        assert!(gate.trusted(&trusted));
        assert!(!gate.trusted(&child));
        assert!(!gate.trusted(&fixture.home));
    }
}
