//! Archive safety (WEB-10, WEB-18).
//!
//! Untrusted ZIP archives are read in two stages. [`inspect`] walks the central
//! directory without extracting anything and refuses the whole archive on the
//! first violation: too many entries, too many bytes, an entry that declares
//! more than its share, a compression-ratio bomb, an unsafe name, a link, an
//! encrypted entry, or an unsupported compression method. [`extract`] repeats
//! that validation and then copies each file through a counting reader into the
//! caller's destination, so a header that lies about its size is still bounded
//! by the actual byte count.
//!
//! Names are validated by components, never by string prefix. Absolute paths,
//! drive and UNC prefixes, `..`, `.`, backslashes, NUL bytes, and names deeper
//! than the limit are refused. Symbolic links, hard-link-like entries (any
//! unix type that is not a regular file or directory), encrypted entries, and
//! compression methods Zero does not read are refused. Nothing is ever written
//! outside the destination: every parent directory is created one component at
//! a time without following a link, files are opened with `create_new`, and a
//! path that collides after case folding is rejected.
//!
//! On a mid-extraction refusal the files already written stay inside the
//! destination and the partially written current file is removed best-effort.
//! The failure report lists what was written before the refusal. Cleanup is
//! intentionally limited to the destination; no recursive delete runs on
//! caller paths.

use std::collections::HashSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Seek, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use zero_types::error::{ErrorCode, ZeroError};

/// Unix file-type mask (`S_IFMT`).
const S_IFMT: u32 = 0o170_000;
/// Unix regular file (`S_IFREG`).
const S_IFREG: u32 = 0o100_000;
/// Unix directory (`S_IFDIR`).
const S_IFDIR: u32 = 0o040_000;
/// Unix symbolic link (`S_IFLNK`).
const S_IFLNK: u32 = 0o120_000;

/// Conservative per-archive limits.
///
/// The defaults are sized for documents fetched from the web, not for software
/// distribution archives: 1,024 entries, 256 MiB declared in total, 64 MiB per
/// entry, a 100:1 expansion ratio, and 16 path components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveLimits {
    /// Maximum number of central-directory entries, including directories.
    pub max_entries: usize,
    /// Maximum sum of declared uncompressed sizes.
    pub max_total_bytes: u64,
    /// Maximum declared uncompressed size of one entry.
    pub max_entry_bytes: u64,
    /// Maximum uncompressed-to-compressed ratio for one entry (`100` = 100:1).
    pub max_compression_ratio: u64,
    /// Maximum number of path components in one entry name.
    pub max_path_depth: usize,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_entries: 1_024,
            max_total_bytes: 256 * 1024 * 1024,
            max_entry_bytes: 64 * 1024 * 1024,
            max_compression_ratio: 100,
            max_path_depth: 16,
        }
    }
}

/// One refusal reason with the values that triggered it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArchiveError {
    /// The archive holds more entries than the limit allows.
    #[error("archive has {entries} entries, limit is {limit}")]
    EntryCount { entries: usize, limit: usize },
    /// The declared uncompressed total is over the limit.
    #[error("archive declares {declared} bytes in total, limit is {limit}")]
    TotalSize { declared: u64, limit: u64 },
    /// One entry declares more bytes than the per-entry limit.
    #[error("entry `{name}` declares {declared} bytes, limit is {limit}")]
    EntrySize {
        name: String,
        declared: u64,
        limit: u64,
    },
    /// One entry expands beyond the configured compression ratio.
    #[error(
        "entry `{name}` expands to {actual} bytes from {compressed} compressed bytes \
         (ratio {ratio}:1), limit is {limit}:1"
    )]
    CompressionRatio {
        name: String,
        actual: u64,
        compressed: u64,
        ratio: u64,
        limit: u64,
    },
    /// The entry name is absolute or uses a drive, UNC, or stream prefix.
    #[error("entry `{name}` has an absolute, drive, or stream path prefix")]
    AbsolutePath { name: String },
    /// The entry name contains a `..` component.
    #[error("entry `{name}` contains a parent (`..`) component")]
    ParentTraversal { name: String },
    /// The entry name contains a `.` component.
    #[error("entry `{name}` contains a `.` component")]
    DotComponent { name: String },
    /// The entry name uses a backslash as a separator.
    #[error("entry `{name}` uses a backslash as a path separator")]
    BackslashSeparator { name: String },
    /// The entry name contains a NUL byte.
    #[error("entry `{name}` contains a NUL byte")]
    NulByte { name: String },
    /// The entry name is empty, has an empty component, or cannot be a path.
    #[error("entry `{name}` is not a usable relative path")]
    MalformedPath { name: String },
    /// The entry name is deeper than the path limit.
    #[error("entry `{name}` is {depth} components deep, limit is {limit}")]
    PathTooDeep {
        name: String,
        depth: usize,
        limit: usize,
    },
    /// The entry is a symbolic link.
    #[error("entry `{name}` is a symbolic link")]
    Symlink { name: String },
    /// The entry is a device, socket, FIFO, or another non-regular type.
    #[error("entry `{name}` has special unix mode {mode:#o}, not a regular file or directory")]
    SpecialFile { name: String, mode: u32 },
    /// The entry is encrypted.
    #[error("entry `{name}` is encrypted")]
    Encrypted { name: String },
    /// The entry uses a compression method this build cannot read.
    #[error("entry `{name}` uses unsupported compression method `{method}`")]
    UnsupportedMethod { name: String, method: String },
    /// Two entries collide after case folding.
    #[error("entry `{name}` collides with another entry after case folding")]
    DuplicatePath { name: String },
    /// A planned file and a planned directory occupy the same path.
    #[error("entry `{name}` conflicts with a file or directory in the extraction plan")]
    PathConflict { name: String },
    /// The entry name is not valid UTF-8.
    #[error("entry {index} has a name that is not valid UTF-8")]
    NonUtf8Name { index: usize },
    /// The destination already holds the path, or holds a link where a directory is needed.
    #[error("destination conflict at `{path}`")]
    DestinationConflict { path: String },
    /// The destination contains a symbolic link on the extraction path.
    #[error("destination `{path}` is a symbolic link; refusing to write through it")]
    DestinationSymlink { path: String },
    /// The archive structure could not be parsed.
    #[error("archive is malformed: {detail}")]
    Malformed { detail: String },
    /// Reading the archive source or writing the destination failed.
    #[error("archive I/O failed: {detail}")]
    Io { detail: String },
}

impl ArchiveError {
    /// Stable wire code for this refusal.
    pub fn code(&self) -> ErrorCode {
        match self {
            ArchiveError::EntryCount { .. }
            | ArchiveError::TotalSize { .. }
            | ArchiveError::EntrySize { .. }
            | ArchiveError::CompressionRatio { .. }
            | ArchiveError::PathTooDeep { .. } => ErrorCode::LimitExceeded,
            ArchiveError::AbsolutePath { .. }
            | ArchiveError::ParentTraversal { .. }
            | ArchiveError::DotComponent { .. }
            | ArchiveError::BackslashSeparator { .. }
            | ArchiveError::NulByte { .. }
            | ArchiveError::MalformedPath { .. }
            | ArchiveError::Symlink { .. }
            | ArchiveError::SpecialFile { .. }
            | ArchiveError::DuplicatePath { .. }
            | ArchiveError::PathConflict { .. }
            | ArchiveError::DestinationSymlink { .. } => ErrorCode::PolicyDenied,
            ArchiveError::Encrypted { .. } | ArchiveError::UnsupportedMethod { .. } => {
                ErrorCode::Unsupported
            }
            ArchiveError::NonUtf8Name { .. } | ArchiveError::Malformed { .. } => ErrorCode::Corrupt,
            ArchiveError::DestinationConflict { .. } => ErrorCode::AlreadyExists,
            ArchiveError::Io { .. } => ErrorCode::Io,
        }
    }

    /// Convert to the shared typed error, including the code's remediation.
    pub fn into_zero_error(self) -> ZeroError {
        ZeroError::new(self.code(), self.to_string())
    }
}

impl From<ArchiveError> for ZeroError {
    fn from(error: ArchiveError) -> Self {
        error.into_zero_error()
    }
}

/// Successful central-directory inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveReport {
    /// Every entry, in central-directory order.
    pub entries: Vec<ArchiveEntryInfo>,
    /// Sum of declared uncompressed sizes (directories declare zero).
    pub total_declared_bytes: u64,
    /// Largest declared uncompressed-to-compressed ratio in the archive.
    pub max_compression_ratio: u64,
    /// Deepest entry path in components.
    pub max_path_depth: usize,
}

impl ArchiveReport {
    /// Number of entries, including directories.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Number of regular-file entries.
    pub fn file_count(&self) -> usize {
        self.entries.iter().filter(|entry| !entry.is_dir).count()
    }

    /// Number of directory entries.
    pub fn directory_count(&self) -> usize {
        self.entries.iter().filter(|entry| entry.is_dir).count()
    }
}

/// One inspected entry. No entry data is read while building this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntryInfo {
    /// Entry name exactly as written in the central directory.
    pub name: String,
    /// Whether the entry is a directory.
    pub is_dir: bool,
    /// Declared uncompressed size.
    pub declared_size: u64,
    /// Declared compressed size.
    pub compressed_size: u64,
    /// Declared compression ratio, rounded up.
    pub compression_ratio: u64,
    /// Unix mode from the external attributes, when the writer supplied one.
    pub unix_mode: Option<u32>,
    /// Number of path components.
    pub depth: usize,
}

/// Files and directories written by [`extract`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtractionReport {
    /// Paths written, relative to the destination, in archive order.
    pub extracted: Vec<PathBuf>,
    /// Directories actually created (implicit parents are not listed).
    pub directories_created: usize,
    /// Bytes written across all files.
    pub bytes_written: u64,
}

/// A refusal during extraction, plus everything written before it.
///
/// Files listed in [`Self::extracted`] are complete and remain in the
/// destination. The current partially written file is removed best-effort.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractionError {
    reason: ArchiveError,
    extracted: Vec<PathBuf>,
    bytes_written: u64,
}

impl ExtractionError {
    fn new(reason: ArchiveError, extracted: Vec<PathBuf>, bytes_written: u64) -> Self {
        Self {
            reason,
            extracted,
            bytes_written,
        }
    }

    /// The refusal reason.
    pub fn reason(&self) -> &ArchiveError {
        &self.reason
    }

    /// Stable wire code of the refusal.
    pub fn code(&self) -> ErrorCode {
        self.reason.code()
    }

    /// Complete files written before the refusal, relative to the destination.
    pub fn extracted(&self) -> &[PathBuf] {
        &self.extracted
    }

    /// Bytes accepted before the refusal, including a removed partial file.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Convert to the shared typed error, including the code's remediation.
    pub fn into_zero_error(self) -> ZeroError {
        self.reason.into_zero_error()
    }
}

impl fmt::Display for ExtractionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} ({} file(s), {} byte(s) written before the refusal)",
            self.reason,
            self.extracted.len(),
            self.bytes_written
        )
    }
}

impl std::error::Error for ExtractionError {}

impl From<ExtractionError> for ZeroError {
    fn from(error: ExtractionError) -> Self {
        error.into_zero_error()
    }
}

/// Either an in-memory archive or a filesystem path.
///
/// `&[u8]`, `&Vec<u8>`, `&Path`, and `&PathBuf` convert into this type.
#[derive(Debug, Clone, Copy)]
pub enum ArchiveSource<'a> {
    /// Archive bytes already in memory.
    Bytes(&'a [u8]),
    /// A file that is opened read-only.
    Path(&'a Path),
}

impl<'a> From<&'a [u8]> for ArchiveSource<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        ArchiveSource::Bytes(bytes)
    }
}

impl<'a> From<&'a Vec<u8>> for ArchiveSource<'a> {
    fn from(bytes: &'a Vec<u8>) -> Self {
        ArchiveSource::Bytes(bytes.as_slice())
    }
}

impl<'a> From<&'a Path> for ArchiveSource<'a> {
    fn from(path: &'a Path) -> Self {
        ArchiveSource::Path(path)
    }
}

impl<'a> From<&'a PathBuf> for ArchiveSource<'a> {
    fn from(path: &'a PathBuf) -> Self {
        ArchiveSource::Path(path.as_path())
    }
}

trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

fn open_archive<'a>(
    source: ArchiveSource<'a>,
) -> ArchiveResult<zip::ZipArchive<Box<dyn ReadSeek + 'a>>> {
    let reader: Box<dyn ReadSeek + 'a> = match source {
        ArchiveSource::Bytes(bytes) => Box::new(Cursor::new(bytes)),
        ArchiveSource::Path(path) => {
            Box::new(File::open(path).map_err(|error| ArchiveError::Io {
                detail: format!("could not open `{}`: {error}", path.display()),
            })?)
        }
    };
    zip::ZipArchive::new(reader).map_err(map_zip_error)
}

/// Inspect an archive without extracting it.
///
/// Walks the central directory, validates every name and every declared size,
/// and refuses the whole archive on the first violation.
pub fn inspect<'a>(
    source: impl Into<ArchiveSource<'a>>,
    limits: &ArchiveLimits,
) -> ArchiveResult<ArchiveReport> {
    let mut archive = open_archive(source.into())?;
    let (report, _plan) = build_plan(&mut archive, limits)?;
    Ok(report)
}

/// Validate an archive and extract it under `dest`.
///
/// All names and declared sizes are validated before the first write. Actual
/// bytes are counted as they are copied, so a header that understates its size
/// still cannot exceed the entry, total, or ratio limits. Existing files are
/// never overwritten, links are never followed, and nothing is written outside
/// `dest`.
pub fn extract<'a>(
    source: impl Into<ArchiveSource<'a>>,
    dest: impl AsRef<Path>,
    limits: &ArchiveLimits,
) -> Result<ExtractionReport, ExtractionError> {
    let mut archive = open_archive(source.into())
        .map_err(|reason| ExtractionError::new(reason, Vec::new(), 0))?;
    let (_report, plan) = build_plan(&mut archive, limits)
        .map_err(|reason| ExtractionError::new(reason, Vec::new(), 0))?;

    let dest = dest.as_ref();
    fs::create_dir_all(dest).map_err(|error| {
        ExtractionError::new(
            ArchiveError::Io {
                detail: format!("could not create `{}`: {error}", dest.display()),
            },
            Vec::new(),
            0,
        )
    })?;
    let root = dest.canonicalize().map_err(|error| {
        ExtractionError::new(
            ArchiveError::Io {
                detail: format!("could not resolve `{}`: {error}", dest.display()),
            },
            Vec::new(),
            0,
        )
    })?;

    let mut report = ExtractionReport::default();

    for entry in &plan {
        if entry.is_dir {
            match ensure_directory(&root, &entry.relative) {
                Ok((_path, created)) => {
                    if created {
                        report.directories_created += 1;
                    }
                    report.extracted.push(entry.relative.clone());
                }
                Err(reason) => {
                    return Err(ExtractionError::new(
                        reason,
                        report.extracted,
                        report.bytes_written,
                    ))
                }
            }
            continue;
        }

        let parent_relative = entry.relative.parent().unwrap_or_else(|| Path::new(""));
        let Some(file_name) = entry.relative.file_name() else {
            return Err(ExtractionError::new(
                ArchiveError::MalformedPath {
                    name: entry.name.clone(),
                },
                report.extracted,
                report.bytes_written,
            ));
        };
        let parent = match ensure_directory(&root, parent_relative) {
            Ok((path, created)) => {
                if created {
                    report.directories_created += 1;
                }
                path
            }
            Err(reason) => {
                return Err(ExtractionError::new(
                    reason,
                    report.extracted,
                    report.bytes_written,
                ))
            }
        };
        let target = parent.join(file_name);

        let outcome = extract_one(
            &mut archive,
            entry,
            &target,
            limits,
            &mut report.bytes_written,
        );
        match outcome {
            Ok(()) => report.extracted.push(entry.relative.clone()),
            Err(reason) => {
                return Err(ExtractionError::new(
                    reason,
                    report.extracted,
                    report.bytes_written,
                ));
            }
        }
    }

    Ok(report)
}

fn extract_one<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    entry: &PlannedEntry,
    target: &Path,
    limits: &ArchiveLimits,
    bytes_written: &mut u64,
) -> ArchiveResult<()> {
    let mut reader = archive.by_index(entry.index).map_err(map_zip_error)?;
    if reader.encrypted() {
        return Err(ArchiveError::Encrypted {
            name: entry.name.clone(),
        });
    }
    if !is_supported_compression(reader.compression()) {
        return Err(ArchiveError::UnsupportedMethod {
            name: entry.name.clone(),
            method: format!("{:?}", reader.compression()),
        });
    }

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(|error| match error.kind() {
            io::ErrorKind::AlreadyExists => ArchiveError::DestinationConflict {
                path: target.display().to_string(),
            },
            _ => ArchiveError::Io {
                detail: format!("could not create `{}`: {error}", target.display()),
            },
        })?;

    // Only a file this call created is ever removed on failure. A destination
    // conflict above returns before any cleanup and leaves the existing file
    // untouched.
    let outcome = (|| {
        copy_entry(
            &mut reader,
            &mut output,
            &entry.name,
            entry.compressed_size,
            bytes_written,
            limits,
        )?;
        output.flush().map_err(|error| ArchiveError::Io {
            detail: format!("could not flush `{}`: {error}", target.display()),
        })
    })();
    if outcome.is_err() {
        drop(output);
        let _ = fs::remove_file(target);
    }
    outcome
}

/// Copy one decompressed entry through the actual-byte accounting.
///
/// The entry limit, archive total, and actual compression ratio are checked
/// before each chunk is written. A lying header therefore cannot exceed the
/// limits even when the declared size passes [`inspect`].
fn copy_entry<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    name: &str,
    compressed_size: u64,
    total_bytes: &mut u64,
    limits: &ArchiveLimits,
) -> ArchiveResult<()> {
    let mut buffer = [0u8; 64 * 1024];
    let mut entry_bytes = 0u64;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) => {
                return Err(ArchiveError::Malformed {
                    detail: format!("entry `{name}` could not be decompressed: {error}"),
                })
            }
        };
        let read = read as u64;
        entry_bytes = entry_bytes
            .checked_add(read)
            .ok_or_else(|| ArchiveError::EntrySize {
                name: name.to_string(),
                declared: u64::MAX,
                limit: limits.max_entry_bytes,
            })?;
        let next_total = total_bytes
            .checked_add(read)
            .ok_or(ArchiveError::TotalSize {
                declared: u64::MAX,
                limit: limits.max_total_bytes,
            })?;

        if entry_bytes > limits.max_entry_bytes {
            return Err(ArchiveError::EntrySize {
                name: name.to_string(),
                declared: entry_bytes,
                limit: limits.max_entry_bytes,
            });
        }
        if next_total > limits.max_total_bytes {
            return Err(ArchiveError::TotalSize {
                declared: next_total,
                limit: limits.max_total_bytes,
            });
        }
        let ratio = compression_ratio(entry_bytes, compressed_size);
        if ratio > limits.max_compression_ratio {
            return Err(ArchiveError::CompressionRatio {
                name: name.to_string(),
                actual: entry_bytes,
                compressed: compressed_size,
                ratio,
                limit: limits.max_compression_ratio,
            });
        }

        writer
            .write_all(&buffer[..read as usize])
            .map_err(|error| ArchiveError::Io {
                detail: format!("could not write entry `{name}`: {error}"),
            })?;
        *total_bytes = next_total;
    }
    Ok(())
}

fn ensure_directory(root: &Path, relative: &Path) -> ArchiveResult<(PathBuf, bool)> {
    let mut current = root.to_path_buf();
    let mut created = false;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(ArchiveError::MalformedPath {
                name: relative.display().to_string(),
            });
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(ArchiveError::DestinationSymlink {
                        path: display_relative(root, &current),
                    });
                }
                if !metadata.is_dir() {
                    return Err(ArchiveError::DestinationConflict {
                        path: display_relative(root, &current),
                    });
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => match fs::create_dir(&current)
            {
                Ok(()) => created = true,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let metadata =
                        fs::symlink_metadata(&current).map_err(|error| ArchiveError::Io {
                            detail: format!("could not inspect `{}`: {error}", current.display()),
                        })?;
                    if metadata.file_type().is_symlink() {
                        return Err(ArchiveError::DestinationSymlink {
                            path: display_relative(root, &current),
                        });
                    }
                    if !metadata.is_dir() {
                        return Err(ArchiveError::DestinationConflict {
                            path: display_relative(root, &current),
                        });
                    }
                }
                Err(error) => {
                    return Err(ArchiveError::Io {
                        detail: format!("could not create `{}`: {error}", current.display()),
                    })
                }
            },
            Err(error) => {
                return Err(ArchiveError::Io {
                    detail: format!("could not inspect `{}`: {error}", current.display()),
                })
            }
        }
    }

    let canonical = current.canonicalize().map_err(|error| ArchiveError::Io {
        detail: format!("could not resolve `{}`: {error}", current.display()),
    })?;
    if !canonical.starts_with(root) {
        return Err(ArchiveError::DestinationSymlink {
            path: canonical.display().to_string(),
        });
    }
    Ok((canonical, created))
}

fn display_relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

/// One validated entry ready for extraction.
pub(crate) struct PlannedEntry {
    pub(crate) index: usize,
    pub(crate) name: String,
    pub(crate) relative: PathBuf,
    pub(crate) is_dir: bool,
    pub(crate) compressed_size: u64,
}

pub(crate) fn build_plan<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    limits: &ArchiveLimits,
) -> ArchiveResult<(ArchiveReport, Vec<PlannedEntry>)> {
    let count = archive.len();
    if count > limits.max_entries {
        return Err(ArchiveError::EntryCount {
            entries: count,
            limit: limits.max_entries,
        });
    }

    let mut entries = Vec::with_capacity(count);
    let mut plan = Vec::with_capacity(count);
    let mut total_declared = 0u64;
    let mut max_ratio = 0u64;
    let mut max_depth = 0usize;
    let mut seen = HashSet::new();
    let mut file_paths = HashSet::new();
    let mut directory_paths = HashSet::new();

    for index in 0..count {
        let file = archive.by_index_raw(index).map_err(map_zip_error)?;
        let name = file
            .name()
            .map_err(|_| ArchiveError::NonUtf8Name { index })?
            .into_owned();
        if file.encrypted() {
            return Err(ArchiveError::Encrypted { name });
        }

        let is_dir = file.is_dir();
        let unix_mode = file.unix_mode();
        if let Some(mode) = unix_mode {
            let kind = mode & S_IFMT;
            match kind {
                0 | S_IFREG | S_IFDIR => {}
                S_IFLNK => return Err(ArchiveError::Symlink { name }),
                _ => return Err(ArchiveError::SpecialFile { name, mode }),
            }
        }

        if !is_dir && !is_supported_compression(file.compression()) {
            return Err(ArchiveError::UnsupportedMethod {
                name,
                method: format!("{:?}", file.compression()),
            });
        }

        let components = validate_entry_path(&name, limits)?;
        let depth = components.len();
        let key = collision_key(&components);
        register_path(
            &key,
            is_dir,
            &name,
            &mut seen,
            &mut file_paths,
            &mut directory_paths,
        )?;

        let declared_size = if is_dir { 0 } else { file.size() };
        let compressed_size = file.compressed_size();
        let ratio = if is_dir {
            0
        } else {
            compression_ratio(declared_size, compressed_size)
        };

        if declared_size > limits.max_entry_bytes {
            return Err(ArchiveError::EntrySize {
                name,
                declared: declared_size,
                limit: limits.max_entry_bytes,
            });
        }
        if ratio > limits.max_compression_ratio {
            return Err(ArchiveError::CompressionRatio {
                name,
                actual: declared_size,
                compressed: compressed_size,
                ratio,
                limit: limits.max_compression_ratio,
            });
        }
        total_declared =
            total_declared
                .checked_add(declared_size)
                .ok_or(ArchiveError::TotalSize {
                    declared: u64::MAX,
                    limit: limits.max_total_bytes,
                })?;
        if total_declared > limits.max_total_bytes {
            return Err(ArchiveError::TotalSize {
                declared: total_declared,
                limit: limits.max_total_bytes,
            });
        }

        max_ratio = max_ratio.max(ratio);
        max_depth = max_depth.max(depth);

        let relative = path_from_components(&components);
        entries.push(ArchiveEntryInfo {
            name: name.clone(),
            is_dir,
            declared_size,
            compressed_size,
            compression_ratio: ratio,
            unix_mode,
            depth,
        });
        plan.push(PlannedEntry {
            index,
            name,
            relative,
            is_dir,
            compressed_size,
        });
    }

    Ok((
        ArchiveReport {
            entries,
            total_declared_bytes: total_declared,
            max_compression_ratio: max_ratio,
            max_path_depth: max_depth,
        },
        plan,
    ))
}

fn is_supported_compression(method: zip::CompressionMethod) -> bool {
    matches!(
        method,
        zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated
    )
}

fn compression_ratio(uncompressed: u64, compressed: u64) -> u64 {
    if uncompressed == 0 {
        0
    } else if compressed == 0 {
        u64::MAX
    } else {
        uncompressed.div_ceil(compressed)
    }
}

fn validate_entry_path(name: &str, limits: &ArchiveLimits) -> ArchiveResult<Vec<String>> {
    if name.is_empty() {
        return Err(ArchiveError::MalformedPath {
            name: name.to_string(),
        });
    }
    if name.contains('\0') {
        return Err(ArchiveError::NulByte {
            name: name.to_string(),
        });
    }
    if name.contains('\\') {
        return Err(ArchiveError::BackslashSeparator {
            name: name.to_string(),
        });
    }
    let bytes = name.as_bytes();
    if name.starts_with('/')
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
        || name.contains(':')
    {
        return Err(ArchiveError::AbsolutePath {
            name: name.to_string(),
        });
    }

    let trimmed = name.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(ArchiveError::AbsolutePath {
            name: name.to_string(),
        });
    }

    let mut components = Vec::new();
    for part in trimmed.split('/') {
        if part.is_empty() {
            return Err(ArchiveError::MalformedPath {
                name: name.to_string(),
            });
        }
        if part == "." {
            return Err(ArchiveError::DotComponent {
                name: name.to_string(),
            });
        }
        if part == ".." {
            return Err(ArchiveError::ParentTraversal {
                name: name.to_string(),
            });
        }
        // Windows does not allow a component this long.
        if part.len() > 255 {
            return Err(ArchiveError::MalformedPath {
                name: name.to_string(),
            });
        }
        components.push(part.to_string());
    }

    if components.len() > limits.max_path_depth {
        return Err(ArchiveError::PathTooDeep {
            name: name.to_string(),
            depth: components.len(),
            limit: limits.max_path_depth,
        });
    }
    Ok(components)
}

fn path_from_components(components: &[String]) -> PathBuf {
    let mut path = PathBuf::new();
    for component in components {
        path.push(component);
    }
    path
}

/// Collision key: lowercase every component and drop trailing dots/spaces,
/// which Windows also ignores. Applied on every platform so an archive that is
/// safe here is safe when copied to Windows.
fn collision_key(components: &[String]) -> String {
    let mut key = String::new();
    for (index, component) in components.iter().enumerate() {
        if index > 0 {
            key.push('/');
        }
        key.push_str(&fold_component(component));
    }
    key
}

fn fold_component(component: &str) -> String {
    let lowered = component.to_lowercase();
    let trimmed = lowered.trim_end_matches(['.', ' ']).to_string();
    if trimmed.is_empty() {
        lowered
    } else {
        trimmed
    }
}

fn register_path(
    key: &str,
    is_dir: bool,
    name: &str,
    seen: &mut HashSet<String>,
    files: &mut HashSet<String>,
    directories: &mut HashSet<String>,
) -> ArchiveResult<()> {
    if !seen.insert(key.to_string()) {
        return Err(ArchiveError::DuplicatePath {
            name: name.to_string(),
        });
    }

    let parts: Vec<&str> = key.split('/').collect();
    for end in 1..parts.len() {
        let ancestor = parts[..end].join("/");
        if files.contains(&ancestor) {
            return Err(ArchiveError::PathConflict {
                name: name.to_string(),
            });
        }
        directories.insert(ancestor);
    }

    if is_dir {
        if files.contains(key) {
            return Err(ArchiveError::PathConflict {
                name: name.to_string(),
            });
        }
        directories.insert(key.to_string());
    } else {
        if directories.contains(key) {
            return Err(ArchiveError::PathConflict {
                name: name.to_string(),
            });
        }
        files.insert(key.to_string());
    }
    Ok(())
}

fn map_zip_error(error: zip::result::ZipError) -> ArchiveError {
    match error {
        zip::result::ZipError::Io(error) => ArchiveError::Io {
            detail: error.to_string(),
        },
        zip::result::ZipError::InvalidArchive(detail) => ArchiveError::Malformed {
            detail: detail.into_owned(),
        },
        zip::result::ZipError::UnsupportedArchive(detail) => ArchiveError::UnsupportedMethod {
            name: "<archive>".to_string(),
            method: detail.to_string(),
        },
        zip::result::ZipError::FileNotFound => ArchiveError::Malformed {
            detail: "an entry named in the central directory was not found".to_string(),
        },
        zip::result::ZipError::InvalidPassword => ArchiveError::Encrypted {
            name: "<archive>".to_string(),
        },
        zip::result::ZipError::CompressionMethodNotSupported(method) => {
            ArchiveError::UnsupportedMethod {
                name: "<archive>".to_string(),
                method: format!("method {method}"),
            }
        }
        zip::result::ZipError::DecompressedSizeLimitExceeded { size, limit } => {
            ArchiveError::TotalSize {
                declared: u64::try_from(size).unwrap_or(u64::MAX),
                limit,
            }
        }
        zip::result::ZipError::DecompressedSizeUnknown => ArchiveError::Malformed {
            detail: "the archive does not declare its decompressed size".to_string(),
        },
        other => ArchiveError::Malformed {
            detail: other.to_string(),
        },
    }
}

/// Result alias for archive work.
pub type ArchiveResult<T> = std::result::Result<T, ArchiveError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use tempfile::TempDir;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    const LOCAL_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
    const CENTRAL_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
    const END_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];

    fn writer() -> ZipWriter<Cursor<Vec<u8>>> {
        ZipWriter::new(Cursor::new(Vec::new()))
    }

    fn add_file(zip: &mut ZipWriter<Cursor<Vec<u8>>>, name: &str, data: &[u8]) {
        zip.start_file(name, SimpleFileOptions::default())
            .expect("start file");
        zip.write_all(data).expect("write file");
    }

    fn add_deflated(zip: &mut ZipWriter<Cursor<Vec<u8>>>, name: &str, data: &[u8]) {
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        zip.start_file(name, options).expect("start file");
        zip.write_all(data).expect("write file");
    }

    fn finish(zip: ZipWriter<Cursor<Vec<u8>>>) -> Vec<u8> {
        zip.finish().expect("finish archive").into_inner()
    }

    fn find(bytes: &[u8], signature: [u8; 4], from: usize) -> Option<usize> {
        bytes[from..]
            .windows(4)
            .position(|window| window == signature)
            .map(|position| position + from)
    }

    fn find_nth(bytes: &[u8], signature: [u8; 4], nth: usize) -> usize {
        let mut start = 0;
        for index in 0..=nth {
            let position = find(bytes, signature, start).expect("signature");
            if index == nth {
                return position;
            }
            start = position + 4;
        }
        unreachable!()
    }

    /// Mark the first entry as ZipCrypto-encrypted by setting the general
    /// purpose bit instead of using the unstable writer API.
    fn mark_encrypted(mut bytes: Vec<u8>) -> Vec<u8> {
        let local = find(&bytes, LOCAL_SIGNATURE, 0).expect("local header");
        bytes[local + 6] |= 0x01;
        let central = find(&bytes, CENTRAL_SIGNATURE, 0).expect("central header");
        bytes[central + 8] |= 0x01;
        bytes
    }

    fn set_compression_method(mut bytes: Vec<u8>, method: u16) -> Vec<u8> {
        let local = find(&bytes, LOCAL_SIGNATURE, 0).expect("local header");
        bytes[local + 8..local + 10].copy_from_slice(&method.to_le_bytes());
        let central = find(&bytes, CENTRAL_SIGNATURE, 0).expect("central header");
        bytes[central + 10..central + 12].copy_from_slice(&method.to_le_bytes());
        bytes
    }

    /// Rewrite the declared uncompressed size in both headers. The data itself
    /// is untouched, which is exactly what a lying header looks like.
    fn set_declared_uncompressed_size(mut bytes: Vec<u8>, size: u32) -> Vec<u8> {
        let local = find(&bytes, LOCAL_SIGNATURE, 0).expect("local header");
        bytes[local + 22..local + 26].copy_from_slice(&size.to_le_bytes());
        let central = find(&bytes, CENTRAL_SIGNATURE, 0).expect("central header");
        bytes[central + 24..central + 28].copy_from_slice(&size.to_le_bytes());
        bytes
    }

    fn corrupt_central_crc(mut bytes: Vec<u8>, nth: usize) -> Vec<u8> {
        let central = find_nth(&bytes, CENTRAL_SIGNATURE, nth);
        bytes[central + 16..central + 20].copy_from_slice(&0u32.to_le_bytes());
        bytes
    }

    fn limits() -> ArchiveLimits {
        ArchiveLimits::default()
    }

    #[test]
    fn valid_archive_with_files_and_nested_dirs_extracts_and_reports() {
        let mut zip = writer();
        add_file(&mut zip, "README.md", b"hello");
        add_file(&mut zip, "docs/guide/intro.txt", b"nested");
        zip.add_directory("docs/guide/", SimpleFileOptions::default())
            .expect("directory");
        let bytes = finish(zip);

        let report = inspect(&bytes, &limits()).expect("inspect");
        assert_eq!(report.entry_count(), 3);
        assert_eq!(report.file_count(), 2);
        assert_eq!(report.directory_count(), 1);
        assert_eq!(report.total_declared_bytes, 11);
        assert_eq!(report.max_path_depth, 3);
        assert_eq!(report.entries[1].compression_ratio, 1);

        let destination = TempDir::new().expect("tempdir");
        let extracted = extract(&bytes, destination.path(), &limits()).expect("extract");
        assert_eq!(extracted.bytes_written, 11);
        assert_eq!(
            extracted.extracted,
            vec![
                PathBuf::from("README.md"),
                PathBuf::from("docs/guide/intro.txt"),
                PathBuf::from("docs/guide"),
            ]
        );
        assert_eq!(
            fs::read(destination.path().join("docs/guide/intro.txt")).unwrap(),
            b"nested"
        );
    }

    #[test]
    fn zip_slip_parent_traversal_is_refused() {
        for name in ["../evil.txt", "docs/../../evil.txt", ".."] {
            let mut zip = writer();
            add_file(&mut zip, name, b"escape");
            let bytes = finish(zip);
            let error = inspect(&bytes, &limits()).expect_err("must refuse");
            assert!(
                matches!(error, ArchiveError::ParentTraversal { .. }),
                "{name}: {error}"
            );
            assert_eq!(error.code(), ErrorCode::PolicyDenied);

            let destination = TempDir::new().expect("tempdir");
            let error = extract(&bytes, destination.path(), &limits()).expect_err("must refuse");
            assert!(matches!(
                error.reason(),
                ArchiveError::ParentTraversal { .. }
            ));
            assert!(!destination
                .path()
                .parent()
                .unwrap()
                .join("evil.txt")
                .exists());
        }
    }

    #[test]
    fn absolute_drive_and_unc_paths_are_refused() {
        for name in [
            "/etc/passwd",
            "C:/evil",
            "C:\\evil",
            "C:evil",
            "\\\\server\\share\\evil",
            "//server/share/evil",
            "docs/./guide.txt",
            "docs//guide.txt",
            "nul\0byte",
        ] {
            let mut zip = writer();
            add_file(&mut zip, name, b"escape");
            let bytes = finish(zip);
            let error = inspect(&bytes, &limits()).expect_err("must refuse");
            assert!(
                matches!(
                    error,
                    ArchiveError::AbsolutePath { .. }
                        | ArchiveError::BackslashSeparator { .. }
                        | ArchiveError::DotComponent { .. }
                        | ArchiveError::MalformedPath { .. }
                        | ArchiveError::NulByte { .. }
                ),
                "{name}: {error}"
            );
        }
    }

    #[test]
    fn symlink_entries_are_refused() {
        let mut zip = writer();
        zip.add_symlink(
            "link",
            "../outside",
            SimpleFileOptions::default().unix_permissions(0o120_777),
        )
        .expect("symlink");
        let bytes = finish(zip);

        let error = inspect(&bytes, &limits()).expect_err("must refuse");
        assert!(matches!(error, ArchiveError::Symlink { .. }), "{error}");

        let destination = TempDir::new().expect("tempdir");
        let error = extract(&bytes, destination.path(), &limits()).expect_err("must refuse");
        assert!(matches!(error.reason(), ArchiveError::Symlink { .. }));
        assert!(!destination.path().join("link").exists());
    }

    #[test]
    fn ratio_bomb_is_refused_during_inspection() {
        let mut zip = writer();
        add_deflated(&mut zip, "bomb.txt", &vec![0u8; 1024 * 1024]);
        let bytes = finish(zip);

        let error = inspect(&bytes, &limits()).expect_err("must refuse");
        assert!(
            matches!(error, ArchiveError::CompressionRatio { .. }),
            "{error}"
        );
        assert_eq!(error.code(), ErrorCode::LimitExceeded);

        let destination = TempDir::new().expect("tempdir");
        let error = extract(&bytes, destination.path(), &limits()).expect_err("must refuse");
        assert!(matches!(
            error.reason(),
            ArchiveError::CompressionRatio { .. }
        ));
        assert_eq!(fs::read_dir(destination.path()).unwrap().count(), 0);
    }

    #[test]
    fn declared_size_bomb_is_refused_before_extraction() {
        let mut zip = writer();
        add_file(&mut zip, "big.bin", b"small");
        let bytes = set_declared_uncompressed_size(finish(zip), 512 * 1024 * 1024);

        let error = inspect(&bytes, &limits()).expect_err("must refuse");
        assert!(matches!(error, ArchiveError::EntrySize { .. }), "{error}");
    }

    #[test]
    fn actual_bytes_are_counted_even_when_the_header_lies() {
        // A header that claims 10 bytes but yields 2 MiB: the copy loop must
        // refuse on the actual count before writing everything.
        let mut source = io::repeat(b'x').take(2 * 1024 * 1024);
        let mut sink = io::sink();
        let mut total = 0u64;
        let error = copy_entry(
            &mut source,
            &mut sink,
            "lie.bin",
            1,
            &mut total,
            &ArchiveLimits {
                max_entry_bytes: 64 * 1024,
                max_compression_ratio: u64::MAX,
                ..ArchiveLimits::default()
            },
        )
        .expect_err("must refuse");
        assert!(matches!(error, ArchiveError::EntrySize { .. }), "{error}");
        assert!(total <= 64 * 1024);
    }

    #[test]
    fn actual_ratio_is_counted_even_when_the_declared_ratio_passes() {
        let mut source = io::repeat(b'x').take(1024 * 1024);
        let mut sink = io::sink();
        let mut total = 0u64;
        let error = copy_entry(
            &mut source,
            &mut sink,
            "lie.bin",
            1,
            &mut total,
            &ArchiveLimits {
                max_compression_ratio: 100,
                ..ArchiveLimits::default()
            },
        )
        .expect_err("must refuse");
        assert!(
            matches!(error, ArchiveError::CompressionRatio { .. }),
            "{error}"
        );
    }

    #[test]
    fn total_declared_size_limit_is_refused() {
        let mut zip = writer();
        add_file(&mut zip, "one.bin", &[0u8; 8]);
        add_file(&mut zip, "two.bin", &[0u8; 8]);
        let bytes = finish(zip);
        let error = inspect(
            &bytes,
            &ArchiveLimits {
                max_total_bytes: 10,
                ..ArchiveLimits::default()
            },
        )
        .expect_err("must refuse");
        assert!(
            matches!(
                error,
                ArchiveError::TotalSize {
                    declared: 16,
                    limit: 10
                }
            ),
            "{error}"
        );
    }

    #[test]
    fn actual_total_is_counted_across_entries() {
        let mut total = 0u64;
        let mut first = io::repeat(b'x').take(6);
        let mut sink = io::sink();
        copy_entry(
            &mut first,
            &mut sink,
            "first.bin",
            1,
            &mut total,
            &ArchiveLimits::default(),
        )
        .expect("first entry fits");
        assert_eq!(total, 6);

        let mut second = io::repeat(b'x').take(6);
        let error = copy_entry(
            &mut second,
            &mut sink,
            "second.bin",
            1,
            &mut total,
            &ArchiveLimits {
                max_total_bytes: 10,
                ..ArchiveLimits::default()
            },
        )
        .expect_err("must refuse");
        assert!(matches!(error, ArchiveError::TotalSize { .. }), "{error}");
        assert_eq!(total, 6);
    }

    #[test]
    fn too_many_entries_are_refused() {
        let mut zip = writer();
        for index in 0..3 {
            add_file(&mut zip, &format!("file-{index}.txt"), b"x");
        }
        let bytes = finish(zip);
        let error = inspect(
            &bytes,
            &ArchiveLimits {
                max_entries: 2,
                ..ArchiveLimits::default()
            },
        )
        .expect_err("must refuse");
        assert!(
            matches!(
                error,
                ArchiveError::EntryCount {
                    entries: 3,
                    limit: 2
                }
            ),
            "{error}"
        );
    }

    #[test]
    fn paths_deeper_than_the_limit_are_refused() {
        let mut zip = writer();
        add_file(&mut zip, "a/b/c/d.txt", b"x");
        let bytes = finish(zip);
        let error = inspect(
            &bytes,
            &ArchiveLimits {
                max_path_depth: 3,
                ..ArchiveLimits::default()
            },
        )
        .expect_err("must refuse");
        assert!(
            matches!(
                error,
                ArchiveError::PathTooDeep {
                    depth: 4,
                    limit: 3,
                    ..
                }
            ),
            "{error}"
        );
    }

    #[test]
    fn duplicate_and_case_colliding_names_are_refused() {
        let mut zip = writer();
        add_file(&mut zip, "Readme.md", b"one");
        add_file(&mut zip, "README.md", b"two");
        let bytes = finish(zip);
        let error = inspect(&bytes, &limits()).expect_err("must refuse");
        assert!(
            matches!(error, ArchiveError::DuplicatePath { .. }),
            "{error}"
        );

        // Windows ignores a trailing dot or space, so these names alias the
        // same file even though the zip reader sees two distinct entries.
        let mut zip = writer();
        add_file(&mut zip, "notes.txt", b"one");
        add_file(&mut zip, "notes.txt.", b"two");
        let bytes = finish(zip);
        let error = inspect(&bytes, &limits()).expect_err("must refuse");
        assert!(
            matches!(error, ArchiveError::DuplicatePath { .. }),
            "{error}"
        );
    }

    #[test]
    fn exact_duplicate_planner_keys_are_refused() {
        // The zip reader collapses identical central-directory names into one
        // entry, so exercise the planner's duplicate branch directly.
        let mut seen = HashSet::new();
        let mut files = HashSet::new();
        let mut directories = HashSet::new();
        register_path(
            "same",
            false,
            "same",
            &mut seen,
            &mut files,
            &mut directories,
        )
        .expect("first");
        let error = register_path(
            "same",
            false,
            "same",
            &mut seen,
            &mut files,
            &mut directories,
        )
        .expect_err("must refuse");
        assert!(
            matches!(error, ArchiveError::DuplicatePath { .. }),
            "{error}"
        );
    }

    #[test]
    fn file_and_directory_path_conflicts_are_refused() {
        let mut zip = writer();
        add_file(&mut zip, "a", b"file");
        add_file(&mut zip, "a/b.txt", b"child");
        let bytes = finish(zip);
        let error = inspect(&bytes, &limits()).expect_err("must refuse");
        assert!(
            matches!(error, ArchiveError::PathConflict { .. }),
            "{error}"
        );
    }

    #[test]
    fn encrypted_entries_are_refused_from_a_crafted_header() {
        // The stable writer has no encryption option; set the general-purpose
        // encryption bit in both headers instead.
        let mut zip = writer();
        add_file(&mut zip, "secret.txt", b"data");
        let bytes = mark_encrypted(finish(zip));

        let error = inspect(&bytes, &limits()).expect_err("must refuse");
        assert!(matches!(error, ArchiveError::Encrypted { .. }), "{error}");
        assert_eq!(error.code(), ErrorCode::Unsupported);
    }

    #[test]
    fn unsupported_compression_methods_are_refused() {
        let mut zip = writer();
        add_file(&mut zip, "file.txt", b"data");
        let bytes = set_compression_method(finish(zip), 99);
        let error = inspect(&bytes, &limits()).expect_err("must refuse");
        assert!(
            matches!(error, ArchiveError::UnsupportedMethod { .. }),
            "{error}"
        );
    }

    #[test]
    fn existing_destination_files_are_not_overwritten() {
        let mut zip = writer();
        add_file(&mut zip, "keep.txt", b"new");
        let bytes = finish(zip);
        let destination = TempDir::new().expect("tempdir");
        fs::write(destination.path().join("keep.txt"), b"original").unwrap();

        let error = extract(&bytes, destination.path(), &limits()).expect_err("must refuse");
        assert!(
            matches!(error.reason(), ArchiveError::DestinationConflict { .. }),
            "{error}"
        );
        assert_eq!(
            fs::read(destination.path().join("keep.txt")).unwrap(),
            b"original"
        );
    }

    #[test]
    fn a_mid_extraction_failure_keeps_completed_files_and_removes_the_partial_one() {
        let mut zip = writer();
        add_file(&mut zip, "good.txt", b"good");
        add_file(&mut zip, "bad.txt", b"bad");
        let bytes = corrupt_central_crc(finish(zip), 1);

        let destination = TempDir::new().expect("tempdir");
        let error = extract(&bytes, destination.path(), &limits()).expect_err("must refuse");
        assert!(matches!(error.reason(), ArchiveError::Malformed { .. }));
        assert_eq!(error.extracted(), &[PathBuf::from("good.txt")]);
        assert_eq!(
            fs::read(destination.path().join("good.txt")).unwrap(),
            b"good"
        );
        assert!(!destination.path().join("bad.txt").exists());
    }

    #[test]
    fn mutated_central_directory_never_panics_and_errors_stay_typed() {
        let mut zip = writer();
        add_file(&mut zip, "a.txt", b"alpha");
        add_file(&mut zip, "b/c.txt", b"bravo");
        let bytes = finish(zip);

        let central_start = find(&bytes, CENTRAL_SIGNATURE, 0).expect("central directory");
        let central_end = find(&bytes, END_SIGNATURE, central_start).expect("end record");
        let span = central_end - central_start;
        assert!(span > 0);

        let limits = ArchiveLimits {
            max_entries: 64,
            max_total_bytes: 1 << 20,
            max_entry_bytes: 1 << 20,
            ..ArchiveLimits::default()
        };

        for step in 0..256usize {
            let mut mutated = bytes.clone();
            let offset = central_start + (step * 37 + 11) % span;
            mutated[offset] ^= ((step as u8) | 1).wrapping_mul(17);
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                inspect(&mutated, &limits)
            }));
            let outcome = outcome.expect("inspect must not panic on mutated bytes");
            match outcome {
                Ok(report) => {
                    assert!(report.entry_count() <= limits.max_entries);
                }
                Err(error) => {
                    // Every refusal is a typed error with a stable code.
                    let _ = error.code();
                }
            }
        }
    }
}
