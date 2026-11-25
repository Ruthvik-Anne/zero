//! Content-addressed, resumable workspace bundle (T-TEL-02, TEL-02, TEL-04,
//! TEL-05).
//!
//! A [`Bundle`] is the file half of teleport: a [`BundleManifest`] that lists
//! every workspace file and its ordered [`ChunkRef`]s, plus the unique chunk
//! bytes those references name. Files are split into fixed-size chunks by
//! [`build`], each chunk is hashed with blake3, and identical chunks are stored
//! once no matter how many files (or how many offsets in one file) refer to
//! them. Chunk hashes are verified while building and again while reading, so a
//! bundle either matches its manifest or fails with `zero.tru.tamper`.
//!
//! [`BundleWriter`] sends the chunks into a bundle directory as files named by
//! their lower-case hex hash, with an atomically replaced `checkpoint.json`
//! recording which chunks are durable. [`BundleWriter::resume`] loads that
//! checkpoint and [`BundleWriter::write_pending`] writes only the missing
//! chunks, which is the T-TEL-02 done criterion: **an interrupted bundle
//! resumes**. A chunk whose file is missing, truncated, or otherwise corrupt is
//! detected by hash and rewritten.
//!
//! [`BundleReader`] opens a bundle directory, [`verify`](BundleReader::verify)s
//! every chunk, and [`materialize`](BundleReader::materialize)s the files under a
//! target directory with Unix modes and recorded symlinks. Materialize never
//! overwrites a file with different content and refuses an unrecorded symlink.
//!
//! Exclusions are first-class: `excluded` carries a path and a reason for every
//! path the caller left out, and the manifest always reports them (TEL-05).
//! [`build`] also refuses a secret-like file path outright, so a vault or
//! credential path cannot enter a bundle by accident.
//!
//! Scope: no network, no encryption, no lease. The encrypted transfer is
//! [`crate::transfer`] (TEL-03/TEL-06) and the lease fence is TEL-05's
//! `T-TEL-05` task. Symlink creation is Unix-only in this slice; on Windows a
//! recorded symlink is refused rather than guessed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, ZeroError};

/// Bundle manifest schema this build reads and writes.
pub const BUNDLE_SCHEMA_VERSION: u32 = 1;

/// Domain separator for the bundle manifest's canonical bytes.
pub const BUNDLE_MANIFEST_DOMAIN: &[u8] = b"zero.teleport.bundle.v1\0";

/// Domain separator for the content-derived bundle id.
pub const BUNDLE_ID_DOMAIN: &[u8] = b"zero.teleport.bundle-id.v1\0";

/// Default chunk size: 1 MiB.
pub const DEFAULT_CHUNK_BYTES: usize = 1024 * 1024;

/// Largest chunk a bundle may declare: 64 MiB.
pub const MAX_CHUNK_BYTES: usize = 64 * 1024 * 1024;

/// Default ceiling on chunk references in one bundle.
pub const DEFAULT_MAX_CHUNKS: usize = 1_048_576;

/// Hard ceiling on chunk references in one manifest.
pub const MAX_TOTAL_CHUNKS: u64 = 2_097_152;

/// Most files one bundle may carry.
pub const MAX_FILES: usize = 65_536;

/// Longest bundle-relative path, in bytes.
pub const MAX_PATH_BYTES: usize = 1024;

/// Most exclusions one manifest may report.
pub const MAX_EXCLUDED: usize = 4096;

/// Longest exclusion reason, in bytes.
pub const MAX_EXCLUDED_REASON_BYTES: usize = 256;

/// Largest sum of logical file bytes in one bundle: 1 TiB.
pub const MAX_BUNDLE_BYTES: u64 = 1 << 40;

/// Largest canonical bundle manifest: 16 MiB.
pub const MAX_BUNDLE_MANIFEST_BYTES: usize = 16 * 1024 * 1024;

/// Length of a bundle id or chunk hash in hex: 64 characters (32 bytes).
pub const BUNDLE_ID_HEX: usize = 64;

/// The manifest file inside a bundle directory.
pub const BUNDLE_MANIFEST_FILE: &str = "bundle.json";

/// The resumable-transfer checkpoint file inside a bundle directory.
pub const CHECKPOINT_FILE: &str = "checkpoint.json";

/// Suffix of a chunk file that is still being written.
pub const CHUNK_PARTIAL_SUFFIX: &str = ".part";

/// Chunking parameters for [`build`].
///
/// `chunk_bytes` is the maximum chunk size; the last chunk of a file may be
/// smaller. `max_chunks` bounds the total number of chunk references in the
/// bundle, which also bounds the unique chunk set held in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkConfig {
    /// Maximum chunk size in bytes.
    pub chunk_bytes: usize,
    /// Maximum number of chunk references across every file.
    pub max_chunks: usize,
}

impl Default for ChunkConfig {
    fn default() -> Self {
        Self {
            chunk_bytes: DEFAULT_CHUNK_BYTES,
            max_chunks: DEFAULT_MAX_CHUNKS,
        }
    }
}

impl ChunkConfig {
    /// Validate a chunk configuration.
    pub fn new(chunk_bytes: usize, max_chunks: usize) -> Result<Self> {
        let config = Self {
            chunk_bytes,
            max_chunks,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(self) -> Result<()> {
        if self.chunk_bytes == 0 {
            return Err(invalid("chunk size must be greater than zero"));
        }
        if self.chunk_bytes > MAX_CHUNK_BYTES {
            return Err(limit(format!(
                "chunk size is {} bytes; the limit is {MAX_CHUNK_BYTES}",
                self.chunk_bytes
            )));
        }
        if self.max_chunks == 0 {
            return Err(invalid("max_chunks must be greater than zero"));
        }
        if self.max_chunks as u64 > MAX_TOTAL_CHUNKS {
            return Err(limit(format!(
                "max_chunks is {}; the limit is {MAX_TOTAL_CHUNKS}",
                self.max_chunks
            )));
        }
        Ok(())
    }
}

/// One content-addressed chunk reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkRef {
    /// Lower-case hex blake3 digest of the chunk, which is also its file name.
    pub hash: String,
    /// Chunk length in bytes.
    pub bytes: u64,
}

/// What the manifest records about one workspace file.
///
/// A symlink's `bytes` and chunks carry its link target as UTF-8; the target is
/// validated as a safe relative path. Regular file modes are the Unix
/// permission bits and are ignored on Windows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    /// Ordered chunks that reassemble the file (or the link target).
    pub chunks: Vec<ChunkRef>,
    /// Logical file length in bytes.
    pub bytes: u64,
    /// Unix permission bits. `None` means the platform default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    /// True when the entry is a symlink and the chunks carry its target.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub symlink: bool,
}

/// One path the caller deliberately left out of the bundle (TEL-05).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Excluded {
    /// Bundle-relative path that was excluded.
    pub path: String,
    /// Why it was excluded, for the user-facing report.
    pub reason: String,
}

impl Excluded {
    /// Build an exclusion report entry.
    pub fn new(path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            reason: reason.into(),
        }
    }
}

/// A complete, deterministic description of a bundle.
///
/// `files` is a `BTreeMap` and `excluded` is sorted and deduplicated, so
/// insertion order never changes the encoding. `total_chunks` is the number of
/// chunk *references* (before dedupe); `total_bytes` is the logical size of
/// every file. The unique stored size is reported by [`BundleStats`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    /// Manifest schema version.
    pub schema_version: u32,
    /// Deterministic id derived from this manifest's content.
    pub bundle_id: String,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_ms: i64,
    /// Every file, keyed by its safe bundle-relative path.
    pub files: BTreeMap<String, FileEntry>,
    /// Paths deliberately left out, sorted and unique.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded: Vec<Excluded>,
    /// Sum of every file's chunk count (references, not unique chunks).
    pub total_chunks: u64,
    /// Sum of every file's logical length.
    pub total_bytes: u64,
}

impl BundleManifest {
    /// The canonical, deterministic bytes hashed for the bundle id check.
    ///
    /// Layout, all integers big-endian and every variable field
    /// length-prefixed:
    ///
    /// ```text
    /// "zero.teleport.bundle.v1\0"     domain separator
    /// schema_version                  u32
    /// bundle_id                       u32 length + UTF-8
    /// created_ms                      i64
    /// file count                      u32
    /// repeated files, ascending path:
    ///   path                          u32 length + UTF-8
    ///   bytes                         u64
    ///   mode present                  u8 (0 or 1)
    ///     mode                        u32 when present
    ///   symlink                       u8 (0 or 1)
    ///   chunk count                   u32
    ///   repeated chunks, in file order:
    ///     hash                        u32 length + UTF-8
    ///     bytes                       u64
    /// excluded count                  u32
    /// repeated exclusions, sorted:
    ///   path                          u32 length + UTF-8
    ///   reason                        u32 length + UTF-8
    /// total_chunks                    u64
    /// total_bytes                     u64
    /// ```
    ///
    /// Validation is part of canonicalisation: the schema version, bundle id,
    /// path and exclusion safety, per-chunk bounds, per-file and total sums,
    /// fixed totals, and the content-derived bundle id are all checked first.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        validate_manifest(self)?;

        let mut out = Vec::with_capacity(1024);
        out.extend_from_slice(BUNDLE_MANIFEST_DOMAIN);
        out.extend_from_slice(&self.schema_version.to_be_bytes());
        put_str(&mut out, &self.bundle_id)?;
        out.extend_from_slice(&self.created_ms.to_be_bytes());

        put_count(&mut out, self.files.len(), MAX_FILES, "files")?;
        for (path, entry) in &self.files {
            put_str(&mut out, path)?;
            out.extend_from_slice(&entry.bytes.to_be_bytes());
            match entry.mode {
                Some(mode) => {
                    out.push(1);
                    out.extend_from_slice(&mode.to_be_bytes());
                }
                None => out.push(0),
            }
            out.push(u8::from(entry.symlink));
            put_count(
                &mut out,
                entry.chunks.len(),
                MAX_TOTAL_CHUNKS as usize,
                "chunks",
            )?;
            for chunk in &entry.chunks {
                put_str(&mut out, &chunk.hash)?;
                out.extend_from_slice(&chunk.bytes.to_be_bytes());
            }
        }

        put_count(&mut out, self.excluded.len(), MAX_EXCLUDED, "exclusions")?;
        for entry in &self.excluded {
            put_str(&mut out, &entry.path)?;
            put_str(&mut out, &entry.reason)?;
        }

        out.extend_from_slice(&self.total_chunks.to_be_bytes());
        out.extend_from_slice(&self.total_bytes.to_be_bytes());

        if out.len() > MAX_BUNDLE_MANIFEST_BYTES {
            return Err(limit(format!(
                "bundle manifest is {} bytes; the limit is {MAX_BUNDLE_MANIFEST_BYTES}",
                out.len()
            )));
        }
        Ok(out)
    }

    /// Lower-case hex blake3 of [`canonical_bytes`](Self::canonical_bytes).
    pub fn hash(&self) -> Result<String> {
        Ok(blake3::hash(&self.canonical_bytes()?).to_hex().to_string())
    }

    /// Every unique chunk hash the manifest refers to, in ascending order.
    pub fn chunk_hashes(&self) -> BTreeSet<String> {
        self.files
            .values()
            .flat_map(|entry| entry.chunks.iter().map(|chunk| chunk.hash.clone()))
            .collect()
    }

    /// Compact transfer and dedupe numbers for a UI.
    pub fn stats(&self) -> BundleStats {
        let unique: BTreeSet<&str> = self
            .files
            .values()
            .flat_map(|entry| entry.chunks.iter().map(|chunk| chunk.hash.as_str()))
            .collect();
        let stored_bytes: u64 = self
            .files
            .values()
            .flat_map(|entry| entry.chunks.iter())
            .fold(BTreeMap::new(), |mut seen, chunk| {
                seen.insert(chunk.hash.as_str(), chunk.bytes);
                seen
            })
            .values()
            .sum();
        BundleStats {
            files: self.files.len() as u64,
            chunk_references: self.total_chunks,
            unique_chunks: unique.len() as u64,
            logical_bytes: self.total_bytes,
            stored_bytes,
            excluded: self.excluded.len() as u64,
        }
    }
}

/// One builder input: the bytes of a regular file or the target of a symlink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleFile {
    /// File bytes, or the UTF-8 symlink target when `symlink` is set.
    pub bytes: Vec<u8>,
    /// Unix permission bits.
    pub mode: Option<u32>,
    /// True when `bytes` is a symlink target.
    pub symlink: bool,
}

impl BundleFile {
    /// A regular file with the platform-default mode.
    pub fn file(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
            mode: None,
            symlink: false,
        }
    }

    /// Set the Unix permission bits recorded in the manifest.
    pub fn with_mode(mut self, mode: u32) -> Self {
        self.mode = Some(mode);
        self
    }

    /// A symlink whose target is a safe bundle-relative path.
    pub fn symlink(target: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: target.into(),
            mode: None,
            symlink: true,
        }
    }
}

/// Transfer and dedupe numbers for one manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleStats {
    /// Number of files.
    pub files: u64,
    /// Chunk references across every file, before dedupe.
    pub chunk_references: u64,
    /// Chunks stored once.
    pub unique_chunks: u64,
    /// Logical size of every file.
    pub logical_bytes: u64,
    /// Bytes actually stored after dedupe.
    pub stored_bytes: u64,
    /// Exclusions reported in the manifest.
    pub excluded: u64,
}

impl BundleStats {
    /// Bytes saved by storing identical chunks once.
    pub fn dedupe_saved_bytes(&self) -> u64 {
        self.logical_bytes.saturating_sub(self.stored_bytes)
    }
}

/// A built bundle: the manifest and the unique chunk bytes it names.
///
/// `chunks` is keyed and addressed by lower-case hex blake3. `Debug` prints the
/// counts and sizes only; it never dumps chunk bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Bundle {
    /// The deterministic description.
    pub manifest: BundleManifest,
    /// Unique chunk bytes, keyed by hash.
    pub chunks: BTreeMap<String, Vec<u8>>,
}

impl fmt::Debug for Bundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bundle")
            .field("bundle_id", &self.manifest.bundle_id)
            .field("created_ms", &self.manifest.created_ms)
            .field("files", &self.manifest.files.len())
            .field("unique_chunks", &self.chunks.len())
            .field("logical_bytes", &self.manifest.total_bytes)
            .finish()
    }
}

impl Bundle {
    /// Transfer and dedupe numbers.
    pub fn stats(&self) -> BundleStats {
        self.manifest.stats()
    }

    /// Write the manifest and every chunk into `dir` from scratch.
    ///
    /// An existing bundle directory whose manifest is byte-identical is reused;
    /// a different manifest in the same directory is refused.
    pub fn write_to(&self, dir: &Path) -> Result<WriteReport> {
        let mut writer = BundleWriter::create(dir, &self.manifest)?;
        writer.write_pending(&self.chunks)
    }

    /// Write into `dir`, resuming an interrupted transfer when one is present.
    ///
    /// This is the ordinary sender entry point: a first call creates the
    /// directory, a later call loads the checkpoint and writes only what is
    /// missing or corrupt.
    pub fn write_resumable(&self, dir: &Path) -> Result<WriteReport> {
        let mut writer = if dir.join(BUNDLE_MANIFEST_FILE).exists() {
            let writer = BundleWriter::resume(dir)?;
            if writer.manifest.bundle_id != self.manifest.bundle_id
                || writer.manifest.canonical_bytes()? != self.manifest.canonical_bytes()?
            {
                return Err(denied(format!(
                    "a different bundle already occupies `{}`",
                    dir.display()
                )));
            }
            writer
        } else {
            BundleWriter::create(dir, &self.manifest)?
        };
        writer.write_pending(&self.chunks)
    }
}

/// Split `files` into content-addressed chunks.
///
/// Every file becomes a [`FileEntry`] of ordered [`ChunkRef`]s, identical chunks
/// are stored once across the whole bundle, and every chunk hash is verified
/// before it is stored. The returned [`Bundle::manifest`] records the exclusions
/// it was given; nothing is dropped silently.
///
/// Paths must be safe and relative (no absolute prefix, no drive letter, no
/// `.`/`..` component, no backslash). A secret-like path — the vault, an `.env`
/// file, a credential store, a private key — is `zero.pol.denied`: the caller
/// must leave it out and report it in `excluded` instead.
pub fn build<E>(
    files: BTreeMap<String, Vec<u8>>,
    excluded: E,
    config: ChunkConfig,
    now_ms: i64,
) -> Result<Bundle>
where
    E: IntoIterator<Item = Excluded>,
{
    let files = files
        .into_iter()
        .map(|(path, bytes)| (path, BundleFile::file(bytes)))
        .collect();
    build_files(files, excluded, config, now_ms)
}

/// [`build`] for entries that carry a mode or record a symlink.
///
/// A symlink's bytes are its target, which must be a safe relative path. This is
/// the TEL-04 input shape; the T-TEL-02 done criterion only needs regular files.
pub fn build_files<E>(
    files: BTreeMap<String, BundleFile>,
    excluded: E,
    config: ChunkConfig,
    now_ms: i64,
) -> Result<Bundle>
where
    E: IntoIterator<Item = Excluded>,
{
    config.validate()?;
    if files.len() > MAX_FILES {
        return Err(limit(format!(
            "bundle has {} files; the limit is {MAX_FILES}",
            files.len()
        )));
    }
    let excluded = normalize_excluded(excluded)?;

    let mut chunks: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut entries = BTreeMap::new();
    let mut total_chunks = 0u64;
    let mut total_bytes = 0u64;

    for (path, file) in files {
        validate_relative_path(&path)?;
        if crate::snapshot::is_secret_like(&path) {
            return Err(denied(format!(
                "`{path}` looks like a secret and is never bundled; leave it out and report it in `excluded`"
            )));
        }
        if excluded.iter().any(|entry| entry.path == path) {
            return Err(invalid(format!(
                "`{path}` is supplied and also listed as excluded"
            )));
        }
        let bytes = file.bytes;
        if file.symlink {
            let target = std::str::from_utf8(&bytes)
                .map_err(|_| invalid(format!("symlink `{path}` target is not UTF-8")))?;
            validate_relative_path(target)?;
            if target.len() > MAX_PATH_BYTES {
                return Err(limit(format!(
                    "symlink `{path}` target is {} bytes; the limit is {MAX_PATH_BYTES}",
                    target.len()
                )));
            }
        }

        let mut refs = Vec::new();
        for block in bytes.chunks(config.chunk_bytes) {
            let hash = blake3::hash(block).to_hex().to_string();
            if let Some(stored) = chunks.get(&hash) {
                if stored != block {
                    return Err(tamper(format!(
                        "blake3 collision on chunk `{hash}` while building `{path}`"
                    )));
                }
            } else {
                let digest = blake3::hash(block).to_hex().to_string();
                if digest != hash {
                    return Err(tamper(format!(
                        "chunk `{hash}` does not match its own bytes"
                    )));
                }
                chunks.insert(hash.clone(), block.to_vec());
            }
            total_chunks = total_chunks
                .checked_add(1)
                .ok_or_else(|| limit("bundle chunk count overflows"))?;
            if total_chunks as usize > config.max_chunks {
                return Err(limit(format!(
                    "bundle has {total_chunks} chunk references; max_chunks is {}",
                    config.max_chunks
                )));
            }
            refs.push(ChunkRef {
                hash,
                bytes: block.len() as u64,
            });
        }

        let file_bytes = bytes.len() as u64;
        if file_bytes > MAX_BUNDLE_BYTES {
            return Err(limit(format!(
                "file `{path}` is {file_bytes} bytes; the bundle limit is {MAX_BUNDLE_BYTES}"
            )));
        }
        let logical = refs.iter().map(|chunk| chunk.bytes).sum::<u64>();
        if logical != file_bytes {
            return Err(internal(format!(
                "file `{path}` chunks total {logical} bytes; expected {file_bytes}"
            )));
        }
        total_bytes = total_bytes
            .checked_add(file_bytes)
            .ok_or_else(|| limit("bundle size overflows its counter"))?;
        if total_bytes > MAX_BUNDLE_BYTES {
            return Err(limit(format!(
                "bundle files total {total_bytes} bytes; the limit is {MAX_BUNDLE_BYTES}"
            )));
        }

        entries.insert(
            path,
            FileEntry {
                chunks: refs,
                bytes: file_bytes,
                mode: file.mode,
                symlink: file.symlink,
            },
        );
    }

    let bundle_id = derive_bundle_id(BUNDLE_SCHEMA_VERSION, now_ms, &entries, &excluded)?;
    let manifest = BundleManifest {
        schema_version: BUNDLE_SCHEMA_VERSION,
        bundle_id,
        created_ms: now_ms,
        files: entries,
        excluded,
        total_chunks,
        total_bytes,
    };
    // Canonicalisation also cross-checks the declared totals and the id.
    manifest.canonical_bytes()?;

    Ok(Bundle { manifest, chunks })
}

/// Lower-case hex blake3 of a bundle manifest's canonical bytes.
pub fn manifest_hash(manifest: &BundleManifest) -> Result<String> {
    manifest.hash()
}

/// Verify a built [`Bundle`] in memory, without a bundle directory.
///
/// This is the same check [`BundleReader::verify`] runs over a directory: every
/// unique chunk is present, within the chunk cap, and hashes to its key, and
/// every file's chunks total the declared size. It is used by the encrypted
/// transfer to re-check a decrypted bundle before it is handed to the caller.
pub fn verify_bundle(bundle: &Bundle) -> Result<VerifyReport> {
    verify_manifest_chunks(&bundle.manifest, |hash| {
        let bytes = bundle
            .chunks
            .get(hash)
            .ok_or_else(|| tamper(format!("chunk `{hash}` is missing from the bundle")))?;
        if bytes.len() as u64 > MAX_CHUNK_BYTES as u64 {
            return Err(tamper(format!(
                "chunk `{hash}` is {} bytes; the limit is {MAX_CHUNK_BYTES}",
                bytes.len()
            )));
        }
        if blake3::hash(bytes).to_hex().to_string() != hash {
            return Err(tamper(format!(
                "chunk `{hash}` does not match its content hash"
            )));
        }
        Ok(bytes.clone())
    })
}

fn verify_manifest_chunks<F>(manifest: &BundleManifest, mut read_chunk: F) -> Result<VerifyReport>
where
    F: FnMut(&str) -> Result<Vec<u8>>,
{
    let manifest_hash = manifest.hash()?;
    let expected = manifest.chunk_hashes();
    let mut stored_bytes = 0u64;
    for hash in &expected {
        let bytes = read_chunk(hash)?;
        stored_bytes = stored_bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| limit("bundle size overflows its counter"))?;
    }

    for (path, entry) in &manifest.files {
        let mut total = 0u64;
        for chunk in &entry.chunks {
            let bytes = read_chunk(&chunk.hash)?;
            if bytes.len() as u64 != chunk.bytes {
                return Err(tamper(format!(
                    "file `{path}` chunk `{}` is {} bytes but the manifest declares {}",
                    chunk.hash,
                    bytes.len(),
                    chunk.bytes
                )));
            }
            total = total
                .checked_add(chunk.bytes)
                .ok_or_else(|| limit("file size overflows its counter"))?;
        }
        if total != entry.bytes {
            return Err(tamper(format!(
                "file `{path}` chunks total {total} bytes but the manifest declares {}",
                entry.bytes
            )));
        }
    }

    Ok(VerifyReport {
        bundle_id: manifest.bundle_id.clone(),
        manifest_hash,
        files: manifest.files.len() as u64,
        chunks: expected.len() as u64,
        stored_bytes,
        logical_bytes: manifest.total_bytes,
        excluded: manifest.excluded.len() as u64,
    })
}

/// Progress record written after every chunk.
///
/// `written` is the set of chunk hashes whose file is durable. `offsets` records
/// the number of bytes that were durable for each written chunk; it is progress
/// information for a UI. A chunk that is not in `written` is untrusted and is
/// rewritten, including any leftover `.<hash>.part` file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleCheckpoint {
    /// Checkpoint schema version.
    pub schema_version: u32,
    /// The bundle this checkpoint belongs to.
    pub bundle_id: String,
    /// Durable and hash-verified chunk hashes.
    pub written: BTreeSet<String>,
    /// Durable byte count per written chunk.
    #[serde(default)]
    pub offsets: BTreeMap<String, u64>,
}

/// What one [`BundleWriter::write_pending`] call did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteReport {
    /// The bundle written.
    pub bundle_id: String,
    /// Chunks written by this call.
    pub written: u64,
    /// Chunks that were already durable and hash-correct.
    pub already_present: u64,
    /// Chunks whose previous file or partial was corrupt and rewritten.
    pub repaired: u64,
    /// True when every chunk in the manifest is durable and verified.
    pub complete: bool,
    /// Bytes of unique chunks on disk.
    pub stored_bytes: u64,
}

/// A resumable writer for one bundle directory.
///
/// The directory holds `bundle.json`, `checkpoint.json`, and one file per chunk
/// named by its hash. `checkpoint.json` is replaced atomically (write
/// `checkpoint.json.partial`, `sync_all`, rename) after every chunk, so a killed
/// process leaves a usable resume point.
#[derive(Clone)]
pub struct BundleWriter {
    dir: PathBuf,
    manifest: BundleManifest,
    written: BTreeSet<String>,
    offsets: BTreeMap<String, u64>,
}

impl fmt::Debug for BundleWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BundleWriter")
            .field("dir", &self.dir)
            .field("bundle_id", &self.manifest.bundle_id)
            .field("written", &self.written.len())
            .field("chunks", &self.manifest.chunk_hashes().len())
            .finish()
    }
}

impl BundleWriter {
    /// Start a transfer into `dir`, writing the manifest if it is not there.
    ///
    /// A directory that already holds a byte-identical manifest keeps its
    /// checkpoint and chunks; a different manifest, a symlink, or a non-directory
    /// is refused so a bundle is never mixed with another.
    pub fn create(dir: &Path, manifest: &BundleManifest) -> Result<Self> {
        let canonical = manifest.canonical_bytes()?;
        prepare_directory(dir)?;

        let checkpoint_path = dir.join(CHECKPOINT_FILE);
        let expected = manifest.chunk_hashes();
        let (written, offsets) = match read_checkpoint(&checkpoint_path)? {
            Some(checkpoint) => {
                if checkpoint.bundle_id != manifest.bundle_id {
                    return Err(denied(format!(
                        "`{}` holds a checkpoint for a different bundle",
                        checkpoint_path.display()
                    )));
                }
                let written: BTreeSet<String> = checkpoint
                    .written
                    .into_iter()
                    .filter(|hash| expected.contains(hash))
                    .collect();
                let offsets = checkpoint
                    .offsets
                    .into_iter()
                    .filter(|(hash, _)| expected.contains(hash))
                    .collect();
                (written, offsets)
            }
            None => (BTreeSet::new(), BTreeMap::new()),
        };

        let manifest_path = dir.join(BUNDLE_MANIFEST_FILE);
        match fs::symlink_metadata(&manifest_path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(denied(format!(
                        "`{}` is a symlink; the bundle manifest must be a regular file",
                        manifest_path.display()
                    )));
                }
                let stored_bytes = fs::read(&manifest_path).map_err(|error| {
                    io_error(format!("cannot read `{}`", manifest_path.display()), error)
                })?;
                let stored: BundleManifest =
                    serde_json::from_slice(&stored_bytes).map_err(|_| {
                        tamper(format!(
                            "`{}` is not a readable bundle manifest",
                            manifest_path.display()
                        ))
                    })?;
                if stored.canonical_bytes()? != canonical {
                    return Err(denied(format!(
                        "a different bundle already occupies `{}`",
                        dir.display()
                    )));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let json = serde_json::to_vec_pretty(manifest).map_err(|error| {
                    internal(format!("cannot encode the bundle manifest: {error}"))
                })?;
                write_atomic(&manifest_path, &json)?;
            }
            Err(error) => {
                return Err(io_error(
                    format!("cannot inspect `{}`", manifest_path.display()),
                    error,
                ))
            }
        }

        let writer = Self {
            dir: dir.to_path_buf(),
            manifest: manifest.clone(),
            written,
            offsets,
        };
        writer.save_checkpoint()?;
        Ok(writer)
    }

    /// Open an existing bundle directory and load its checkpoint.
    ///
    /// A missing `bundle.json` is `zero.fnd.invalid_input`; a corrupted
    /// checkpoint is `zero.tru.tamper`. The checkpoint's recorded set is
    /// reconciled with the files on disk by [`write_pending`](Self::write_pending).
    pub fn resume(dir: &Path) -> Result<Self> {
        let manifest_path = dir.join(BUNDLE_MANIFEST_FILE);
        let metadata = fs::symlink_metadata(&manifest_path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                invalid(format!(
                    "`{}` has no `{BUNDLE_MANIFEST_FILE}`; it is not a bundle directory",
                    dir.display()
                ))
            } else {
                io_error(
                    format!("cannot inspect `{}`", manifest_path.display()),
                    error,
                )
            }
        })?;
        if metadata.file_type().is_symlink() {
            return Err(denied(format!(
                "`{}` is a symlink; the bundle manifest must be a regular file",
                manifest_path.display()
            )));
        }
        let manifest_bytes = fs::read(&manifest_path).map_err(|error| {
            io_error(format!("cannot read `{}`", manifest_path.display()), error)
        })?;
        let manifest: BundleManifest = serde_json::from_slice(&manifest_bytes).map_err(|_| {
            tamper(format!(
                "`{}` is not a readable bundle manifest",
                manifest_path.display()
            ))
        })?;
        manifest.canonical_bytes()?;

        let checkpoint_path = dir.join(CHECKPOINT_FILE);
        let (written, offsets) = match read_checkpoint(&checkpoint_path)? {
            Some(checkpoint) => {
                if checkpoint.bundle_id != manifest.bundle_id {
                    return Err(denied(format!(
                        "`{}` holds a checkpoint for a different bundle",
                        checkpoint_path.display()
                    )));
                }
                let expected = manifest.chunk_hashes();
                let written = checkpoint
                    .written
                    .into_iter()
                    .filter(|hash| expected.contains(hash))
                    .collect();
                let offsets = checkpoint
                    .offsets
                    .into_iter()
                    .filter(|(hash, _)| expected.contains(hash))
                    .collect();
                (written, offsets)
            }
            None => (BTreeSet::new(), BTreeMap::new()),
        };

        Ok(Self {
            dir: dir.to_path_buf(),
            manifest,
            written,
            offsets,
        })
    }

    /// The bundle directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The manifest being transferred.
    pub fn manifest(&self) -> &BundleManifest {
        &self.manifest
    }

    /// The durable, hash-verified chunks recorded so far.
    pub fn written(&self) -> &BTreeSet<String> {
        &self.written
    }

    /// The checkpoint file for this directory.
    pub fn checkpoint_path(&self) -> PathBuf {
        self.dir.join(CHECKPOINT_FILE)
    }

    /// True when every chunk in the manifest is recorded as durable.
    ///
    /// This reads the checkpoint only; call [`write_pending`](Self::write_pending)
    /// or [`BundleReader::verify`] to hash the files again.
    pub fn is_complete(&self) -> bool {
        self.written.len() == self.manifest.chunk_hashes().len()
    }

    /// Write every missing chunk, repair anything corrupt, and return a report.
    ///
    /// The recorded set is reconciled with the files on disk first: a chunk file
    /// that is missing, truncated, or hash-mismatched is removed from `written`
    /// and rewritten. A needed hash absent from `chunks` is
    /// `zero.fnd.invalid_input`; a supplied chunk whose bytes do not hash to its
    /// key is `zero.tru.tamper`. The checkpoint is replaced after each chunk.
    pub fn write_pending(&mut self, chunks: &BTreeMap<String, Vec<u8>>) -> Result<WriteReport> {
        let expected = self.manifest.chunk_hashes();
        let repaired = self.reconcile(&expected)?;
        let already_present = self.written.len() as u64;

        let mut written = 0u64;
        for hash in &expected {
            if self.written.contains(hash) {
                continue;
            }
            self.write_chunk(hash, chunks)?;
            written += 1;
        }

        for hash in &expected {
            if !self.chunk_ok(hash) {
                return Err(tamper(format!(
                    "chunk `{hash}` is not durable after the transfer"
                )));
            }
        }

        let stored_bytes = expected
            .iter()
            .filter_map(|hash| self.chunk_len(hash))
            .sum();
        Ok(WriteReport {
            bundle_id: self.manifest.bundle_id.clone(),
            written,
            already_present,
            repaired,
            complete: self.written.len() == expected.len(),
            stored_bytes,
        })
    }

    /// Write at most one pending chunk and return its hash.
    ///
    /// This is the progressive-send seam: a caller can stop between chunks, drop
    /// the writer, and resume later. The checkpoint is durable before this
    /// returns.
    pub fn write_one_pending(
        &mut self,
        chunks: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Option<String>> {
        let expected = self.manifest.chunk_hashes();
        self.reconcile(&expected)?;
        for hash in &expected {
            if !self.written.contains(hash) {
                self.write_chunk(hash, chunks)?;
                return Ok(Some(hash.clone()));
            }
        }
        Ok(None)
    }

    fn reconcile(&mut self, expected: &BTreeSet<String>) -> Result<u64> {
        let mut kept = BTreeSet::new();
        let mut offsets = BTreeMap::new();
        let mut repaired = 0u64;
        for hash in std::mem::take(&mut self.written) {
            if expected.contains(&hash) {
                if let Some(len) = self.chunk_len(&hash) {
                    offsets.insert(hash.clone(), len);
                    kept.insert(hash);
                } else {
                    let partial = self.dir.join(format!("{hash}{CHUNK_PARTIAL_SUFFIX}"));
                    let _ = fs::remove_file(&partial);
                    repaired += 1;
                }
            }
        }
        self.written = kept;
        self.offsets = offsets;
        Ok(repaired)
    }

    fn write_chunk(&mut self, hash: &str, chunks: &BTreeMap<String, Vec<u8>>) -> Result<()> {
        let bytes = chunks
            .get(hash)
            .ok_or_else(|| invalid(format!("chunk `{hash}` is missing from the transfer set")))?;
        if bytes.len() as u64 > MAX_CHUNK_BYTES as u64 {
            return Err(limit(format!(
                "chunk `{hash}` is {} bytes; the limit is {MAX_CHUNK_BYTES}",
                bytes.len()
            )));
        }
        if blake3::hash(bytes).to_hex().to_string() != hash {
            return Err(tamper(format!(
                "chunk `{hash}` does not match the bytes supplied for it"
            )));
        }

        let destination = self.dir.join(hash);
        let partial = self.dir.join(format!("{hash}{CHUNK_PARTIAL_SUFFIX}"));
        let _ = fs::remove_file(&partial);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&partial)
            .map_err(|error| io_error(format!("cannot create `{}`", partial.display()), error))?;
        if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(&partial);
            return Err(io_error(
                format!("cannot write `{}`", partial.display()),
                error,
            ));
        }
        drop(file);
        if let Err(error) = fs::rename(&partial, &destination) {
            let _ = fs::remove_file(&partial);
            return Err(io_error(
                format!("cannot move chunk `{hash}` into place"),
                error,
            ));
        }

        self.written.insert(hash.to_string());
        self.offsets.insert(hash.to_string(), bytes.len() as u64);
        self.save_checkpoint()
    }

    fn chunk_ok(&self, hash: &str) -> bool {
        self.chunk_len(hash).is_some()
    }

    fn chunk_len(&self, hash: &str) -> Option<u64> {
        let bytes = fs::read(self.dir.join(hash)).ok()?;
        if bytes.len() as u64 > MAX_CHUNK_BYTES as u64 {
            return None;
        }
        if blake3::hash(&bytes).to_hex().to_string() != hash {
            return None;
        }
        Some(bytes.len() as u64)
    }

    fn save_checkpoint(&self) -> Result<()> {
        let checkpoint = BundleCheckpoint {
            schema_version: BUNDLE_SCHEMA_VERSION,
            bundle_id: self.manifest.bundle_id.clone(),
            written: self.written.clone(),
            offsets: self.offsets.clone(),
        };
        let json = serde_json::to_vec_pretty(&checkpoint)
            .map_err(|error| internal(format!("cannot encode the checkpoint: {error}")))?;
        write_atomic(&self.checkpoint_path(), &json)
    }
}

/// What [`BundleReader::verify`] checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyReport {
    /// The bundle verified.
    pub bundle_id: String,
    /// Lower-case hex blake3 of the canonical manifest.
    pub manifest_hash: String,
    /// Files in the manifest.
    pub files: u64,
    /// Unique chunks read and hashed.
    pub chunks: u64,
    /// Bytes of unique chunks verified.
    pub stored_bytes: u64,
    /// Logical size of every file.
    pub logical_bytes: u64,
    /// Exclusions reported in the manifest.
    pub excluded: u64,
}

/// Policy for [`BundleReader::materialize_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MaterializeOptions {
    /// Create symlinks recorded in the manifest. Off by default, so a manifest
    /// that claims a symlink is refused unless the caller opts in.
    pub allow_symlinks: bool,
}

/// What [`BundleReader::materialize`] wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Materialized {
    /// Target root the files were written under.
    pub directory: PathBuf,
    /// Files in manifest order.
    pub files: Vec<PathBuf>,
    /// Files that already held identical content and were left alone.
    pub already_present: u64,
    /// Lower-case hex blake3 of the canonical manifest.
    pub manifest_hash: String,
}

/// A verified reader for one bundle directory.
#[derive(Debug, Clone)]
pub struct BundleReader {
    dir: PathBuf,
    manifest: BundleManifest,
}

impl BundleReader {
    /// Open `dir` and validate its manifest. Chunks are not read yet.
    pub fn open(dir: &Path) -> Result<Self> {
        let manifest_path = dir.join(BUNDLE_MANIFEST_FILE);
        let metadata = fs::symlink_metadata(&manifest_path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                invalid(format!(
                    "`{}` has no `{BUNDLE_MANIFEST_FILE}`; it is not a bundle directory",
                    dir.display()
                ))
            } else {
                io_error(
                    format!("cannot inspect `{}`", manifest_path.display()),
                    error,
                )
            }
        })?;
        if metadata.file_type().is_symlink() {
            return Err(denied(format!(
                "`{}` is a symlink; the bundle manifest must be a regular file",
                manifest_path.display()
            )));
        }
        let bytes = fs::read(&manifest_path).map_err(|error| {
            io_error(format!("cannot read `{}`", manifest_path.display()), error)
        })?;
        let manifest: BundleManifest = serde_json::from_slice(&bytes).map_err(|_| {
            tamper(format!(
                "`{}` is not a readable bundle manifest",
                manifest_path.display()
            ))
        })?;
        manifest.canonical_bytes()?;
        Ok(Self {
            dir: dir.to_path_buf(),
            manifest,
        })
    }

    /// The bundle directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The manifest as stored.
    pub fn manifest(&self) -> &BundleManifest {
        &self.manifest
    }

    /// Read one chunk by hash, refusing a missing or corrupt file.
    ///
    /// A missing chunk or a hash mismatch is `zero.tru.tamper`.
    pub fn read_chunk(&self, hash: &str) -> Result<Vec<u8>> {
        validate_chunk_hash(hash)?;
        let path = self.dir.join(hash);
        let bytes = fs::read(&path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                tamper(format!("chunk `{hash}` is missing from the bundle"))
            } else {
                io_error(format!("cannot read chunk `{hash}`"), error)
            }
        })?;
        if bytes.len() as u64 > MAX_CHUNK_BYTES as u64 {
            return Err(tamper(format!(
                "chunk `{hash}` is {} bytes; the limit is {MAX_CHUNK_BYTES}",
                bytes.len()
            )));
        }
        if blake3::hash(&bytes).to_hex().to_string() != hash {
            return Err(tamper(format!(
                "chunk `{hash}` does not match its content hash"
            )));
        }
        Ok(bytes)
    }

    /// Check that every file's chunks exist, hash correctly, and match the
    /// manifest's declared sizes.
    ///
    /// Verification is read-only. Missing or corrupt chunks are
    /// `zero.tru.tamper`; a structurally invalid manifest is
    /// `zero.fnd.invalid_input`.
    pub fn verify(&self) -> Result<VerifyReport> {
        verify_manifest_chunks(&self.manifest, |hash| self.read_chunk(hash))
    }

    /// Materialize every file under `target`, refusing symlinks.
    ///
    /// See [`materialize_with`](Self::materialize_with).
    pub fn materialize(&self, target: &Path) -> Result<Materialized> {
        self.materialize_with(target, MaterializeOptions::default())
    }

    /// Verify, then write every file under `target`.
    ///
    /// The bundle is verified before anything is created. A manifest that
    /// records a symlink is refused unless `options.allow_symlinks` is set;
    /// symlink creation is Unix-only. A destination that already holds different
    /// content, is a directory, or is a symlink is refused rather than
    /// overwritten; identical content is counted and left alone. Unix modes are
    /// applied from the manifest and ignored on Windows.
    pub fn materialize_with(
        &self,
        target: &Path,
        options: MaterializeOptions,
    ) -> Result<Materialized> {
        self.verify()?;
        self.check_materialize_policy(options)?;
        if target.as_os_str().is_empty() {
            return Err(invalid("materialize target must not be empty"));
        }
        prepare_directory(target)?;

        let mut files = Vec::with_capacity(self.manifest.files.len());
        let mut already_present = 0u64;
        for (path, entry) in &self.manifest.files {
            validate_relative_path(path)?;
            ensure_parent_dirs(target, path)?;
            let destination = join_relative(target, path);
            let bytes = self.assemble(path, entry)?;

            if entry.symlink {
                let link_target = std::str::from_utf8(&bytes)
                    .map_err(|_| invalid(format!("symlink `{path}` target is not UTF-8")))?;
                validate_relative_path(link_target)?;
                match fs::symlink_metadata(&destination) {
                    Ok(metadata) => {
                        let existing = fs::read_link(&destination).ok();
                        if metadata.file_type().is_symlink()
                            && existing.as_deref() == Some(Path::new(link_target))
                        {
                            already_present += 1;
                            files.push(destination);
                            continue;
                        }
                        return Err(denied(format!(
                            "`{}` already exists and is not the recorded symlink; materialize does not overwrite it",
                            destination.display()
                        )));
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(io_error(
                            format!("cannot inspect `{}`", destination.display()),
                            error,
                        ))
                    }
                }
                create_symlink(link_target, &destination)?;
            } else {
                match fs::symlink_metadata(&destination) {
                    Ok(metadata) => {
                        if metadata.file_type().is_symlink() {
                            return Err(denied(format!(
                                "`{}` is a symlink; materialize refuses to follow it",
                                destination.display()
                            )));
                        }
                        if !metadata.is_file() {
                            return Err(denied(format!(
                                "`{}` exists and is not a file; materialize does not overwrite it",
                                destination.display()
                            )));
                        }
                        let existing = fs::read(&destination).map_err(|error| {
                            io_error(format!("cannot read `{}`", destination.display()), error)
                        })?;
                        if existing == bytes {
                            already_present += 1;
                            files.push(destination);
                            continue;
                        }
                        return Err(denied(format!(
                            "`{}` already holds different content; materialize does not overwrite it",
                            destination.display()
                        )));
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(io_error(
                            format!("cannot inspect `{}`", destination.display()),
                            error,
                        ))
                    }
                }
                write_file(&destination, &bytes, entry.mode)?;
            }
            files.push(destination);
        }

        Ok(Materialized {
            directory: target.to_path_buf(),
            files,
            already_present,
            manifest_hash: self.manifest.hash()?,
        })
    }

    fn check_materialize_policy(&self, options: MaterializeOptions) -> Result<()> {
        for (path, entry) in &self.manifest.files {
            if entry.symlink {
                if !options.allow_symlinks {
                    return Err(denied(format!(
                        "`{path}` is a recorded symlink; materialize requires MaterializeOptions::allow_symlinks"
                    )));
                }
                #[cfg(not(unix))]
                return Err(denied("symlink creation is not supported on this platform"));
            }
        }
        Ok(())
    }

    fn assemble(&self, path: &str, entry: &FileEntry) -> Result<Vec<u8>> {
        let capacity = usize::try_from(entry.bytes)
            .map_err(|_| limit(format!("file `{path}` is too large to materialize here")))?;
        let mut out = Vec::with_capacity(capacity);
        for chunk in &entry.chunks {
            let bytes = self.read_chunk(&chunk.hash)?;
            if bytes.len() as u64 != chunk.bytes {
                return Err(tamper(format!(
                    "file `{path}` chunk `{}` is {} bytes but the manifest declares {}",
                    chunk.hash,
                    bytes.len(),
                    chunk.bytes
                )));
            }
            out.extend_from_slice(&bytes);
        }
        if out.len() as u64 != entry.bytes {
            return Err(tamper(format!(
                "file `{path}` reassembles to {} bytes but the manifest declares {}",
                out.len(),
                entry.bytes
            )));
        }
        Ok(out)
    }
}

fn validate_manifest(manifest: &BundleManifest) -> Result<()> {
    if manifest.schema_version != BUNDLE_SCHEMA_VERSION {
        return Err(ZeroError::new(
            ErrorCode::SchemaVersion,
            format!(
                "bundle schema version {} is not supported; this build reads {BUNDLE_SCHEMA_VERSION}",
                manifest.schema_version
            ),
        ));
    }
    if !is_lower_hex_64(&manifest.bundle_id) {
        return Err(invalid("bundle id must be 64 lower-case hex characters"));
    }
    if manifest.files.len() > MAX_FILES {
        return Err(limit(format!(
            "bundle has {} files; the limit is {MAX_FILES}",
            manifest.files.len()
        )));
    }
    if manifest.total_chunks > MAX_TOTAL_CHUNKS {
        return Err(limit(format!(
            "bundle declares {} chunks; the limit is {MAX_TOTAL_CHUNKS}",
            manifest.total_chunks
        )));
    }
    if manifest.total_bytes > MAX_BUNDLE_BYTES {
        return Err(limit(format!(
            "bundle declares {} bytes; the limit is {MAX_BUNDLE_BYTES}",
            manifest.total_bytes
        )));
    }

    let mut chunks = 0u64;
    let mut bytes = 0u64;
    for (path, entry) in &manifest.files {
        validate_relative_path(path)?;
        if entry.bytes > MAX_BUNDLE_BYTES {
            return Err(limit(format!(
                "file `{path}` declares {} bytes; the limit is {MAX_BUNDLE_BYTES}",
                entry.bytes
            )));
        }
        if entry.symlink && entry.bytes > MAX_PATH_BYTES as u64 {
            return Err(limit(format!(
                "symlink `{path}` target declares {} bytes; the limit is {MAX_PATH_BYTES}",
                entry.bytes
            )));
        }
        let mut file_total = 0u64;
        for chunk in &entry.chunks {
            if !is_lower_hex_64(&chunk.hash) {
                return Err(invalid(format!(
                    "file `{path}` names an invalid chunk hash"
                )));
            }
            if chunk.bytes == 0 || chunk.bytes > MAX_CHUNK_BYTES as u64 {
                return Err(limit(format!(
                    "file `{path}` chunk `{}` declares {} bytes; chunks are 1..={MAX_CHUNK_BYTES}",
                    chunk.hash, chunk.bytes
                )));
            }
            chunks = chunks
                .checked_add(1)
                .ok_or_else(|| limit("bundle chunk count overflows"))?;
            file_total = file_total
                .checked_add(chunk.bytes)
                .ok_or_else(|| limit("file size overflows its counter"))?;
        }
        if file_total != entry.bytes {
            return Err(invalid(format!(
                "file `{path}` chunks total {file_total} bytes but the manifest declares {}",
                entry.bytes
            )));
        }
        bytes = bytes
            .checked_add(entry.bytes)
            .ok_or_else(|| limit("bundle size overflows its counter"))?;
    }
    if chunks != manifest.total_chunks {
        return Err(invalid(format!(
            "manifest declares {} chunks but the files hold {chunks}",
            manifest.total_chunks
        )));
    }
    if bytes != manifest.total_bytes {
        return Err(invalid(format!(
            "manifest declares {} bytes but the files hold {bytes}",
            manifest.total_bytes
        )));
    }

    validate_excluded(&manifest.excluded)?;

    let derived = derive_bundle_id(
        manifest.schema_version,
        manifest.created_ms,
        &manifest.files,
        &manifest.excluded,
    )?;
    if derived != manifest.bundle_id {
        return Err(invalid("bundle id does not match the manifest content"));
    }
    Ok(())
}

pub(crate) fn validate_relative_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(invalid("a bundle path must not be empty"));
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(limit(format!(
            "bundle path is {} bytes; the limit is {MAX_PATH_BYTES}",
            path.len()
        )));
    }
    if path.chars().any(char::is_control) {
        return Err(invalid("a bundle path must not contain control characters"));
    }
    if path.starts_with('/') || path.starts_with('\\') {
        return Err(invalid(format!(
            "bundle path `{path}` must be relative, not absolute"
        )));
    }
    if path.contains('\\') {
        return Err(invalid(format!(
            "bundle path `{path}` must use forward slashes"
        )));
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(invalid(format!(
            "bundle path `{path}` must not carry a drive letter"
        )));
    }
    for component in path.split('/') {
        if component.is_empty() {
            return Err(invalid(format!(
                "bundle path `{path}` has an empty component"
            )));
        }
        if component == "." || component == ".." {
            return Err(invalid(format!(
                "bundle path `{path}` has a traversal component"
            )));
        }
        if component.ends_with('.') || component.ends_with(' ') {
            return Err(invalid(format!(
                "bundle path `{path}` has a component that ends with a dot or space"
            )));
        }
    }
    Ok(())
}

fn normalize_excluded<E>(entries: E) -> Result<Vec<Excluded>>
where
    E: IntoIterator<Item = Excluded>,
{
    let mut entries: Vec<Excluded> = entries.into_iter().collect();
    for entry in &entries {
        validate_relative_path(&entry.path)?;
        if entry.reason.is_empty() {
            return Err(invalid(format!(
                "exclusion `{}` needs a reason",
                entry.path
            )));
        }
        if entry.reason.len() > MAX_EXCLUDED_REASON_BYTES {
            return Err(limit(format!(
                "exclusion `{}` reason is {} bytes; the limit is {MAX_EXCLUDED_REASON_BYTES}",
                entry.path,
                entry.reason.len()
            )));
        }
        if entry.reason.trim() != entry.reason {
            return Err(invalid(format!(
                "exclusion `{}` reason must not start or end with whitespace",
                entry.path
            )));
        }
        if entry.reason.chars().any(char::is_control) {
            return Err(invalid(format!(
                "exclusion `{}` reason must not contain control characters",
                entry.path
            )));
        }
    }
    entries.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.reason.cmp(&right.reason))
    });
    entries.dedup();
    if entries.len() > MAX_EXCLUDED {
        return Err(limit(format!(
            "bundle reports {} exclusions; the limit is {MAX_EXCLUDED}",
            entries.len()
        )));
    }
    Ok(entries)
}

fn validate_excluded(excluded: &[Excluded]) -> Result<()> {
    if excluded.len() > MAX_EXCLUDED {
        return Err(limit(format!(
            "bundle reports {} exclusions; the limit is {MAX_EXCLUDED}",
            excluded.len()
        )));
    }
    let mut previous: Option<&Excluded> = None;
    for entry in excluded {
        validate_relative_path(&entry.path)?;
        if entry.reason.is_empty() {
            return Err(invalid(format!(
                "exclusion `{}` needs a reason",
                entry.path
            )));
        }
        if entry.reason.len() > MAX_EXCLUDED_REASON_BYTES {
            return Err(limit(format!(
                "exclusion `{}` reason is {} bytes; the limit is {MAX_EXCLUDED_REASON_BYTES}",
                entry.path,
                entry.reason.len()
            )));
        }
        if entry.reason.trim() != entry.reason || entry.reason.chars().any(char::is_control) {
            return Err(invalid(format!(
                "exclusion `{}` reason is not a clean label",
                entry.path
            )));
        }
        if let Some(previous) = previous {
            if previous >= entry {
                return Err(invalid(
                    "bundle exclusions must be sorted and unique by path and reason",
                ));
            }
        }
        previous = Some(entry);
    }
    Ok(())
}

fn derive_bundle_id(
    schema_version: u32,
    created_ms: i64,
    files: &BTreeMap<String, FileEntry>,
    excluded: &[Excluded],
) -> Result<String> {
    let mut out = Vec::with_capacity(1024);
    out.extend_from_slice(BUNDLE_ID_DOMAIN);
    out.extend_from_slice(&schema_version.to_be_bytes());
    out.extend_from_slice(&created_ms.to_be_bytes());

    put_count(&mut out, files.len(), MAX_FILES, "files")?;
    for (path, entry) in files {
        put_str(&mut out, path)?;
        out.extend_from_slice(&entry.bytes.to_be_bytes());
        match entry.mode {
            Some(mode) => {
                out.push(1);
                out.extend_from_slice(&mode.to_be_bytes());
            }
            None => out.push(0),
        }
        out.push(u8::from(entry.symlink));
        put_count(
            &mut out,
            entry.chunks.len(),
            MAX_TOTAL_CHUNKS as usize,
            "chunks",
        )?;
        for chunk in &entry.chunks {
            put_str(&mut out, &chunk.hash)?;
            out.extend_from_slice(&chunk.bytes.to_be_bytes());
        }
    }

    put_count(&mut out, excluded.len(), MAX_EXCLUDED, "exclusions")?;
    for entry in excluded {
        put_str(&mut out, &entry.path)?;
        put_str(&mut out, &entry.reason)?;
    }

    Ok(blake3::hash(&out).to_hex().to_string())
}

fn read_checkpoint(path: &Path) -> Result<Option<BundleCheckpoint>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(format!("cannot read `{}`", path.display()), error)),
    };
    let checkpoint: BundleCheckpoint = serde_json::from_slice(&bytes)
        .map_err(|_| tamper(format!("`{}` is not a readable checkpoint", path.display())))?;
    if checkpoint.schema_version != BUNDLE_SCHEMA_VERSION {
        return Err(ZeroError::new(
            ErrorCode::SchemaVersion,
            format!(
                "checkpoint schema version {} is not supported; this build reads {BUNDLE_SCHEMA_VERSION}",
                checkpoint.schema_version
            ),
        ));
    }
    for hash in &checkpoint.written {
        validate_chunk_hash(hash)?;
    }
    Ok(Some(checkpoint))
}

fn prepare_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(denied(format!(
                    "`{}` is a symlink; the bundle requires a real directory",
                    path.display()
                )));
            }
            if !metadata.is_dir() {
                return Err(invalid(format!(
                    "`{}` exists and is not a directory",
                    path.display()
                )));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .map_err(|error| io_error(format!("cannot create `{}`", path.display()), error))?;
        }
        Err(error) => {
            return Err(io_error(
                format!("cannot inspect `{}`", path.display()),
                error,
            ))
        }
    }
    Ok(())
}

fn join_relative(target: &Path, path: &str) -> PathBuf {
    let mut destination = target.to_path_buf();
    for component in path.split('/') {
        destination.push(component);
    }
    destination
}

fn ensure_parent_dirs(target: &Path, path: &str) -> Result<()> {
    let components: Vec<&str> = path.split('/').collect();
    let Some((_, parents)) = components.split_last() else {
        return Err(invalid("a bundle path must not be empty"));
    };
    let mut current = target.to_path_buf();
    for component in parents {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(denied(format!(
                        "`{}` is a symlink; materialize refuses to follow it",
                        current.display()
                    )));
                }
                if !metadata.is_dir() {
                    return Err(invalid(format!(
                        "`{}` exists and is not a directory",
                        current.display()
                    )));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|error| {
                    io_error(format!("cannot create `{}`", current.display()), error)
                })?;
            }
            Err(error) => {
                return Err(io_error(
                    format!("cannot inspect `{}`", current.display()),
                    error,
                ))
            }
        }
    }
    Ok(())
}

fn write_file(destination: &Path, bytes: &[u8], mode: Option<u32>) -> Result<()> {
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid("a bundle file name is not valid UTF-8"))?;
    let suffix = random_u64()?;
    let partial = destination.with_file_name(format!(".{file_name}.{suffix:016x}.part"));

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|error| io_error(format!("cannot create `{}`", partial.display()), error))?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&partial);
        return Err(io_error(
            format!("cannot write `{}`", partial.display()),
            error,
        ));
    }
    drop(file);

    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) = fs::set_permissions(&partial, fs::Permissions::from_mode(mode & 0o7777))
        {
            let _ = fs::remove_file(&partial);
            return Err(io_error(
                format!("cannot set the mode of `{}`", partial.display()),
                error,
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = mode;

    if let Err(error) = fs::rename(&partial, destination) {
        let _ = fs::remove_file(&partial);
        return Err(io_error(
            format!("cannot move `{}` into place", partial.display()),
            error,
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn create_symlink(target: &str, link: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, link)
        .map_err(|error| io_error(format!("cannot create `{}`", link.display()), error))
}

#[cfg(not(unix))]
fn create_symlink(_target: &str, link: &Path) -> Result<()> {
    Err(denied(format!(
        "cannot create symlink `{}`: symlinks are not supported on this platform",
        link.display()
    )))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid("a bundle file name is not valid UTF-8"))?;
    let partial = path.with_file_name(format!("{file_name}.partial"));
    let _ = fs::remove_file(&partial);

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|error| io_error(format!("cannot create `{}`", partial.display()), error))?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&partial);
        return Err(io_error(
            format!("cannot write `{}`", partial.display()),
            error,
        ));
    }
    drop(file);
    if let Err(error) = fs::rename(&partial, path) {
        let _ = fs::remove_file(&partial);
        return Err(io_error(
            format!("cannot move `{}` into place", partial.display()),
            error,
        ));
    }
    Ok(())
}

fn random_u64() -> Result<u64> {
    let mut random = [0u8; 8];
    getrandom::getrandom(&mut random)
        .map_err(|error| internal(format!("cannot read random bytes: {error}")))?;
    Ok(u64::from_be_bytes(random))
}

fn validate_chunk_hash(hash: &str) -> Result<()> {
    if !is_lower_hex_64(hash) {
        return Err(invalid("a chunk hash must be 64 lower-case hex characters"));
    }
    Ok(())
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == BUNDLE_ID_HEX
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn put_str(out: &mut Vec<u8>, value: &str) -> Result<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| limit("a bundle field exceeds the u32 length prefix"))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_count(out: &mut Vec<u8>, count: usize, max: usize, field: &str) -> Result<()> {
    if count > max {
        return Err(limit(format!(
            "bundle has {count} {field}; the limit is {max}"
        )));
    }
    let count =
        u32::try_from(count).map_err(|_| limit(format!("{field} count exceeds a u32 prefix")))?;
    out.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

fn denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyDenied, message)
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn tamper(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::TamperDetected, message)
}

fn limit(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

fn internal(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Internal, message)
}

fn io_error(message: impl Into<String>, error: io::Error) -> ZeroError {
    ZeroError::new(ErrorCode::Internal, format!("{}: {error}", message.into()))
}

type Result<T, E = ZeroError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const NOW: i64 = 1_700_000_000_000;

    fn chunk_config(chunk_bytes: usize) -> ChunkConfig {
        ChunkConfig {
            chunk_bytes,
            max_chunks: 4096,
        }
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|index| (index % 251) as u8).collect()
    }

    fn file_map(entries: &[(&str, Vec<u8>)]) -> BTreeMap<String, Vec<u8>> {
        entries
            .iter()
            .map(|(path, bytes)| ((*path).to_string(), bytes.clone()))
            .collect()
    }

    fn simple_bundle(bytes: &[u8]) -> Bundle {
        build(
            file_map(&[("a.txt", bytes.to_vec())]),
            Vec::<Excluded>::new(),
            chunk_config(1024),
            NOW,
        )
        .expect("build")
    }

    fn read_target(target: &Path, path: &str) -> Vec<u8> {
        fs::read(target.join(path)).expect("read materialized file")
    }

    #[test]
    fn files_split_into_content_addressed_chunks_and_reassemble() {
        let source = pattern(2500);
        let bundle = build(
            file_map(&[("docs/notes.bin", source.clone())]),
            Vec::<Excluded>::new(),
            chunk_config(1000),
            NOW,
        )
        .expect("build");

        let entry = &bundle.manifest.files["docs/notes.bin"];
        assert_eq!(entry.chunks.len(), 3);
        assert_eq!(entry.bytes, 2500);
        assert!(!entry.symlink);
        assert_eq!(entry.mode, None);
        assert_eq!(bundle.manifest.total_chunks, 3);
        assert_eq!(bundle.manifest.total_bytes, 2500);
        assert_eq!(bundle.chunks.len(), 3);

        let mut reassembled = Vec::new();
        for chunk in &entry.chunks {
            let stored = &bundle.chunks[&chunk.hash];
            assert_eq!(stored.len() as u64, chunk.bytes);
            assert_eq!(blake3::hash(stored).to_hex().to_string(), chunk.hash);
            reassembled.extend_from_slice(stored);
        }
        assert_eq!(reassembled, source);

        let dir = TempDir::new().expect("tempdir");
        bundle.write_to(dir.path()).expect("write bundle");
        let reader = BundleReader::open(dir.path()).expect("open bundle");
        assert_eq!(reader.manifest(), &bundle.manifest);
        let report = reader.verify().expect("verify");
        assert_eq!(report.chunks, 3);
        assert_eq!(report.files, 1);
        assert_eq!(report.stored_bytes, 2500);
        assert_eq!(report.logical_bytes, 2500);

        let target = TempDir::new().expect("target");
        reader.materialize(target.path()).expect("materialize");
        assert_eq!(read_target(target.path(), "docs/notes.bin"), source);
    }

    #[test]
    fn identical_chunks_are_stored_once_and_savings_are_reported() {
        let block = pattern(2048);
        let bundle = build(
            file_map(&[("a.bin", block.clone()), ("b.bin", block.clone())]),
            Vec::<Excluded>::new(),
            chunk_config(1024),
            NOW,
        )
        .expect("build");

        assert_eq!(bundle.manifest.total_chunks, 4);
        assert_eq!(bundle.manifest.total_bytes, 4096);
        assert_eq!(bundle.chunks.len(), 2);

        let stats = bundle.stats();
        assert_eq!(stats.files, 2);
        assert_eq!(stats.chunk_references, 4);
        assert_eq!(stats.unique_chunks, 2);
        assert_eq!(stats.logical_bytes, 4096);
        assert_eq!(stats.stored_bytes, 2048);
        assert_eq!(stats.dedupe_saved_bytes(), 2048);

        let dir = TempDir::new().expect("tempdir");
        bundle.write_to(dir.path()).expect("write bundle");
        let reader = BundleReader::open(dir.path()).expect("open bundle");
        let report = reader.verify().expect("verify");
        assert_eq!(report.chunks, 2);
        assert_eq!(report.stored_bytes, 2048);

        let target = TempDir::new().expect("target");
        reader.materialize(target.path()).expect("materialize");
        assert_eq!(read_target(target.path(), "a.bin"), block);
        assert_eq!(read_target(target.path(), "b.bin"), block);
    }

    #[test]
    fn an_empty_file_round_trips() {
        let bundle = build(
            file_map(&[("empty.txt", Vec::new())]),
            Vec::<Excluded>::new(),
            chunk_config(1024),
            NOW,
        )
        .expect("build");
        let entry = &bundle.manifest.files["empty.txt"];
        assert!(entry.chunks.is_empty());
        assert_eq!(entry.bytes, 0);
        assert_eq!(bundle.manifest.total_chunks, 0);
        assert!(bundle.chunks.is_empty());

        let dir = TempDir::new().expect("tempdir");
        bundle.write_to(dir.path()).expect("write bundle");
        let reader = BundleReader::open(dir.path()).expect("open bundle");
        assert_eq!(reader.verify().expect("verify").chunks, 0);

        let target = TempDir::new().expect("target");
        reader.materialize(target.path()).expect("materialize");
        let metadata = fs::metadata(target.path().join("empty.txt")).expect("empty file");
        assert_eq!(metadata.len(), 0);
    }

    #[test]
    fn a_multi_chunk_file_materializes_byte_identically() {
        let data = pattern(5000);
        let bundle = build(
            file_map(&[("data/big.bin", data.clone())]),
            Vec::<Excluded>::new(),
            chunk_config(512),
            NOW,
        )
        .expect("build");
        assert_eq!(bundle.manifest.files["data/big.bin"].chunks.len(), 10);
        assert_eq!(bundle.manifest.files["data/big.bin"].bytes, 5000);

        let dir = TempDir::new().expect("tempdir");
        bundle.write_resumable(dir.path()).expect("write bundle");
        let reader = BundleReader::open(dir.path()).expect("open bundle");
        let report = reader.verify().expect("verify");
        assert_eq!(report.chunks, 10);
        assert_eq!(
            report.manifest_hash,
            manifest_hash(&bundle.manifest).expect("hash")
        );

        let target = TempDir::new().expect("target");
        let materialized = reader.materialize(target.path()).expect("materialize");
        assert_eq!(materialized.files.len(), 1);
        assert_eq!(materialized.already_present, 0);
        assert_eq!(read_target(target.path(), "data/big.bin"), data);
    }

    #[test]
    fn an_interrupted_bundle_resumes() {
        let one = pattern(1200);
        let two = pattern(1500);
        let files = file_map(&[("one.bin", one.clone()), ("two.bin", two.clone())]);
        let bundle = build(files, Vec::<Excluded>::new(), chunk_config(400), NOW).expect("build");
        let total_unique = bundle.manifest.chunk_hashes().len();
        assert!(total_unique > 2);

        let dir = TempDir::new().expect("tempdir");
        let mut writer = BundleWriter::create(dir.path(), &bundle.manifest).expect("create");
        assert!(writer
            .write_one_pending(&bundle.chunks)
            .expect("first chunk")
            .is_some());
        assert!(writer
            .write_one_pending(&bundle.chunks)
            .expect("second chunk")
            .is_some());
        assert_eq!(writer.written().len(), 2);
        assert!(!writer.is_complete());
        drop(writer);

        let checkpoint: BundleCheckpoint = serde_json::from_slice(
            &fs::read(dir.path().join(CHECKPOINT_FILE)).expect("checkpoint"),
        )
        .expect("checkpoint json");
        assert_eq!(checkpoint.bundle_id, bundle.manifest.bundle_id);
        assert_eq!(checkpoint.written.len(), 2);
        assert_eq!(checkpoint.offsets.len(), 2);
        assert!(dir.path().join(BUNDLE_MANIFEST_FILE).exists());

        let mut resumed = BundleWriter::resume(dir.path()).expect("resume");
        assert_eq!(resumed.written().len(), 2);
        let report = resumed.write_pending(&bundle.chunks).expect("finish");
        assert!(report.complete);
        assert_eq!(report.already_present, 2);
        assert_eq!(report.written as usize, total_unique - 2);
        assert_eq!(resumed.written().len(), total_unique);
        assert!(resumed.is_complete());
        assert_eq!(
            resumed.write_one_pending(&bundle.chunks).expect("complete"),
            None
        );

        let reader = BundleReader::open(dir.path()).expect("open bundle");
        let verified = reader.verify().expect("verify resumed bundle");
        assert_eq!(verified.chunks as usize, total_unique);

        let target = TempDir::new().expect("target");
        let materialized = reader.materialize(target.path()).expect("materialize");
        assert_eq!(materialized.files.len(), 2);
        assert_eq!(read_target(target.path(), "one.bin"), one);
        assert_eq!(read_target(target.path(), "two.bin"), two);
        assert_eq!(
            materialized.manifest_hash,
            manifest_hash(&bundle.manifest).expect("hash")
        );
    }

    #[test]
    fn a_corrupted_or_missing_chunk_is_rewritten_on_resume() {
        let bundle = build(
            file_map(&[("one.txt", b"one".to_vec()), ("two.txt", b"two".to_vec())]),
            Vec::<Excluded>::new(),
            chunk_config(1024),
            NOW,
        )
        .expect("build");
        let hashes: Vec<String> = bundle.manifest.chunk_hashes().into_iter().collect();
        assert_eq!(hashes.len(), 2);

        let dir = TempDir::new().expect("tempdir");
        bundle.write_to(dir.path()).expect("write bundle");
        fs::write(dir.path().join(&hashes[0]), b"corrupted").expect("corrupt chunk");
        fs::remove_file(dir.path().join(&hashes[1])).expect("delete chunk");

        let mut writer = BundleWriter::resume(dir.path()).expect("resume");
        assert_eq!(writer.written().len(), 2);
        let report = writer.write_pending(&bundle.chunks).expect("repair");
        assert!(report.complete);
        assert_eq!(report.already_present, 0);
        assert_eq!(report.repaired, 2);
        assert_eq!(report.written, 2);

        let reader = BundleReader::open(dir.path()).expect("open bundle");
        reader.verify().expect("repaired bundle verifies");
        let target = TempDir::new().expect("target");
        reader.materialize(target.path()).expect("materialize");
        assert_eq!(read_target(target.path(), "one.txt"), b"one");
        assert_eq!(read_target(target.path(), "two.txt"), b"two");
    }

    #[test]
    fn a_missing_chunk_is_a_typed_error() {
        let bundle = simple_bundle(b"alpha");
        let dir = TempDir::new().expect("tempdir");
        bundle.write_to(dir.path()).expect("write bundle");
        let hash = bundle
            .manifest
            .chunk_hashes()
            .into_iter()
            .next()
            .expect("chunk");
        fs::remove_file(dir.path().join(&hash)).expect("delete chunk");

        let reader = BundleReader::open(dir.path()).expect("open bundle");
        assert_eq!(
            reader.verify().expect_err("missing chunk").code(),
            ErrorCode::TamperDetected
        );
        assert_eq!(
            reader.read_chunk(&hash).expect_err("missing chunk").code(),
            ErrorCode::TamperDetected
        );
        assert_eq!(
            reader
                .read_chunk("not-a-hash")
                .expect_err("malformed hash")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut chunks = bundle.chunks.clone();
        chunks.remove(&hash);
        let mut writer = BundleWriter::resume(dir.path()).expect("resume");
        assert_eq!(
            writer
                .write_pending(&chunks)
                .expect_err("the transfer set is incomplete")
                .code(),
            ErrorCode::InvalidInput
        );

        let missing = dir.path().join("not-a-bundle");
        assert_eq!(
            BundleWriter::resume(&missing)
                .expect_err("no manifest")
                .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            BundleReader::open(&missing)
                .expect_err("no manifest")
                .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn the_manifest_hash_is_content_bound_and_tamper_is_refused() {
        let first = build(
            file_map(&[("a.txt", b"alpha".to_vec())]),
            Vec::<Excluded>::new(),
            chunk_config(1024),
            NOW,
        )
        .expect("build");
        let second = build(
            file_map(&[("a.txt", b"alpha".to_vec())]),
            Vec::<Excluded>::new(),
            chunk_config(1024),
            NOW,
        )
        .expect("build");
        assert_eq!(first.manifest.bundle_id, second.manifest.bundle_id);
        assert_eq!(
            manifest_hash(&first.manifest).expect("hash"),
            manifest_hash(&second.manifest).expect("hash")
        );
        assert_ne!(
            manifest_hash(&first.manifest).expect("hash"),
            manifest_hash(
                &build(
                    file_map(&[("a.txt", b"beta".to_vec())]),
                    Vec::<Excluded>::new(),
                    chunk_config(1024),
                    NOW,
                )
                .expect("build")
                .manifest
            )
            .expect("hash")
        );

        let mut wrong_bytes = first.manifest.clone();
        wrong_bytes.files.get_mut("a.txt").expect("entry").bytes += 1;
        assert_eq!(
            wrong_bytes
                .canonical_bytes()
                .expect_err("sum mismatch")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut wrong_id = first.manifest.clone();
        wrong_id
            .files
            .get_mut("a.txt")
            .expect("entry")
            .chunks
            .first_mut()
            .expect("chunk")
            .hash = "a".repeat(BUNDLE_ID_HEX);
        assert_eq!(
            wrong_id
                .canonical_bytes()
                .expect_err("content-bound id")
                .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            manifest_hash(&wrong_id)
                .expect_err("content-bound id")
                .code(),
            ErrorCode::InvalidInput
        );

        let dir = TempDir::new().expect("tempdir");
        first.write_to(dir.path()).expect("write bundle");
        let hash = first
            .manifest
            .chunk_hashes()
            .into_iter()
            .next()
            .expect("chunk");
        fs::write(dir.path().join(&hash), b"tampered").expect("tamper chunk");
        let reader = BundleReader::open(dir.path()).expect("open bundle");
        assert_eq!(
            reader.verify().expect_err("tampered chunk").code(),
            ErrorCode::TamperDetected
        );

        let manifest_path = dir.path().join(BUNDLE_MANIFEST_FILE);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
                .expect("manifest json");
        let declared = value["total_bytes"].as_u64().expect("total bytes");
        value["total_bytes"] = serde_json::json!(declared + 1);
        fs::write(
            &manifest_path,
            serde_json::to_vec(&value).expect("encode manifest"),
        )
        .expect("write manifest");
        assert_eq!(
            BundleReader::open(dir.path())
                .expect_err("tampered manifest")
                .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn unsafe_paths_and_symlink_targets_are_rejected() {
        for path in [
            "",
            ".",
            "..",
            "/etc/passwd",
            "C:/Windows/system32",
            "a/../../b",
            "a/./b",
            "a//b",
            "a\\b",
            "dir/",
            "trailing.",
            "trailing ",
        ] {
            let error = build(
                file_map(&[(path, b"value".to_vec())]),
                Vec::<Excluded>::new(),
                chunk_config(1024),
                NOW,
            )
            .expect_err("unsafe path");
            assert_eq!(error.code(), ErrorCode::InvalidInput, "{path:?}");
        }

        for target in ["../escape", "/absolute", "C:/windows"] {
            let mut files = BTreeMap::new();
            files.insert("link".to_string(), BundleFile::symlink(target));
            assert_eq!(
                build_files(files, Vec::<Excluded>::new(), chunk_config(1024), NOW)
                    .expect_err("unsafe symlink target")
                    .code(),
                ErrorCode::InvalidInput,
                "{target:?}"
            );
        }
    }

    #[test]
    fn exclusions_are_reported_and_never_silently_dropped() {
        let excluded = vec![
            Excluded::new(".zero/vault", "secret vault"),
            Excluded::new(".env", "credentials"),
            Excluded::new(".env", "credentials"),
        ];
        let files = file_map(&[("notes.txt", b"notes".to_vec())]);
        let bundle = build(files.clone(), excluded, chunk_config(1024), NOW).expect("build");
        assert_eq!(bundle.manifest.excluded.len(), 2);
        assert_eq!(bundle.manifest.excluded[0].path, ".env");
        assert_eq!(bundle.manifest.excluded[0].reason, "credentials");
        assert_eq!(bundle.manifest.excluded[1].path, ".zero/vault");
        assert_eq!(
            bundle.manifest.stats().excluded,
            bundle.manifest.excluded.len() as u64
        );

        let dir = TempDir::new().expect("tempdir");
        bundle.write_to(dir.path()).expect("write bundle");
        let reader = BundleReader::open(dir.path()).expect("open bundle");
        assert_eq!(reader.manifest().excluded, bundle.manifest.excluded);
        assert_eq!(reader.verify().expect("verify").excluded, 2);

        let without = build(files, Vec::<Excluded>::new(), chunk_config(1024), NOW).expect("build");
        assert_ne!(without.manifest.bundle_id, bundle.manifest.bundle_id);

        assert_eq!(
            build(
                file_map(&[("notes.txt", b"notes".to_vec())]),
                vec![Excluded::new("notes.txt", "user excluded")],
                chunk_config(1024),
                NOW,
            )
            .expect_err("a supplied file cannot also be excluded")
            .code(),
            ErrorCode::InvalidInput
        );

        assert_eq!(
            build(
                file_map(&[(".zero/vault/project.db", b"secret".to_vec())]),
                Vec::<Excluded>::new(),
                chunk_config(1024),
                NOW,
            )
            .expect_err("a secret path is never bundled")
            .code(),
            ErrorCode::PolicyDenied
        );

        assert_eq!(
            build(
                file_map(&[("notes.txt", b"notes".to_vec())]),
                vec![Excluded::new("", "empty path")],
                chunk_config(1024),
                NOW,
            )
            .expect_err("an exclusion needs a path")
            .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn materialize_never_overwrites_different_content() {
        let bundle = build(
            file_map(&[("dir/sub/a.txt", b"alpha".to_vec())]),
            Vec::<Excluded>::new(),
            chunk_config(1024),
            NOW,
        )
        .expect("build");
        let dir = TempDir::new().expect("tempdir");
        bundle.write_to(dir.path()).expect("write bundle");
        let reader = BundleReader::open(dir.path()).expect("open bundle");
        let target = TempDir::new().expect("target");

        let first = reader.materialize(target.path()).expect("materialize");
        assert_eq!(first.files.len(), 1);
        assert_eq!(first.already_present, 0);
        assert_eq!(read_target(target.path(), "dir/sub/a.txt"), b"alpha");

        let second = reader.materialize(target.path()).expect("repeat");
        assert_eq!(second.already_present, 1);

        let path = target.path().join("dir/sub/a.txt");
        fs::write(&path, b"different").expect("edit target");
        assert_eq!(
            reader
                .materialize(target.path())
                .expect_err("different content")
                .code(),
            ErrorCode::PolicyDenied
        );
        assert_eq!(fs::read(&path).expect("unchanged"), b"different");

        fs::remove_file(&path).expect("remove target");
        reader.materialize(target.path()).expect("restore");
        assert_eq!(fs::read(&path).expect("restored"), b"alpha");

        fs::remove_file(&path).expect("remove target");
        fs::create_dir(&path).expect("directory in the way");
        assert_eq!(
            reader
                .materialize(target.path())
                .expect_err("directory in the way")
                .code(),
            ErrorCode::PolicyDenied
        );
    }

    #[test]
    fn symlinks_are_refused_unless_recorded_and_allowed() {
        let mut files = BTreeMap::new();
        files.insert("real.txt".to_string(), BundleFile::file(b"real".to_vec()));
        files.insert(
            "link.txt".to_string(),
            BundleFile::symlink(b"real.txt".to_vec()),
        );
        let bundle =
            build_files(files, Vec::<Excluded>::new(), chunk_config(1024), NOW).expect("build");
        let entry = &bundle.manifest.files["link.txt"];
        assert!(entry.symlink);
        assert_eq!(entry.bytes, 8);

        let dir = TempDir::new().expect("tempdir");
        bundle.write_to(dir.path()).expect("write bundle");
        let reader = BundleReader::open(dir.path()).expect("open bundle");
        reader.verify().expect("verify");

        let target = TempDir::new().expect("target");
        let error = reader
            .materialize(target.path())
            .expect_err("symlink refused");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(!target.path().join("real.txt").exists());

        #[cfg(unix)]
        {
            let materialized = reader
                .materialize_with(
                    target.path(),
                    MaterializeOptions {
                        allow_symlinks: true,
                    },
                )
                .expect("materialize symlink");
            assert_eq!(materialized.files.len(), 2);
            assert_eq!(
                fs::read_link(target.path().join("link.txt")).expect("read link"),
                PathBuf::from("real.txt")
            );
            assert_eq!(read_target(target.path(), "real.txt"), b"real");
        }
        #[cfg(not(unix))]
        {
            assert_eq!(
                reader
                    .materialize_with(
                        target.path(),
                        MaterializeOptions {
                            allow_symlinks: true,
                        },
                    )
                    .expect_err("symlink creation is Unix-only")
                    .code(),
                ErrorCode::PolicyDenied
            );
        }
    }

    #[test]
    fn modes_are_recorded_and_applied_on_unix() {
        let mut files = BTreeMap::new();
        files.insert(
            "bin/run.sh".to_string(),
            BundleFile::file(b"#!/bin/sh\n".to_vec()).with_mode(0o640),
        );
        let bundle =
            build_files(files, Vec::<Excluded>::new(), chunk_config(1024), NOW).expect("build");
        assert_eq!(bundle.manifest.files["bin/run.sh"].mode, Some(0o640));

        let dir = TempDir::new().expect("tempdir");
        bundle.write_to(dir.path()).expect("write bundle");
        let reader = BundleReader::open(dir.path()).expect("open bundle");
        let target = TempDir::new().expect("target");
        reader.materialize(target.path()).expect("materialize");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(target.path().join("bin/run.sh")).expect("metadata");
            assert_eq!(metadata.permissions().mode() & 0o777, 0o640);
        }
        assert_eq!(read_target(target.path(), "bin/run.sh"), b"#!/bin/sh\n");
    }

    #[test]
    fn the_manifest_and_checkpoint_survive_serde() {
        let bundle = simple_bundle(b"alpha");
        let json = serde_json::to_vec(&bundle.manifest).expect("encode manifest");
        let restored: BundleManifest = serde_json::from_slice(&json).expect("decode manifest");
        assert_eq!(restored, bundle.manifest);
        assert_eq!(
            restored.canonical_bytes().expect("canonical"),
            bundle.manifest.canonical_bytes().expect("canonical")
        );
        assert_eq!(
            manifest_hash(&restored).expect("hash"),
            manifest_hash(&bundle.manifest).expect("hash")
        );

        let checkpoint = BundleCheckpoint {
            schema_version: BUNDLE_SCHEMA_VERSION,
            bundle_id: bundle.manifest.bundle_id.clone(),
            written: bundle.manifest.chunk_hashes(),
            offsets: bundle
                .chunks
                .iter()
                .map(|(hash, bytes)| (hash.clone(), bytes.len() as u64))
                .collect(),
        };
        let json = serde_json::to_vec(&checkpoint).expect("encode checkpoint");
        let restored: BundleCheckpoint = serde_json::from_slice(&json).expect("decode checkpoint");
        assert_eq!(restored, checkpoint);
    }

    #[test]
    fn a_bundle_directory_refuses_a_different_manifest() {
        let first = simple_bundle(b"alpha");
        let second = simple_bundle(b"beta");
        assert_ne!(first.manifest.bundle_id, second.manifest.bundle_id);

        let dir = TempDir::new().expect("tempdir");
        first.write_to(dir.path()).expect("write bundle");
        assert_eq!(
            BundleWriter::create(dir.path(), &second.manifest)
                .expect_err("a different bundle already occupies the directory")
                .code(),
            ErrorCode::PolicyDenied
        );

        let mut writer = BundleWriter::create(dir.path(), &first.manifest).expect("reopen");
        assert!(writer.is_complete());
        assert_eq!(writer.written().len(), 1);
        assert_eq!(
            writer
                .write_pending(&first.chunks)
                .expect("idempotent")
                .written,
            0
        );
        assert_eq!(
            second
                .write_resumable(dir.path())
                .expect_err("resume refuses another bundle")
                .code(),
            ErrorCode::PolicyDenied
        );
    }

    #[test]
    fn chunk_configuration_is_validated() {
        assert_eq!(ChunkConfig::default().chunk_bytes, DEFAULT_CHUNK_BYTES);
        assert_eq!(
            ChunkConfig::new(1024, 16).expect("valid"),
            ChunkConfig {
                chunk_bytes: 1024,
                max_chunks: 16
            }
        );
        assert_eq!(
            ChunkConfig::new(0, 16).expect_err("zero chunks").code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            ChunkConfig::new(MAX_CHUNK_BYTES + 1, 16)
                .expect_err("oversized chunk")
                .code(),
            ErrorCode::LimitExceeded
        );
        assert_eq!(
            ChunkConfig::new(1024, 0)
                .expect_err("zero max chunks")
                .code(),
            ErrorCode::InvalidInput
        );
    }
}
