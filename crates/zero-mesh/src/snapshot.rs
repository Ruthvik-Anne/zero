//! Teleport snapshots and same-device restore (T-TEL-01, TEL-01, TEL-03,
//! TODO-07).
//!
//! A [`Snapshot`] is the portable state teleport moves between hosts: the
//! session transcript, kernel state, artifacts, goals, schedules, the usage
//! ledger, and the workspace manifest. Every component is caller-supplied
//! opaque bytes, so this module has no dependency on the session, kernel, task,
//! or scheduler crates. The [`SnapshotManifest`] records only a size, a blake3
//! hash, and a kind label per component — never a component value.
//!
//! [`create`] validates the component set, hashes every blob, derives a
//! content-bound [`snapshot_id`](SnapshotManifest::snapshot_id), and signs the
//! canonical manifest with the device's Ed25519 key. [`verify`] checks the
//! signature, the manifest shape, and every blob hash, so a tampered or partial
//! snapshot is refused before anything is written. [`restore`] then writes the
//! components under `target_root/.zero/teleport/snap-<id>/`, each file through
//! a temporary file and a rename, with the signed manifest written last and a
//! refusal to overwrite a different snapshot.
//!
//! Scope: this is the snapshot and the **same-device** restore only. The
//! content-addressed bundle (`TEL-02`) and the encrypted transfer (`TEL-03`,
//! `TEL-06`) live in [`crate::bundle`] and [`crate::transfer`].
//! [`crate::portability`] covers path remapping, the kernel rebuild plan, and
//! tool preflight (`TEL-06`, `TEL-12`), and [`crate::fence`] covers the write
//! lease (`TEL-05`). The vault travelling as ciphertext (`TEL-07`) is a later
//! task. No socket is opened, and no secret value enters the manifest.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, ZeroError};

use crate::identity::{verify as verify_signature, KeyPair};

/// Snapshot manifest schema this build reads and writes.
pub const SCHEMA_VERSION: u32 = 1;

/// Largest single component: 16 MiB.
///
/// Snapshot components are structured session and kernel state. Workspace files
/// travel in the content-addressed bundle (`TEL-02`), not here.
pub const MAX_COMPONENT_BYTES: usize = 16 * 1024 * 1024;

/// Largest sum of all component blobs: 64 MiB.
pub const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;

/// Largest canonical manifest: 64 KiB.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;

/// Most exclusion labels a manifest may report.
pub const MAX_EXCLUDED: usize = 256;

/// Longest exclusion label, in bytes.
pub const MAX_EXCLUDED_BYTES: usize = 256;

/// Longest project id, in bytes.
pub const MAX_PROJECT_ID_BYTES: usize = 128;

/// Length of a snapshot id: 64 lower-case hex characters (32 bytes).
pub const SNAPSHOT_ID_HEX: usize = 64;

/// Directory under the target root that holds teleport snapshots.
pub const TELEPORT_DIR: &str = ".zero/teleport";

/// The signed snapshot manifest file written inside each snapshot directory.
pub const MANIFEST_FILE: &str = "snapshot.json";

/// Domain separator for the signed snapshot manifest.
pub const MANIFEST_DOMAIN: &[u8] = b"zero.teleport.manifest.v1\0";

/// Domain separator for the content-derived snapshot id.
pub const SNAPSHOT_ID_DOMAIN: &[u8] = b"zero.teleport.snapshot-id.v1\0";

/// One component of a teleport snapshot.
///
/// The set is closed: exactly the seven components TEL-03 names. A path such as
/// `.zero/vault` or a credential store cannot be represented, which is the
/// structural half of TEL-05's secret exclusion. [`classify_component`] applies
/// the same rule when a caller has a label from a bundle or workspace manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Component {
    /// Session transcript and its entries.
    Session,
    /// Kernel state or the log-derived kernel checkpoint.
    Kernel,
    /// Artifact index for the session.
    Artifacts,
    /// Goals and their accounting.
    Goals,
    /// Schedules and heartbeats.
    Schedules,
    /// Usage ledger.
    Ledger,
    /// Workspace manifest (paths, types, sizes, hashes).
    Manifest,
}

impl Component {
    /// Every component, in deterministic order.
    pub const ALL: [Component; 7] = [
        Component::Session,
        Component::Kernel,
        Component::Artifacts,
        Component::Goals,
        Component::Schedules,
        Component::Ledger,
        Component::Manifest,
    ];

    /// The components a snapshot must carry.
    pub const REQUIRED: [Component; 3] = [
        Component::Session,
        Component::Kernel,
        Component::Manifest,
    ];

    /// Stable lower-case label, also the file name inside a snapshot directory.
    pub fn as_str(self) -> &'static str {
        match self {
            Component::Session => "session",
            Component::Kernel => "kernel",
            Component::Artifacts => "artifacts",
            Component::Goals => "goals",
            Component::Schedules => "schedules",
            Component::Ledger => "ledger",
            Component::Manifest => "manifest",
        }
    }

    /// Content-kind label recorded in the manifest for a UI.
    pub fn kind(self) -> &'static str {
        match self {
            Component::Session => "session-transcript",
            Component::Kernel => "kernel-checkpoint",
            Component::Artifacts => "artifact-index",
            Component::Goals => "goal-state",
            Component::Schedules => "schedule-state",
            Component::Ledger => "usage-ledger",
            Component::Manifest => "workspace-manifest",
        }
    }

    /// True for session, kernel, and workspace manifest.
    pub fn is_required(self) -> bool {
        Component::REQUIRED.contains(&self)
    }

    /// True for artifacts, goals, schedules, and the usage ledger.
    pub fn is_optional(self) -> bool {
        !self.is_required()
    }

    /// The file name used inside a snapshot directory. Fixed, path-safe, and
    /// never derived from caller text.
    pub fn file_name(self) -> &'static str {
        self.as_str()
    }
}

/// One caller-supplied component blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentBlob {
    /// Which component this blob carries.
    pub component: Component,
    /// Opaque component bytes.
    pub bytes: Vec<u8>,
}

impl ComponentBlob {
    /// Build a blob for a known component.
    pub fn new(component: Component, bytes: Vec<u8>) -> Self {
        Self { component, bytes }
    }

    /// Build a blob from a caller-supplied label, refusing a secret-like path
    /// and any label outside the seven components.
    ///
    /// A `Component` value cannot express `.zero/vault` or a credential store;
    /// this constructor is the gate for labels that come from outside the type,
    /// such as a workspace or bundle manifest entry.
    pub fn from_label(label: &str, bytes: Vec<u8>) -> Result<Self> {
        Ok(Self {
            component: classify_component(label)?,
            bytes,
        })
    }
}

/// What the manifest records about one component.
///
/// There is no value, preview, or path field: only the size, the blake3 digest,
/// and the fixed kind label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentMeta {
    /// Length of the blob in bytes.
    pub bytes: usize,
    /// Lower-case hex blake3 digest of the blob.
    pub blake3: String,
    /// Stable content-kind label, for example `kernel-checkpoint`.
    pub kind: String,
}

/// The signed description of a snapshot.
///
/// `components` is a `BTreeMap`, so encoding and display order is the
/// component order rather than insertion order. `excluded` is sorted and
/// deduplicated, and reports the secret-like paths the caller left out
/// (TEL-05). The manifest carries hashes and sizes, never blob values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    /// Manifest schema version.
    pub schema_version: u32,
    /// Deterministic id derived from this manifest's content.
    pub snapshot_id: String,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_ms: i64,
    /// Project the snapshot belongs to; a display and identity label only.
    pub project_id: String,
    /// Every component present, with its size and hash.
    pub components: BTreeMap<Component, ComponentMeta>,
    /// Secret-like paths deliberately left out, sorted and unique.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded: Vec<String>,
}

impl SnapshotManifest {
    /// The canonical, deterministic bytes the device signs.
    ///
    /// Layout, all integers big-endian and every variable field length-prefixed:
    ///
    /// ```text
    /// "zero.teleport.manifest.v1\0"   domain separator
    /// schema_version                  u32
    /// snapshot_id                     u32 length + UTF-8
    /// created_ms                      i64
    /// project_id                      u32 length + UTF-8
    /// component count                 u32
    /// repeated components, ascending:
    ///   component label               u32 length + UTF-8
    ///   kind                          u32 length + UTF-8
    ///   bytes                         u64
    ///   blake3                        u32 length + UTF-8
    /// excluded count                  u32
    /// repeated exclusions, sorted:    u32 length + UTF-8
    /// ```
    ///
    /// Validation is part of canonicalisation: the schema version, snapshot id,
    /// project id, required components, per-component and total size caps,
    /// kind labels, 64-hex digests, exclusion bounds and ordering, and the
    /// content-derived snapshot id are all checked first.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        validate_manifest(self)?;

        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(MANIFEST_DOMAIN);
        out.extend_from_slice(&self.schema_version.to_be_bytes());
        put_str(&mut out, &self.snapshot_id)?;
        out.extend_from_slice(&self.created_ms.to_be_bytes());
        put_str(&mut out, &self.project_id)?;

        put_count(
            &mut out,
            self.components.len(),
            Component::ALL.len(),
            "components",
        )?;
        for (component, meta) in &self.components {
            put_str(&mut out, component.as_str())?;
            put_str(&mut out, &meta.kind)?;
            let bytes = u64::try_from(meta.bytes)
                .map_err(|_| limit("a component size exceeds the u64 encoding"))?;
            out.extend_from_slice(&bytes.to_be_bytes());
            put_str(&mut out, &meta.blake3)?;
        }

        put_count(&mut out, self.excluded.len(), MAX_EXCLUDED, "excluded entries")?;
        for entry in &self.excluded {
            put_str(&mut out, entry)?;
        }

        if out.len() > MAX_MANIFEST_BYTES {
            return Err(limit(format!(
                "snapshot manifest is {} bytes; the limit is {MAX_MANIFEST_BYTES}",
                out.len()
            )));
        }
        Ok(out)
    }

    /// Optional components this snapshot does not carry.
    ///
    /// Absence is normal (only session, kernel, and the workspace manifest are
    /// required), but a UI can show what was not included.
    pub fn missing_optional(&self) -> Vec<Component> {
        Component::ALL
            .iter()
            .copied()
            .filter(|component| component.is_optional() && !self.components.contains_key(component))
            .collect()
    }
}

/// A complete snapshot: the signed manifest and the opaque component blobs.
///
/// `blobs` is sorted by [`Component`], so two snapshots with the same content
/// have the same in-memory and JSON shape. `signature_b64` is the device key's
/// Ed25519 signature over the manifest's
/// [`canonical_bytes`](SnapshotManifest::canonical_bytes) and is **not** covered
/// by its own signature.
///
/// `Debug` prints ids, sizes, component names, and the signature length only:
/// it never prints a blob or the signature value.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    /// The signed description.
    pub manifest: SnapshotManifest,
    /// Component bytes, keyed by component.
    pub blobs: BTreeMap<Component, Vec<u8>>,
    /// Standard padded base64 Ed25519 signature over the canonical manifest.
    #[serde(default)]
    pub signature_b64: String,
}

impl fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let components: Vec<&str> = self
            .manifest
            .components
            .keys()
            .map(|component| component.as_str())
            .collect();
        let total_bytes: usize = self.blobs.values().map(Vec::len).sum();
        f.debug_struct("Snapshot")
            .field("schema_version", &self.manifest.schema_version)
            .field("snapshot_id", &self.manifest.snapshot_id)
            .field("created_ms", &self.manifest.created_ms)
            .field("project_id", &self.manifest.project_id)
            .field("components", &components)
            .field("total_bytes", &total_bytes)
            .field("signature_b64_len", &self.signature_b64.len())
            .finish()
    }
}

/// A compact view of a snapshot for the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotSummary {
    /// The manifest's snapshot id.
    pub id: String,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_ms: i64,
    /// Project label.
    pub project_id: String,
    /// Declared size per component.
    pub components: BTreeMap<Component, usize>,
    /// Sum of the declared component sizes.
    pub total_bytes: usize,
}

/// The result of a successful same-device restore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoredSnapshot {
    /// Snapshot id that was restored.
    pub snapshot_id: String,
    /// The snapshot directory, `target_root/.zero/teleport/snap-<id>`.
    pub directory: PathBuf,
    /// Restored component files, keyed by component.
    pub components: BTreeMap<Component, PathBuf>,
    /// The signed manifest file (`snapshot.json`).
    pub manifest_path: PathBuf,
    /// Lower-case hex blake3 of the canonical manifest.
    pub manifest_hash: String,
    /// The caller's clock when the restore ran.
    pub restored_ms: i64,
    /// True when the exact snapshot was already restored and was re-verified
    /// instead of being written again.
    pub already_present: bool,
}

/// Build and sign a snapshot with no exclusions.
///
/// The blobs are validated and hashed, the manifest is derived, and the
/// canonical manifest bytes are signed with `device_key`. Required components
/// (session, kernel, manifest) must be present; artifacts, goals, schedules,
/// and ledger are optional but are recorded when supplied.
pub fn create<B>(project_id: &str, blobs: B, now_ms: i64, device_key: &KeyPair) -> Result<Snapshot>
where
    B: IntoIterator<Item = ComponentBlob>,
{
    create_excluding(project_id, blobs, Vec::<String>::new(), now_ms, device_key)
}

/// Build and sign a snapshot, recording the excluded paths.
///
/// `excluded` is the TEL-05 report: secret-like or user-excluded paths the
/// caller deliberately left out. Entries are validated, sorted, and
/// deduplicated. A label that names a supplied component is contradictory and
/// is refused, and a secret-like label is never accepted as a component.
pub fn create_excluding<B, E, S>(
    project_id: &str,
    blobs: B,
    excluded: E,
    now_ms: i64,
    device_key: &KeyPair,
) -> Result<Snapshot>
where
    B: IntoIterator<Item = ComponentBlob>,
    E: IntoIterator<Item = S>,
    S: Into<String>,
{
    validate_project_id(project_id)?;
    let excluded = normalize_excluded(excluded.into_iter().map(Into::into))?;

    let mut blob_map: BTreeMap<Component, Vec<u8>> = BTreeMap::new();
    let mut total = 0usize;
    for blob in blobs {
        ensure_component_allowed(blob.component)?;
        if blob_map.contains_key(&blob.component) {
            return Err(invalid(format!(
                "component `{}` was supplied more than once",
                blob.component.as_str()
            )));
        }
        if blob.bytes.len() > MAX_COMPONENT_BYTES {
            return Err(limit(format!(
                "component `{}` is {} bytes; the per-component limit is {MAX_COMPONENT_BYTES}",
                blob.component.as_str(),
                blob.bytes.len()
            )));
        }
        total = total
            .checked_add(blob.bytes.len())
            .ok_or_else(|| limit("snapshot size overflows its counter"))?;
        if total > MAX_SNAPSHOT_BYTES {
            return Err(limit(format!(
                "snapshot components total {total} bytes; the limit is {MAX_SNAPSHOT_BYTES}"
            )));
        }
        blob_map.insert(blob.component, blob.bytes);
    }

    for required in Component::REQUIRED {
        if !blob_map.contains_key(&required) {
            return Err(invalid(format!(
                "required component `{}` is missing",
                required.as_str()
            )));
        }
    }

    for entry in &excluded {
        if let Ok(component) = classify_component(entry) {
            if blob_map.contains_key(&component) {
                return Err(invalid(format!(
                    "component `{}` is supplied and also listed as excluded",
                    component.as_str()
                )));
            }
        }
    }

    let components: BTreeMap<Component, ComponentMeta> = blob_map
        .iter()
        .map(|(component, bytes)| {
            let meta = ComponentMeta {
                bytes: bytes.len(),
                blake3: blake3::hash(bytes).to_hex().to_string(),
                kind: component.kind().to_string(),
            };
            (*component, meta)
        })
        .collect();

    let snapshot_id = derive_snapshot_id(SCHEMA_VERSION, now_ms, project_id, &components, &excluded)?;
    let manifest = SnapshotManifest {
        schema_version: SCHEMA_VERSION,
        snapshot_id,
        created_ms: now_ms,
        project_id: project_id.to_string(),
        components,
        excluded,
    };
    let canonical = manifest.canonical_bytes()?;
    let signature_b64 = device_key.sign(&canonical);

    Ok(Snapshot {
        manifest,
        blobs: blob_map,
        signature_b64,
    })
}

/// Verify the manifest signature, the manifest shape, and every blob hash.
///
/// Checks, in order:
///
/// 1. the manifest's schema version, ids, required components, kinds, and caps;
/// 2. the blob set is exactly the manifest's component set (a partial snapshot
///    fails);
/// 3. every blob's length and blake3 digest match its manifest entry
///    (`zero.tru.tamper` on a mismatch);
/// 4. the Ed25519 signature verifies over the canonical manifest with
///    `device_pubkey` (`zero.pol.denied`).
///
/// Verification is read-only. [`restore`] calls it before creating a directory,
/// so a tampered, partial, or foreign-signed snapshot writes nothing.
pub fn verify(snapshot: &Snapshot, device_pubkey: &str) -> Result<()> {
    validate_manifest(&snapshot.manifest)?;

    if snapshot.blobs.len() != snapshot.manifest.components.len() {
        return Err(tamper(format!(
            "snapshot carries {} component blobs but the manifest names {}",
            snapshot.blobs.len(),
            snapshot.manifest.components.len()
        )));
    }

    let mut total = 0usize;
    for (component, meta) in &snapshot.manifest.components {
        let bytes = snapshot.blobs.get(component).ok_or_else(|| {
            tamper(format!(
                "component `{}` is missing from the snapshot",
                component.as_str()
            ))
        })?;
        if bytes.len() != meta.bytes {
            return Err(tamper(format!(
                "component `{}` is {} bytes but the manifest declares {}",
                component.as_str(),
                bytes.len(),
                meta.bytes
            )));
        }
        let digest = blake3::hash(bytes).to_hex().to_string();
        if digest != meta.blake3 {
            return Err(tamper(format!(
                "component `{}` does not match its manifest hash",
                component.as_str()
            )));
        }
        total = total
            .checked_add(bytes.len())
            .ok_or_else(|| limit("snapshot size overflows its counter"))?;
    }

    for component in snapshot.blobs.keys() {
        if !snapshot.manifest.components.contains_key(component) {
            return Err(tamper(format!(
                "component `{}` is present but absent from the manifest",
                component.as_str()
            )));
        }
    }
    if total > MAX_SNAPSHOT_BYTES {
        return Err(limit(format!(
            "snapshot components total {total} bytes; the limit is {MAX_SNAPSHOT_BYTES}"
        )));
    }

    let canonical = snapshot.manifest.canonical_bytes()?;
    verify_signature(device_pubkey, &canonical, &snapshot.signature_b64)
        .map_err(|_| denied("snapshot manifest is not signed by the supplied device key"))
}

/// Lower-case hex blake3 of the canonical manifest.
///
/// Call [`verify`] first when the value will be trusted: this hashes the
/// manifest as supplied, without checking the signature or the blobs.
pub fn manifest_hash(snapshot: &Snapshot) -> Result<String> {
    Ok(blake3::hash(&snapshot.manifest.canonical_bytes()?)
        .to_hex()
        .to_string())
}

/// A compact summary for the UI. This reads the manifest; it does not verify.
pub fn inspect(snapshot: &Snapshot) -> SnapshotSummary {
    let mut components = BTreeMap::new();
    let mut total_bytes = 0usize;
    for (component, meta) in &snapshot.manifest.components {
        components.insert(*component, meta.bytes);
        total_bytes = total_bytes.saturating_add(meta.bytes);
    }
    SnapshotSummary {
        id: snapshot.manifest.snapshot_id.clone(),
        created_ms: snapshot.manifest.created_ms,
        project_id: snapshot.manifest.project_id.clone(),
        components,
        total_bytes,
    }
}

/// Restore a verified snapshot on the same device.
///
/// The snapshot is verified first; a tampered, partial, or foreign-signed
/// snapshot returns an error before a directory or file is created. Components
/// are written under `target_root/.zero/teleport/snap-<id>/<component>`, each
/// through a temporary file plus rename inside a staging directory. The signed
/// manifest (`snapshot.json`) is written last, and the staging directory is
/// renamed into place only after every file is durable.
///
/// An existing snapshot directory with the same id is re-verified: if every
/// component still matches the signed manifest it is returned with
/// [`RestoredSnapshot::already_present`], and if anything differs the restore is
/// refused without touching it. A different snapshot in the same path, a
/// symlink, or a non-directory is refused rather than replaced.
pub fn restore(
    snapshot: &Snapshot,
    target_root: &Path,
    device_pubkey: &str,
    now_ms: i64,
) -> Result<RestoredSnapshot> {
    restore_inner(snapshot, target_root, device_pubkey, now_ms, &mut |_, _| {})
}

fn restore_inner(
    snapshot: &Snapshot,
    target_root: &Path,
    device_pubkey: &str,
    now_ms: i64,
    probe: &mut dyn FnMut(Component, &Path),
) -> Result<RestoredSnapshot> {
    verify(snapshot, device_pubkey)?;
    let manifest_hash = manifest_hash(snapshot)?;
    let teleport_dir = prepare_teleport_dir(target_root)?;
    let snapshot_id = snapshot.manifest.snapshot_id.clone();
    let final_dir = teleport_dir.join(format!("snap-{snapshot_id}"));

    if let Some(restored) = existing_restore(snapshot, &final_dir, now_ms)? {
        return Ok(restored);
    }

    let temp_dir = create_temp_dir(&teleport_dir, &snapshot_id)?;
    let files = match write_components(snapshot, &temp_dir, probe) {
        Ok(files) => files,
        Err(error) => {
            let _ = fs::remove_dir_all(&temp_dir);
            return Err(error);
        }
    };
    if let Err(error) = fs::rename(&temp_dir, &final_dir) {
        let _ = fs::remove_dir_all(&temp_dir);
        return Err(io_error(
            format!(
                "cannot move the restored snapshot into `{}`",
                final_dir.display()
            ),
            error,
        ));
    }

    let components = files
        .keys()
        .map(|component| (*component, final_dir.join(component.file_name())))
        .collect();
    Ok(RestoredSnapshot {
        snapshot_id,
        directory: final_dir.clone(),
        components,
        manifest_path: final_dir.join(MANIFEST_FILE),
        manifest_hash,
        restored_ms: now_ms,
        already_present: false,
    })
}

/// Classify a caller-supplied component label.
///
/// Exact component names are accepted, `workspace-manifest` is an alias for
/// `manifest`, and whitespace is ignored at the edges. A secret-like path —
/// the project vault, a credential store, `.env` files, or a private-key file —
/// is refused with `zero.pol.denied` (TEL-05); any other label is
/// `zero.fnd.invalid_input`.
pub fn classify_component(label: &str) -> Result<Component> {
    let trimmed = label.trim();
    if is_secret_like(trimmed) {
        return Err(denied(format!(
            "`{trimmed}` looks like a secret path; teleport excludes it and reports the exclusion"
        )));
    }
    match trimmed {
        "session" => Ok(Component::Session),
        "kernel" => Ok(Component::Kernel),
        "artifacts" => Ok(Component::Artifacts),
        "goals" => Ok(Component::Goals),
        "schedules" => Ok(Component::Schedules),
        "ledger" => Ok(Component::Ledger),
        "manifest" | "workspace-manifest" => Ok(Component::Manifest),
        _ => Err(invalid(format!(
            "`{trimmed}` is not one of the snapshot components"
        ))),
    }
}

/// True for paths TEL-05 excludes by default: the project vault, credential
/// stores, `.env` files, and common private-key files.
///
/// `.zero/key` is the project identity, not a credential, so it is not
/// classified as secret. This is a label check, not a content scan.
pub fn is_secret_like(label: &str) -> bool {
    let normalized = label.replace('\\', "/").to_ascii_lowercase();
    let normalized = normalized.trim().trim_matches('/');
    let file_name = normalized.rsplit('/').next().unwrap_or(normalized);

    normalized == ".zero/vault"
        || normalized.starts_with(".zero/vault/")
        || normalized.contains("/.zero/vault/")
        || normalized.ends_with("/.zero/vault")
        || file_name == ".env"
        || file_name.starts_with(".env.")
        || file_name == "credentials"
        || file_name == "credential"
        || file_name.starts_with("credentials.")
        || file_name.starts_with("credential.")
        || file_name == "id_rsa"
        || file_name == "id_ed25519"
        || file_name.ends_with(".pem")
        || file_name.ends_with(".p12")
        || file_name.ends_with(".pfx")
}

fn ensure_component_allowed(component: Component) -> Result<()> {
    if is_secret_like(component.as_str()) {
        return Err(denied(format!(
            "component `{}` looks like a secret and cannot be snapshotted",
            component.as_str()
        )));
    }
    Ok(())
}

fn validate_manifest(manifest: &SnapshotManifest) -> Result<()> {
    if manifest.schema_version != SCHEMA_VERSION {
        return Err(ZeroError::new(
            ErrorCode::SchemaVersion,
            format!(
                "snapshot schema version {} is not supported; this build reads {SCHEMA_VERSION}",
                manifest.schema_version
            ),
        ));
    }
    if !is_lower_hex_64(&manifest.snapshot_id) {
        return Err(invalid(
            "snapshot id must be 64 lower-case hex characters",
        ));
    }
    validate_project_id(&manifest.project_id)?;

    for required in Component::REQUIRED {
        if !manifest.components.contains_key(&required) {
            return Err(invalid(format!(
                "required component `{}` is missing from the manifest",
                required.as_str()
            )));
        }
    }
    if manifest.components.len() > Component::ALL.len() {
        return Err(invalid(
            "the manifest has more components than the snapshot model defines",
        ));
    }

    let mut total = 0usize;
    for (component, meta) in &manifest.components {
        if meta.kind != component.kind() {
            return Err(invalid(format!(
                "component `{}` has kind `{}`; expected `{}`",
                component.as_str(),
                meta.kind,
                component.kind()
            )));
        }
        if !is_lower_hex_64(&meta.blake3) {
            return Err(invalid(format!(
                "component `{}` has an invalid blake3 digest",
                component.as_str()
            )));
        }
        if meta.bytes > MAX_COMPONENT_BYTES {
            return Err(limit(format!(
                "component `{}` declares {} bytes; the per-component limit is {MAX_COMPONENT_BYTES}",
                component.as_str(),
                meta.bytes
            )));
        }
        total = total
            .checked_add(meta.bytes)
            .ok_or_else(|| limit("snapshot size overflows its counter"))?;
    }
    if total > MAX_SNAPSHOT_BYTES {
        return Err(limit(format!(
            "snapshot components total {total} bytes; the limit is {MAX_SNAPSHOT_BYTES}"
        )));
    }

    validate_excluded(&manifest.excluded)?;

    let derived = derive_snapshot_id(
        manifest.schema_version,
        manifest.created_ms,
        &manifest.project_id,
        &manifest.components,
        &manifest.excluded,
    )?;
    if derived != manifest.snapshot_id {
        return Err(invalid(
            "snapshot id does not match the manifest content",
        ));
    }
    Ok(())
}

fn validate_project_id(project_id: &str) -> Result<()> {
    if project_id.is_empty() {
        return Err(invalid("project id must not be empty"));
    }
    if project_id.len() > MAX_PROJECT_ID_BYTES {
        return Err(limit(format!(
            "project id is {} bytes; the limit is {MAX_PROJECT_ID_BYTES}",
            project_id.len()
        )));
    }
    if project_id.trim() != project_id {
        return Err(invalid("project id must not start or end with whitespace"));
    }
    if project_id.chars().any(char::is_control) {
        return Err(invalid("project id must not contain control characters"));
    }
    if project_id.contains('/') || project_id.contains('\\') {
        return Err(invalid("project id must not contain path separators"));
    }
    if project_id == "." || project_id == ".." {
        return Err(invalid("project id must not be a path traversal component"));
    }
    Ok(())
}

fn normalize_excluded<I>(entries: I) -> Result<Vec<String>>
where
    I: IntoIterator<Item = String>,
{
    let mut entries: Vec<String> = entries.into_iter().collect();
    for entry in &entries {
        validate_excluded_entry(entry)?;
    }
    entries.sort_unstable();
    entries.dedup();
    if entries.len() > MAX_EXCLUDED {
        return Err(limit(format!(
            "snapshot reports {} exclusions; the limit is {MAX_EXCLUDED}",
            entries.len()
        )));
    }
    Ok(entries)
}

fn validate_excluded(excluded: &[String]) -> Result<()> {
    if excluded.len() > MAX_EXCLUDED {
        return Err(limit(format!(
            "snapshot reports {} exclusions; the limit is {MAX_EXCLUDED}",
            excluded.len()
        )));
    }
    let mut previous: Option<&str> = None;
    for entry in excluded {
        validate_excluded_entry(entry)?;
        if let Some(previous) = previous {
            if previous >= entry.as_str() {
                return Err(invalid(
                    "snapshot exclusions must be sorted and unique",
                ));
            }
        }
        previous = Some(entry);
    }
    Ok(())
}

fn validate_excluded_entry(entry: &str) -> Result<()> {
    if entry.is_empty() {
        return Err(invalid("a snapshot exclusion must not be empty"));
    }
    if entry.len() > MAX_EXCLUDED_BYTES {
        return Err(limit(format!(
            "snapshot exclusion is {} bytes; the limit is {MAX_EXCLUDED_BYTES}",
            entry.len()
        )));
    }
    if entry.trim() != entry {
        return Err(invalid(
            "a snapshot exclusion must not start or end with whitespace",
        ));
    }
    if entry.chars().any(char::is_control) {
        return Err(invalid(
            "a snapshot exclusion must not contain control characters",
        ));
    }
    Ok(())
}

fn derive_snapshot_id(
    schema_version: u32,
    created_ms: i64,
    project_id: &str,
    components: &BTreeMap<Component, ComponentMeta>,
    excluded: &[String],
) -> Result<String> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(SNAPSHOT_ID_DOMAIN);
    out.extend_from_slice(&schema_version.to_be_bytes());
    out.extend_from_slice(&created_ms.to_be_bytes());
    put_str(&mut out, project_id)?;

    put_count(
        &mut out,
        components.len(),
        Component::ALL.len(),
        "components",
    )?;
    for (component, meta) in components {
        put_str(&mut out, component.as_str())?;
        put_str(&mut out, &meta.kind)?;
        let bytes = u64::try_from(meta.bytes)
            .map_err(|_| limit("a component size exceeds the u64 encoding"))?;
        out.extend_from_slice(&bytes.to_be_bytes());
        put_str(&mut out, &meta.blake3)?;
    }

    put_count(&mut out, excluded.len(), MAX_EXCLUDED, "excluded entries")?;
    for entry in excluded {
        put_str(&mut out, entry)?;
    }

    Ok(blake3::hash(&out).to_hex().to_string())
}

fn prepare_teleport_dir(target_root: &Path) -> Result<PathBuf> {
    if target_root.as_os_str().is_empty() {
        return Err(invalid("target root must not be empty"));
    }
    fs::create_dir_all(target_root).map_err(|error| {
        io_error(
            format!("cannot create target root `{}`", target_root.display()),
            error,
        )
    })?;

    let zero_dir = target_root.join(".zero");
    ensure_directory(&zero_dir)?;
    let teleport_dir = zero_dir.join("teleport");
    ensure_directory(&teleport_dir)?;
    Ok(teleport_dir)
}

fn ensure_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(denied(format!(
                    "`{}` is a symlink; restore refuses to follow it",
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
            fs::create_dir(path).map_err(|error| {
                io_error(format!("cannot create `{}`", path.display()), error)
            })?;
            let metadata = fs::symlink_metadata(path).map_err(|error| {
                io_error(format!("cannot inspect `{}`", path.display()), error)
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(denied(format!(
                    "`{}` was replaced by a non-directory while it was created",
                    path.display()
                )));
            }
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

fn create_temp_dir(teleport_dir: &Path, snapshot_id: &str) -> Result<PathBuf> {
    let mut random = [0u8; 8];
    getrandom::getrandom(&mut random)
        .map_err(|error| internal(format!("cannot read random bytes: {error}")))?;
    let suffix = u64::from_be_bytes(random);
    let directory = teleport_dir.join(format!(".snap-{snapshot_id}.tmp-{suffix:016x}"));
    fs::create_dir(&directory).map_err(|error| {
        io_error(
            format!(
                "cannot create the restore staging directory `{}`",
                directory.display()
            ),
            error,
        )
    })?;
    Ok(directory)
}

fn write_components(
    snapshot: &Snapshot,
    directory: &Path,
    probe: &mut dyn FnMut(Component, &Path),
) -> Result<BTreeMap<Component, PathBuf>> {
    let mut paths = BTreeMap::new();
    for component in Component::ALL {
        let Some(bytes) = snapshot.blobs.get(&component) else {
            continue;
        };
        let path = directory.join(component.file_name());
        write_atomic(&path, bytes)?;
        probe(component, &path);
        paths.insert(component, path);
    }

    let stored = StoredManifest {
        manifest: snapshot.manifest.clone(),
        signature_b64: snapshot.signature_b64.clone(),
    };
    let json = serde_json::to_vec_pretty(&stored)
        .map_err(|error| internal(format!("cannot encode the snapshot manifest: {error}")))?;
    let manifest_path = directory.join(MANIFEST_FILE);
    write_atomic(&manifest_path, &json)?;
    Ok(paths)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid("a snapshot file name is not valid UTF-8"))?;
    let partial = path.with_file_name(format!("{file_name}.partial"));

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|error| {
            io_error(
                format!("cannot create `{}`", partial.display()),
                error,
            )
        })?;
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

fn existing_restore(
    snapshot: &Snapshot,
    directory: &Path,
    now_ms: i64,
) -> Result<Option<RestoredSnapshot>> {
    let metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(io_error(
                format!("cannot inspect `{}`", directory.display()),
                error,
            ))
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(denied(format!(
            "`{}` is a symlink; restore refuses to replace it",
            directory.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(denied(format!(
            "`{}` already exists and is not a snapshot directory",
            directory.display()
        )));
    }

    let manifest_path = directory.join(MANIFEST_FILE);
    let stored_bytes = match fs::read(&manifest_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(tamper(format!(
                "`{}` exists but has no `{MANIFEST_FILE}`; refusing to overwrite it",
                directory.display()
            )))
        }
        Err(error) => {
            return Err(io_error(
                format!("cannot read `{}`", manifest_path.display()),
                error,
            ))
        }
    };
    let stored: StoredManifest = serde_json::from_slice(&stored_bytes).map_err(|_| {
        tamper(format!(
            "`{}` is not a readable snapshot manifest",
            manifest_path.display()
        ))
    })?;

    let expected = snapshot.manifest.canonical_bytes()?;
    let actual = stored.manifest.canonical_bytes()?;
    if actual != expected || stored.signature_b64 != snapshot.signature_b64 {
        return Err(denied(format!(
            "a different snapshot already occupies `{}`; restore does not overwrite it",
            directory.display()
        )));
    }

    let mut components = BTreeMap::new();
    for (component, meta) in &snapshot.manifest.components {
        let path = directory.join(component.file_name());
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(tamper(format!(
                    "the existing snapshot is missing component `{}`",
                    component.as_str()
                )))
            }
            Err(error) => {
                return Err(io_error(
                    format!("cannot read the existing component `{}`", path.display()),
                    error,
                ))
            }
        };
        if bytes.len() != meta.bytes || blake3::hash(&bytes).to_hex().to_string() != meta.blake3 {
            return Err(tamper(format!(
                "the existing snapshot component `{}` does not match the signed manifest",
                component.as_str()
            )));
        }
        components.insert(*component, path);
    }

    Ok(Some(RestoredSnapshot {
        snapshot_id: snapshot.manifest.snapshot_id.clone(),
        directory: directory.to_path_buf(),
        components,
        manifest_path,
        manifest_hash: blake3::hash(&expected).to_hex().to_string(),
        restored_ms: now_ms,
        already_present: true,
    }))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredManifest {
    manifest: SnapshotManifest,
    signature_b64: String,
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == SNAPSHOT_ID_HEX
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn put_str(out: &mut Vec<u8>, value: &str) -> Result<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| limit("a snapshot field exceeds the u32 length prefix"))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_count(out: &mut Vec<u8>, count: usize, max: usize, field: &str) -> Result<()> {
    if count > max {
        return Err(limit(format!(
            "snapshot has {count} {field}; the limit is {max}"
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

fn limit(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

fn tamper(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::TamperDetected, message)
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

    fn key() -> KeyPair {
        KeyPair::generate().expect("device key")
    }

    fn all_blobs() -> Vec<ComponentBlob> {
        vec![
            ComponentBlob::new(Component::Session, b"{\"entries\":3}".to_vec()),
            ComponentBlob::new(Component::Kernel, b"kernel-state".to_vec()),
            ComponentBlob::new(Component::Artifacts, b"artifact-index".to_vec()),
            ComponentBlob::new(Component::Goals, b"goal-state".to_vec()),
            ComponentBlob::new(Component::Schedules, b"schedule-state".to_vec()),
            ComponentBlob::new(Component::Ledger, b"usage-ledger".to_vec()),
            ComponentBlob::new(Component::Manifest, b"workspace-manifest".to_vec()),
        ]
    }

    fn snapshot() -> (KeyPair, Snapshot) {
        let device = key();
        let snapshot = create("project-1", all_blobs(), NOW, &device).expect("snapshot");
        (device, snapshot)
    }

    #[test]
    fn a_snapshot_round_trips_on_the_same_device() {
        let (device, snapshot) = snapshot();
        verify(&snapshot, &device.public_key_b64()).expect("snapshot verifies");

        let target = TempDir::new().expect("tempdir");
        let restored = restore(
            &snapshot,
            target.path(),
            &device.public_key_b64(),
            NOW + 10,
        )
        .expect("same-device restore");

        assert_eq!(restored.snapshot_id, snapshot.manifest.snapshot_id);
        assert_eq!(restored.components.len(), 7);
        assert!(!restored.already_present);
        assert_eq!(restored.restored_ms, NOW + 10);
        assert!(restored
            .directory
            .ends_with(format!("snap-{}", snapshot.manifest.snapshot_id)));
        assert_eq!(
            restored.directory,
            target
                .path()
                .join(".zero")
                .join("teleport")
                .join(format!("snap-{}", snapshot.manifest.snapshot_id))
        );
        assert!(restored.manifest_path.ends_with(MANIFEST_FILE));
        assert_eq!(
            restored.manifest_hash,
            manifest_hash(&snapshot).expect("manifest hash")
        );

        for blob in all_blobs() {
            let path = &restored.components[&blob.component];
            assert_eq!(fs::read(path).expect("read component"), blob.bytes);
        }
        let stored = fs::read(&restored.manifest_path).expect("read manifest");
        let stored: StoredManifest = serde_json::from_slice(&stored).expect("manifest json");
        assert_eq!(stored.manifest, snapshot.manifest);
        assert_eq!(stored.signature_b64, snapshot.signature_b64);
    }

    #[test]
    fn the_manifest_is_written_after_every_component() {
        let (device, snapshot) = snapshot();
        let target = TempDir::new().expect("tempdir");
        let mut observed = Vec::new();
        let mut manifest_seen_early = false;
        {
            let mut probe = |component: Component, path: &Path| {
                if path
                    .parent()
                    .is_some_and(|parent| parent.join(MANIFEST_FILE).exists())
                {
                    manifest_seen_early = true;
                }
                observed.push(component);
            };
            restore_inner(
                &snapshot,
                target.path(),
                &device.public_key_b64(),
                NOW,
                &mut probe,
            )
            .expect("restore");
        }
        assert_eq!(observed, Component::ALL.to_vec());
        assert!(
            !manifest_seen_early,
            "snapshot.json must be written after every component"
        );
    }

    #[test]
    fn a_tampered_blob_or_signature_is_refused_and_writes_nothing() {
        let (device, snapshot) = snapshot();
        let target = TempDir::new().expect("tempdir");

        let mut tampered_blob = snapshot.clone();
        tampered_blob
            .blobs
            .get_mut(&Component::Session)
            .expect("session blob")
            .push(b'!');
        let error = verify(&tampered_blob, &device.public_key_b64())
            .expect_err("a changed blob must not verify");
        assert_eq!(error.code(), ErrorCode::TamperDetected);
        assert!(restore(
            &tampered_blob,
            target.path(),
            &device.public_key_b64(),
            NOW
        )
        .is_err());
        assert!(!target.path().join(".zero").exists());

        let mut tampered_signature = snapshot.clone();
        tampered_signature.signature_b64 = device.sign(b"different bytes");
        let error = verify(&tampered_signature, &device.public_key_b64())
            .expect_err("a changed signature must not verify");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(restore(
            &tampered_signature,
            target.path(),
            &device.public_key_b64(),
            NOW
        )
        .is_err());
        assert!(!target.path().join(".zero").exists());

        let other = key();
        assert_eq!(
            verify(&snapshot, &other.public_key_b64())
                .expect_err("a foreign device key must not verify")
                .code(),
            ErrorCode::PolicyDenied
        );
    }

    #[test]
    fn a_missing_required_component_is_refused() {
        let device = key();
        let without_kernel = all_blobs()
            .into_iter()
            .filter(|blob| blob.component != Component::Kernel)
            .collect::<Vec<_>>();
        assert_eq!(
            create("project-1", without_kernel, NOW, &device)
                .expect_err("kernel is required")
                .code(),
            ErrorCode::InvalidInput
        );

        let (device, mut snapshot) = snapshot();
        snapshot.blobs.remove(&Component::Kernel);
        assert_eq!(
            verify(&snapshot, &device.public_key_b64())
                .expect_err("a partial snapshot must not verify")
                .code(),
            ErrorCode::TamperDetected
        );
        let target = TempDir::new().expect("tempdir");
        assert!(restore(&snapshot, target.path(), &device.public_key_b64(), NOW).is_err());
        assert!(!target.path().join(".zero").exists());
    }

    #[test]
    fn secret_like_components_are_refused_and_reported_as_exclusions() {
        for label in [
            ".zero/vault",
            ".zero/vault/project.db",
            "project/.zero/vault",
            ".zero\\vault",
            "credentials",
            "credentials.enc",
            ".env",
            ".env.local",
            "id_ed25519",
            "host.pem",
        ] {
            assert!(is_secret_like(label), "{label} should be secret-like");
            assert_eq!(
                classify_component(label)
                    .expect_err("a secret path is not a component")
                    .code(),
                ErrorCode::PolicyDenied,
                "{label}"
            );
            assert_eq!(
                ComponentBlob::from_label(label, b"value".to_vec())
                    .expect_err("a secret path cannot become a blob")
                    .code(),
                ErrorCode::PolicyDenied,
                "{label}"
            );
        }
        assert!(!is_secret_like(".zero/key"));
        assert_eq!(
            classify_component("session").expect("known component"),
            Component::Session
        );
        assert_eq!(
            classify_component("workspace-manifest").expect("manifest alias"),
            Component::Manifest
        );
        assert!(
            Component::ALL
                .iter()
                .all(|component| !is_secret_like(component.as_str())),
            "no modelled component may be secret-like"
        );

        let device = key();
        let snapshot = create_excluding(
            "project-1",
            all_blobs(),
            [".zero/vault", "credentials.enc", ".zero/vault"],
            NOW,
            &device,
        )
        .expect("snapshot with exclusions");
        assert_eq!(
            snapshot.manifest.excluded,
            vec![".zero/vault".to_string(), "credentials.enc".to_string()]
        );
    }

    #[test]
    fn per_component_and_total_size_caps_are_enforced() {
        let device = key();

        let mut oversized = all_blobs();
        oversized[0].bytes = vec![0u8; MAX_COMPONENT_BYTES + 1];
        assert_eq!(
            create("project-1", oversized, NOW, &device)
                .expect_err("a component above the cap")
                .code(),
            ErrorCode::LimitExceeded
        );

        let mut total = Vec::new();
        for component in [
            Component::Session,
            Component::Kernel,
            Component::Manifest,
            Component::Artifacts,
            Component::Goals,
        ] {
            total.push(ComponentBlob::new(
                component,
                vec![7u8; MAX_COMPONENT_BYTES],
            ));
        }
        assert_eq!(
            create("project-1", total, NOW, &device)
                .expect_err("the component sum is above the total cap")
                .code(),
            ErrorCode::LimitExceeded
        );
    }

    #[test]
    fn a_duplicate_component_blob_is_refused() {
        let device = key();
        let mut blobs = all_blobs();
        blobs.push(ComponentBlob::new(
            Component::Session,
            b"a second session".to_vec(),
        ));
        assert_eq!(
            create("project-1", blobs, NOW, &device)
                .expect_err("one blob per component")
                .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn the_snapshot_id_is_deterministic_and_content_bound() {
        let device = key();
        let first = create("project-1", all_blobs(), NOW, &device).expect("first");
        let second = create("project-1", all_blobs(), NOW, &device).expect("second");
        assert_eq!(first.manifest.snapshot_id, second.manifest.snapshot_id);
        assert_eq!(first.signature_b64, second.signature_b64);

        let mut reversed = all_blobs();
        reversed.reverse();
        let reordered = create("project-1", reversed, NOW, &device).expect("reordered");
        assert_eq!(first.manifest.snapshot_id, reordered.manifest.snapshot_id);

        let later = create("project-1", all_blobs(), NOW + 1, &device).expect("later");
        assert_ne!(first.manifest.snapshot_id, later.manifest.snapshot_id);

        let other_project =
            create("project-2", all_blobs(), NOW, &device).expect("other project");
        assert_ne!(
            first.manifest.snapshot_id,
            other_project.manifest.snapshot_id
        );

        assert!(
            !first.manifest.snapshot_id.is_empty(),
            "the id is present for the UI"
        );
    }

    #[test]
    fn inspect_summarises_the_snapshot_without_values() {
        let (_, snapshot) = snapshot();
        let summary = inspect(&snapshot);
        let expected_total: usize = all_blobs().iter().map(|blob| blob.bytes.len()).sum();

        assert_eq!(summary.id, snapshot.manifest.snapshot_id);
        assert_eq!(summary.created_ms, NOW);
        assert_eq!(summary.project_id, "project-1");
        assert_eq!(summary.components.len(), 7);
        assert_eq!(
            summary.components[&Component::Session],
            b"{\"entries\":3}".len()
        );
        assert_eq!(summary.total_bytes, expected_total);

        let json = serde_json::to_string(&summary).expect("summary json");
        assert!(!json.contains("workspace-manifest"), "{json}");
        assert!(!json.contains("{\"entries\":"), "{json}");
    }

    #[test]
    fn a_snapshot_survives_serde_and_still_restores() {
        let (device, snapshot) = snapshot();
        let json = serde_json::to_string(&snapshot).expect("serialise");
        let restored: Snapshot = serde_json::from_str(&json).expect("parse");
        assert_eq!(restored, snapshot);
        verify(&restored, &device.public_key_b64()).expect("restored snapshot verifies");

        let target = TempDir::new().expect("tempdir");
        let outcome = restore(&restored, target.path(), &device.public_key_b64(), NOW)
            .expect("restored snapshot restores");
        assert_eq!(
            fs::read(&outcome.components[&Component::Kernel]).expect("kernel"),
            b"kernel-state"
        );
    }

    #[test]
    fn debug_redacts_blobs_and_the_signature() {
        let (device, snapshot) = snapshot();
        let debug = format!("{snapshot:?}");
        assert!(!debug.contains(&snapshot.signature_b64), "{debug}");
        assert!(!debug.contains("workspace-manifest"), "{debug}");
        assert!(!debug.contains("{\"entries\":3}"), "{debug}");
        assert!(!debug.contains(&device.public_key_b64()), "{debug}");
        assert!(debug.contains(&snapshot.manifest.snapshot_id), "{debug}");
        assert!(debug.contains("project-1"), "{debug}");
        assert!(debug.contains("signature_b64_len"), "{debug}");
    }

    #[test]
    fn optional_components_may_be_absent_and_are_recorded_when_present() {
        let device = key();
        let required = vec![
            ComponentBlob::new(Component::Session, b"session".to_vec()),
            ComponentBlob::new(Component::Kernel, b"kernel".to_vec()),
            ComponentBlob::new(Component::Manifest, b"manifest".to_vec()),
        ];
        let snapshot = create("project-1", required, NOW, &device).expect("required only");
        verify(&snapshot, &device.public_key_b64()).expect("required-only snapshot verifies");
        assert_eq!(snapshot.manifest.components.len(), 3);
        assert_eq!(
            snapshot.manifest.missing_optional(),
            vec![
                Component::Artifacts,
                Component::Goals,
                Component::Schedules,
                Component::Ledger
            ]
        );

        let target = TempDir::new().expect("tempdir");
        let restored = restore(&snapshot, target.path(), &device.public_key_b64(), NOW)
            .expect("required-only restore");
        assert_eq!(restored.components.len(), 3);
        assert!(!restored.components.contains_key(&Component::Goals));

        let full = snapshot_with_all();
        assert!(full.manifest.missing_optional().is_empty());
    }

    fn snapshot_with_all() -> Snapshot {
        let device = key();
        create("project-1", all_blobs(), NOW, &device).expect("full snapshot")
    }

    #[test]
    fn restore_is_idempotent_and_never_overwrites_a_different_snapshot() {
        let (device, snapshot) = snapshot();
        let target = TempDir::new().expect("tempdir");
        let first = restore(&snapshot, target.path(), &device.public_key_b64(), NOW)
            .expect("first restore");
        assert!(!first.already_present);

        let session_path = first.components[&Component::Session].clone();
        let original = fs::read(&session_path).expect("session");
        let second = restore(&snapshot, target.path(), &device.public_key_b64(), NOW + 5)
            .expect("idempotent restore");
        assert!(second.already_present);
        assert_eq!(second.directory, first.directory);
        assert_eq!(fs::read(&session_path).expect("session"), original);

        fs::write(&session_path, b"tampered").expect("corrupt the restored component");
        assert_eq!(
            restore(&snapshot, target.path(), &device.public_key_b64(), NOW)
                .expect_err("a corrupted existing restore is refused")
                .code(),
            ErrorCode::TamperDetected
        );
        assert_eq!(fs::read(&session_path).expect("session"), b"tampered");

        fs::write(&session_path, &original).expect("restore the component");
        let other = create("project-2", all_blobs(), NOW + 60_000, &device).expect("other");
        let stored = StoredManifest {
            manifest: other.manifest.clone(),
            signature_b64: other.signature_b64.clone(),
        };
        fs::write(
            &first.manifest_path,
            serde_json::to_vec_pretty(&stored).expect("json"),
        )
        .expect("replace the manifest");
        assert_eq!(
            restore(&snapshot, target.path(), &device.public_key_b64(), NOW)
                .expect_err("a different snapshot in the same path is refused")
                .code(),
            ErrorCode::PolicyDenied
        );
        assert_eq!(fs::read(&session_path).expect("session"), original);
    }

    #[test]
    fn unsafe_ids_and_labels_are_refused_before_any_write() {
        let (device, mut snapshot) = snapshot();
        snapshot.manifest.snapshot_id = "../escape".to_string();
        assert_eq!(
            verify(&snapshot, &device.public_key_b64())
                .expect_err("a traversal id cannot verify")
                .code(),
            ErrorCode::InvalidInput
        );
        let target = TempDir::new().expect("tempdir");
        assert!(restore(&snapshot, target.path(), &device.public_key_b64(), NOW).is_err());
        assert!(!target.path().join(".zero").exists());
        assert!(!target.path().join("escape").exists());

        assert!(classify_component("../session").is_err());
        assert!(classify_component("not-a-component").is_err());
        assert!(classify_component("Credentials").is_err());
    }

    #[test]
    fn exclusions_are_validated_and_capped() {
        let device = key();
        let too_many = (0..=MAX_EXCLUDED)
            .map(|index| format!("exclude-{index:03}"))
            .collect::<Vec<_>>();
        assert_eq!(
            create_excluding("project-1", all_blobs(), too_many, NOW, &device)
                .expect_err("too many exclusions")
                .code(),
            ErrorCode::LimitExceeded
        );

        let long = "x".repeat(MAX_EXCLUDED_BYTES + 1);
        assert_eq!(
            create_excluding("project-1", all_blobs(), [long], NOW, &device)
                .expect_err("an over-long exclusion")
                .code(),
            ErrorCode::LimitExceeded
        );

        assert_eq!(
            create_excluding("project-1", all_blobs(), ["session"], NOW, &device)
                .expect_err("a supplied component cannot also be excluded")
                .code(),
            ErrorCode::InvalidInput
        );

        let sorted = create_excluding("project-1", all_blobs(), ["b", "a", "b"], NOW, &device)
            .expect("sorted and deduplicated");
        assert_eq!(
            sorted.manifest.excluded,
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn project_ids_are_validated() {
        let device = key();
        for project in ["", " padded", "padded ", "a/b", "a\\b", ".", ".."] {
            assert_eq!(
                create(project, all_blobs(), NOW, &device)
                    .expect_err("an unsafe project id")
                    .code(),
                ErrorCode::InvalidInput,
                "{project:?}"
            );
        }
        let long = "p".repeat(MAX_PROJECT_ID_BYTES + 1);
        assert_eq!(
            create(&long, all_blobs(), NOW, &device)
                .expect_err("an over-long project id")
                .code(),
            ErrorCode::LimitExceeded
        );
        assert!(create("project-1", all_blobs(), NOW, &device).is_ok());
    }

    #[test]
    fn a_crafted_manifest_with_a_wrong_schema_is_refused() {
        let (device, mut snapshot) = snapshot();
        snapshot.manifest.schema_version = SCHEMA_VERSION + 1;
        assert_eq!(
            verify(&snapshot, &device.public_key_b64())
                .expect_err("an unknown schema version")
                .code(),
            ErrorCode::SchemaVersion
        );
    }
}
