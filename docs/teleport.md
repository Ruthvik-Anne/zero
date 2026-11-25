# Teleport snapshots, workspace bundles, encrypted transfer, full restore, fence, and portability

`zero-mesh` owns the T-TEL-01 through T-TEL-07 slices. This document covers the
signed snapshot (session, kernel, artifacts, goals, schedules, ledger, and
workspace manifest), the same-device restore that proves T-TEL-01's done
criterion — **a snapshot restores on the same device** — the content-addressed
workspace bundle whose done criterion is **an interrupted bundle resumes**, the
end-to-end encrypted transfer whose done criterion is **a corrupted chunk fails
verification**, the full conflict-safe restore whose done criterion is
**restore into a conflicting directory stages instead of overwriting**, the
lease fence whose done criterion is **a stale holder cannot write after
handoff**, cross-OS portability whose done criterion is **Windows-to-Linux
and no-git directory runs pass**, and the vault ciphertext whose done criterion
is **the target prompts once and cannot decrypt silently**. The vault travels
inside the same encrypted transfer.

| Slice | Module | State |
|---|---|---|
| T-TEL-01 snapshot and same-device restore | `crates/zero-mesh/src/snapshot.rs` | implemented |
| T-TEL-02 content-addressed bundle | `crates/zero-mesh/src/bundle.rs` | implemented |
| T-TEL-03 transfer, E2E encryption, verify retention | `crates/zero-mesh/src/transfer.rs` | implemented |
| T-TEL-04 full restore (files, modes, symlinks, children) | `crates/zero-mesh/src/restore.rs` | implemented |
| T-TEL-05 fence and resume | `crates/zero-mesh/src/fence.rs` | implemented |
| T-TEL-06 portability, path remapping, kernel rebuild, tool preflight | `crates/zero-mesh/src/portability.rs` | implemented |
| T-TEL-07 vault ciphertext and one unlock | `crates/zero-mesh/src/vault_transfer.rs` | implemented |

`lib.rs` re-exports the snapshot surface: `Component`, `ComponentBlob`,
`ComponentMeta`, `Snapshot`, `SnapshotManifest`, `SnapshotSummary`,
`RestoredSnapshot`, `create`, `create_excluding`, `inspect`, `restore`,
`classify_component`, `is_secret_like`, `manifest_hash`, and the
`MAX_*`/`SCHEMA_VERSION`/`MANIFEST_DOMAIN`/`SNAPSHOT_ID_DOMAIN`/`MANIFEST_FILE`/
`TELEPORT_DIR` constants. `snapshot::verify` is re-exported as
**`verify_snapshot`** because the crate root already exports the identity
`verify`.

It re-exports the bundle surface as `build`, `build_files`, `Bundle`,
`BundleManifest`, `BundleFile`, `BundleWriter`, `BundleReader`, `BundleStats`,
`BundleCheckpoint`, `ChunkConfig`, `ChunkRef`, `FileEntry`, `Excluded`,
`MaterializeOptions`, `Materialized`, `WriteReport`, `VerifyReport`, and the
`BUNDLE_*`/`MAX_*` constants. `bundle::manifest_hash` is re-exported as
**`bundle_manifest_hash`** because `snapshot` already exports `manifest_hash`.
`bundle::verify_bundle` is the in-memory check the transfer reuses.

It re-exports the transfer surface as `seal_bundle`, `seal_bundle_with_seed`,
`open_bundle`, `open_bundle_verified`, `transfer_report`,
`retain_until_verified`, `retain_until_verified_with`, `RecipientKey`,
`RecipientSecret`, `SenderSecret`, `SealedBundle`, `SealedChunk`,
`VerifiedTransfer`, `TransferReport`, `RetentionOptions`, `RetentionReport`, and
the `TRANSFER_*`/`AEAD_*`/`X25519_*`/`RECIPIENT_*`/`CHUNK_*`/`MANIFEST_*`/`MAX_*`
constants.

It re-exports the restore surface as `RestorePlan`, `RestoreEntry`,
`RestoreKind`, `RestoreOptions`, `RestoreReport`, `StagedConflict`, `build_plan`,
`adopt`, and `CHILDREN_FILE`/`COMPONENTS_DIR`/`MAX_MODE_BITS`/
`MAX_RESTORE_ENTRIES`/`RESTORE_STAGING_DIR`. `restore::restore` is re-exported as
**`restore_bundle`** because the crate root already exports the snapshot
`restore`; use `zero_mesh::restore::restore` or `restore_bundle` for the full
workspace restore.

It re-exports the fence surface as `Lease`, `LeaseGeneration`, `HolderId`,
`ResumeCursor`, `ResumePlan`, `fence`, `handoff`, `handoff_if`, `renew`,
`release`, `resume`, `assert_can_write`, and
`DEFAULT_LEASE_TTL_MS`/`MAX_HOLDER_BYTES`/`MAX_LEASE_TTL_MS`/
`MAX_RESOURCE_BYTES`.

It re-exports the portability surface as `PathMap`, `remap_path`, `remap_text`,
`TextRemap`, `RemapReport`, `remap_snapshot`, `remap_snapshot_report`,
`SnapshotRemap`, `KernelRebuildPlan`, `plan_kernel_rebuild`, `ToolProbe`,
`ToolSet`, `ToolPreflight`, `PreflightReport`, `preflight`, `can_run`,
`install_guidance`, `KERNEL_PACKAGES`, `REMAPPABLE_COMPONENTS`, and the
`MAX_REMAP_*`/`MAX_PATH_MAPS`/`MAX_PYTHON_BYTES`/`MAX_KERNEL_PACKAGES`/
`MAX_PACKAGE_NAME_BYTES` constants.

It re-exports the vault-transfer surface as `seal_vault`,
`seal_vault_with_kdf`, `issue_approval`, `wrap_for_transfer`, `unwrap_envelope`,
`receive`, `unlock_vault`, `vault_transfer_report`, `VaultEnvelope`,
`KdfParams`, `KdfOptions`, `UnlockRequest`, `UnlockState`, `TransferApproval`,
`UnlockedVault`, `SealedVault`, `VaultTransferReport`, and the
`VAULT_*`/`DEFAULT_*`/`MAX_VAULT_BYTES`/`MAX_APPROVAL_*` constants.

## Scope

This slice moves **bytes** and proves they restore, resume, verify, and that
cross-OS state is rebuilt rather than copied blindly. The snapshot and bundle
are local values; the transfer is an in-memory encrypted envelope, not a socket.
The fence is a value model of the lease, not a running daemon or an OS lock. It
deliberately does not open a network connection or perform a live cross-device
restore:

- a snapshot, a bundle, and a sealed envelope are values, not services or
  background jobs;
- components are caller-supplied opaque bytes, so `zero-mesh` does not depend
  on `zero-agent`, `zero-kernel`, `zero-tasks`, or `zero-sched`;
- restore writes under `target_root/.zero/teleport/` on the **same device**;
- the bundle writes into a caller-supplied directory; no socket is opened;
- the sealed transfer is a value too: `seal_bundle` and `open_bundle_verified`
  never touch the filesystem, and the retention helper only inspects paths
  (plus an explicit, guarded source cleanup);
- `restore` writes into a caller-supplied target root on the **same device**.
  It is the staged full-tree restore TEL-08 asks for, but it does not negotiate
  a transport, change workspace entry paths (they are already relative), or
  take a lease;
- the lease fence (`T-TEL-05`) is a value model (`fence`); `restore` and
  `materialize` do not call it yet, and no store serialises handoffs for them;
- portability (`T-TEL-06`) is also a value model: it rewrites paths, plans a
  kernel rebuild, and probes a supplied tool set. It does not spawn a kernel,
  install a package, detect a live process, or open a socket;
- the vault transfer (`T-TEL-07`) seals opaque vault bytes and moves only the
  envelope ciphertext. Unlocking is a value model with an in-memory
  `UnlockState`: it does not draw the host passphrase modal, read a credential
  store, or persist consumed envelope ids. A live transport remains a later
  task.

TEL-03 names transcript, entries, kernel state, artifacts, goals, schedules,
heartbeats, permissions, tool state, usage ledger, and a workspace manifest.
This snapshot models the seven components that carry that state. Permissions
and tool state are opaque parts of the session/kernel/manifest blobs at this
layer; they are not separate fields yet. Workspace files travel in the bundle,
not in a snapshot component.

## Components

`Component` is a closed enum of exactly seven values:

| Component | File name | Kind in the manifest | Required |
|---|---|---|---|
| `Session` | `session` | `session-transcript` | yes |
| `Kernel` | `kernel` | `kernel-checkpoint` | yes |
| `Artifacts` | `artifacts` | `artifact-index` | no |
| `Goals` | `goals` | `goal-state` | no |
| `Schedules` | `schedules` | `schedule-state` | no |
| `Ledger` | `ledger` | `usage-ledger` | no |
| `Manifest` | `manifest` | `workspace-manifest` | yes |

A caller supplies `ComponentBlob { component, bytes }`. The bytes are opaque:
this module never parses a transcript, a kernel checkpoint, or a workspace
manifest. The file name is fixed by the enum and is never derived from caller
text, so a component cannot name `../` or `.zero/vault`.

The required set is session, kernel, and workspace manifest. Artifacts, goals,
schedules, and the ledger are optional; when present they are recorded in the
manifest, and `SnapshotManifest::missing_optional` reports the optional ones
that were not supplied. A snapshot with only the three required components
verifies and restores.

## Snapshot manifest

```text
SnapshotManifest {
    schema_version: u32           1 in this build
    snapshot_id: String           64 lower-case hex, derived from the content
    created_ms: i64               caller clock, milliseconds since the epoch
    project_id: String            display/identity label, no path separators
    components: BTreeMap<Component, ComponentMeta>
    excluded: Vec<String>         sorted, unique secret-like paths left out
}

ComponentMeta {
    bytes: usize                  blob length
    blake3: String                64 lower-case hex digest of the blob
    kind: String                  fixed content-kind label from the table above
}
```

`components` is a `BTreeMap` and `excluded` is sorted and deduplicated, so
insertion order never changes the encoding. The manifest contains no blob
value, no preview, no file path, and no secret value; it carries sizes, hashes,
and labels only.

### Canonical encoding

The device signs the manifest's canonical bytes. The layout is deterministic
and length-prefixed, all integers big-endian:

```text
"zero.teleport.manifest.v1\0"   domain separator
schema_version                  u32
snapshot_id                     u32 length + UTF-8
created_ms                      i64
project_id                      u32 length + UTF-8
component count                 u32
repeated components, ascending:
  component label               u32 length + UTF-8
  kind                          u32 length + UTF-8
  bytes                         u64
  blake3                        u32 length + UTF-8
excluded count                  u32
repeated exclusions, sorted:    u32 length + UTF-8
```

Validation is part of canonicalisation and refuses:

- a schema version other than 1 (`zero.fnd.schema_version`);
- a snapshot id or digest that is not 64 lower-case hex characters;
- an empty project id, a padded project id, a control character, a path
  separator, or `.`/`..`;
- a missing required component;
- a component kind that differs from the fixed label;
- more than 16 MiB in one component or 64 MiB across the snapshot;
- an unsorted or duplicate exclusion list, an empty entry, a control character,
  or an entry above 256 bytes;
- a canonical manifest above 64 KiB;
- a snapshot id that does not match the manifest content.

Invalid shapes are `zero.fnd.invalid_input`; size and count overruns are
`zero.fnd.limit_exceeded`.

### Snapshot id

`snapshot_id` is the lower-case hex blake3 of a preimage under the
`zero.teleport.snapshot-id.v1` domain. The preimage contains the schema
version, `created_ms`, `project_id`, every component's label, kind, size, and
blake3, and the sorted exclusions. The signature is excluded.

The id is therefore deterministic for the same project, clock, and component
content, and independent of caller order. Two `create` calls with the same
inputs produce the same id and the same Ed25519 signature (RFC 8032 signatures
are deterministic). A different clock, project, or byte changes the id.

### Signature

`create(project_id, blobs, now_ms, device_key)` hashes each blob, builds the
manifest, derives the id, and signs the canonical manifest with the device's
Ed25519 key. `Snapshot.signature_b64` is the standard padded base64 signature.
The signature is not part of the manifest and is not covered by itself.

`verify(snapshot, device_pubkey)` checks, in order:

1. the manifest validates (schema, ids, required set, caps, kinds, exclusions,
   content-derived id);
2. the blob set is exactly the manifest's component set;
3. every blob's length and blake3 digest match its manifest entry;
4. the signature verifies over the canonical manifest with `device_pubkey`.

A changed blob is `zero.tru.tamper`; a changed or foreign signature is
`zero.pol.denied`. Because the signature covers each blob's hash, a modified
blob cannot be re-bound without the device key.

## Caps and exclusions

| Bound | Value | Error |
|---|---|---|
| one component | 16 MiB | `zero.fnd.limit_exceeded` |
| all components | 64 MiB | `zero.fnd.limit_exceeded` |
| canonical manifest | 64 KiB | `zero.fnd.limit_exceeded` |
| exclusions | 256 entries, 256 bytes each | `zero.fnd.limit_exceeded` |
| project id | 128 bytes | `zero.fnd.limit_exceeded` |

The snapshot is structured state, not a workspace copy. Files travel in the
content-addressed bundle (`TEL-02`), which has its own chunking and exclusion
rules. The 16 MiB per-component bound is a snapshot-state bound; a transcript
larger than it belongs in the bundle/session-store path, not in one blob.

### Secret-like components

`classify_component(label)` accepts a component name (and
`workspace-manifest` as an alias for `manifest`). `is_secret_like(label)`
matches, after normalising `\` to `/`:

- `.zero/vault` and anything under it;
- `.env`, `.env.*`;
- `credentials`, `credential`, and names beginning `credentials.` or
  `credential.`;
- `id_rsa`, `id_ed25519`, and `*.pem`, `*.p12`, `*.pfx`.

A secret-like label is `zero.pol.denied` and can never become a
`ComponentBlob::from_label` or a `Component`. `.zero/key` is the project
identity, not a credential, so it is **not** classified as secret; the
features document says identity is included while credentials never are.

`create_excluding(project_id, blobs, excluded, now_ms, key)` records the TEL-05
report in `SnapshotManifest::excluded`: secret-like or user-excluded paths the
caller left out. Entries are validated, sorted, and deduplicated. A label that
names a supplied component is contradictory and refused; a secret-like label is
allowed in `excluded` precisely because it was excluded.

**Honest limit:** this is a label check, not a content scan. An opaque session
or kernel blob could contain a secret value, and this module will not detect
it. Secret scanning and redaction belong to the session/secret layers and the
bundle exclusion pass (TEL-05); the manifest never records a blob value, so it
cannot leak one through this path.

## Same-device restore

```text
restore(snapshot, target_root, device_pubkey, now_ms) -> RestoredSnapshot
```

Restore runs in this order:

1. **Verify.** If the signature, manifest, or any blob hash fails, the call
   returns before creating a directory or file. A tampered or partial snapshot
   writes nothing.
2. **Prepare.** `target_root` is created if absent, then `.zero`, then
   `.zero/teleport`. Each level is refused if it is a symlink or not a
   directory.
3. **Check the destination.** `snap-<id>` is derived from the manifest's
   64-hex snapshot id. An existing directory is re-verified against the signed
   manifest and the component hashes:
   - the exact snapshot is returned with `already_present = true`;
   - a different manifest, a corrupted component, a missing component, a
     symlink, or a non-directory is refused and left untouched.
4. **Stage.** A unique `.snap-<id>.tmp-<random>` directory is created under
   `.zero/teleport`.
5. **Write.** Each component is written to `<component>.partial` with
   `create_new`, flushed with `sync_all`, and renamed to its final name. The
   signed manifest is written to `snapshot.json` **after every component**.
6. **Publish.** The staging directory is renamed to `snap-<id>`. On any error
   the staging directory is removed and the destination is not created.

The resulting layout is:

```text
<target_root>/
  .zero/
    teleport/
      snap-<snapshot_id>/
        session
        kernel
        artifacts      (when supplied)
        goals          (when supplied)
        schedules      (when supplied)
        ledger         (when supplied)
        manifest       the workspace manifest component
        snapshot.json  the signed snapshot manifest, written last
```

`RestoredSnapshot` returns the snapshot id, the directory, a
`BTreeMap<Component, PathBuf>` of restored files, the manifest path, the
lower-case hex blake3 of the canonical manifest, the restore clock, and the
`already_present` flag. `snapshot.json` contains
`{ "manifest": <SnapshotManifest>, "signature_b64": <string> }`; the component
bytes are in the sibling files, not duplicated into the manifest.

The manifest file is named `snapshot.json` so it cannot collide with the
`Manifest` component's file, which is the workspace manifest named `manifest`.
"Manifest written last" means `snapshot.json`; the workspace manifest component
is an ordinary component written in the component pass.

### Tamper behaviour

| Situation | Result | Writes |
|---|---|---|
| one blob byte changed | `zero.tru.tamper` | none |
| signature changed or foreign key | `zero.pol.denied` | none |
| required component absent | `zero.fnd.invalid_input` / `zero.tru.tamper` | none |
| extra blob not in the manifest | `zero.tru.tamper` | none |
| manifest id does not match content | `zero.fnd.invalid_input` | none |
| schema version unknown | `zero.fnd.schema_version` | none |
| destination already holds this snapshot | success, `already_present = true` | none |
| destination holds a different snapshot | `zero.pol.denied` | none |
| destination is a symlink or a file | `zero.pol.denied` | none |
| existing restored component is corrupted | `zero.tru.tamper` | none |

Verification happens before directory creation, so the "none" column is literal
for every verify failure: `.zero` does not appear under the target root.

## Content-addressed bundle (T-TEL-02)

`bundle::build(files, excluded, config, now_ms)` turns a
`BTreeMap<String, Vec<u8>>` of workspace-relative paths into a
`Bundle { manifest, chunks }`. `bundle::build_files` is the same builder for
entries that carry a Unix `mode` or record a symlink. The bundle is a value: it
does not read the workspace itself and it opens no socket.

### Chunking and dedupe

- `ChunkConfig { chunk_bytes, max_chunks }` defaults to `DEFAULT_CHUNK_BYTES`
  (1 MiB) and `DEFAULT_MAX_CHUNKS` (1,048,576 chunk references).
  `ChunkConfig::new` refuses a zero or oversized chunk and a zero ceiling; a
  chunk may be at most `MAX_CHUNK_BYTES` (64 MiB).
- Every file is split into `chunk_bytes` blocks; the last block may be smaller.
  A zero-byte file has zero chunks and `bytes = 0`.
- `ChunkRef { hash, bytes }` records the lower-case hex blake3 digest and the
  chunk length. The hash is also the chunk's file name.
- Identical chunks are stored **once for the whole bundle**, even when several
  files — or several offsets in one file — refer to them. `total_chunks` counts
  references; `BundleStats` reports `files`, `chunk_references`,
  `unique_chunks`, `logical_bytes`, `stored_bytes`, and
  `dedupe_saved_bytes()` (`logical - stored`).
- Every chunk's blake3 is computed while splitting and checked against the
  stored copy, so a hash collision or a mismatch is `zero.tru.tamper` rather
  than a silently corrupted bundle.

A file's `bytes` must equal the sum of its `ChunkRef::bytes`, and the manifest's
`total_chunks`/`total_bytes` must equal the sums over every file. The limits are
`MAX_FILES` (65,536), `MAX_TOTAL_CHUNKS` (2,097,152 references), and
`MAX_BUNDLE_BYTES` (1 TiB).

### Bundle manifest

```text
BundleManifest {
    schema_version: u32        1 in this build
    bundle_id: String          64 lower-case hex, derived from the content
    created_ms: i64            caller clock, milliseconds since the epoch
    files: BTreeMap<String, FileEntry>
    excluded: Vec<Excluded>    sorted, unique { path, reason }
    total_chunks: u64          chunk references before dedupe
    total_bytes: u64           logical size of every file
}

FileEntry {
    chunks: Vec<ChunkRef>      ordered chunks
    bytes: u64                 logical file length
    mode: Option<u32>          Unix permission bits; None is the default
    symlink: bool              true when the chunks carry a link target
}
```

`files` and `excluded` are ordered, so insertion order never changes the
encoding. The manifest carries hashes and sizes, never a chunk value.

A bundle path is validated before anything else: it must be non-empty, at most
`MAX_PATH_BYTES` (1024 bytes), free of control characters, relative, use forward
slashes, carry no drive letter, and have no empty, `.`, or `..` component and no
component ending in a dot or space. This keeps `a/../../etc/passwd`,
`C:/Windows`, and a Windows-ambiguous `notes.` out of the tree.

`BundleManifest::canonical_bytes()` is deterministic and length-prefixed (all
integers big-endian):

```text
"zero.teleport.bundle.v1\0"     domain separator
schema_version                  u32
bundle_id                       u32 length + UTF-8
created_ms                      i64
file count                      u32
repeated files, ascending path:
  path                          u32 length + UTF-8
  bytes                         u64
  mode present                  u8 (0 or 1)
    mode                        u32 when present
  symlink                       u8 (0 or 1)
  chunk count                   u32
  repeated chunks, in file order:
    hash                        u32 length + UTF-8
    bytes                       u64
excluded count                  u32
repeated exclusions, sorted:
  path                          u32 length + UTF-8
  reason                        u32 length + UTF-8
total_chunks                    u64
total_bytes                     u64
```

Canonicalisation validates the schema version, the 64-hex bundle id, every
path, every chunk hash and size (`1..=MAX_CHUNK_BYTES`), the per-file and total
sums, the exclusion list, and the content-derived id. A canonical manifest
above `MAX_BUNDLE_MANIFEST_BYTES` (16 MiB) is `zero.fnd.limit_exceeded`.
`bundle_manifest_hash(manifest)` is the lower-case hex blake3 of those bytes.

`bundle_id` is derived from a domain-separated preimage of the schema version,
`created_ms`, every file entry, and the sorted exclusions. It is deterministic
for the same inputs and changes when a file, mode, symlink flag, exclusion, or
the clock changes. The id deliberately does not include itself or
`total_chunks`/`total_bytes`, which are derived.

Typed failures follow the crate's error codes: a missing or hash-mismatched
chunk is `zero.tru.tamper`; an unsafe path, a wrong sum, or an id that does not
match the content is `zero.fnd.invalid_input`; a different bundle already in the
directory, a secret-like file path, or a refused symlink is `zero.pol.denied`;
a cap is `zero.fnd.limit_exceeded`; an unknown manifest or checkpoint schema is
`zero.fnd.schema_version`.

### Checkpoint and resume

`BundleWriter` writes a bundle directory as:

```text
<dir>/
  bundle.json        the BundleManifest
  checkpoint.json    { schema_version, bundle_id, written, offsets }
  <hash>             one file per unique chunk, named by its hash
  <hash>.part        only while a chunk is being written
```

`BundleWriter::create(dir, manifest)` creates the directory, writes
`bundle.json` atomically, and refuses a directory that already holds a different
manifest (`zero.pol.denied`). `BundleWriter::resume(dir)` loads `bundle.json` and
`checkpoint.json`; a directory without a manifest is
`zero.fnd.invalid_input`, and a checkpoint for another bundle is
`zero.pol.denied`.

`write_pending(&chunks)` first **reconciles** the checkpoint with the disk: each
recorded chunk is re-hashed, and a missing, truncated, or hash-mismatched file
is dropped from `written`, its stale `.part` removed, and the chunk rewritten.
It then writes the remaining chunks and hashes every chunk once more before
returning `WriteReport { bundle_id, written, already_present, repaired,
complete, stored_bytes }`. A needed hash absent from the supplied chunk map is
`zero.fnd.invalid_input`; bytes that do not hash to their key are
`zero.tru.tamper`.

`write_one_pending(&chunks)` writes at most one chunk and returns its hash; this
is the progressive-send seam used by the interruption test. `is_complete()`
reports the checkpoint's view; `BundleReader::verify` re-hashes the files.

After each chunk the writer replaces `checkpoint.json` atomically: it writes
`checkpoint.json.partial`, calls `sync_all`, and renames it over the checkpoint,
so a killed process has a usable resume point with the previous chunk set. The
checkpoint records `written` (the durable hashes) and `offsets` (durable bytes
per chunk, for progress display). `offsets` is advisory: a partial chunk is
never trusted from the offset alone, because its prefix has not been verified;
the chunk is rewritten and re-hashed.

`Bundle::write_to(dir)` writes from scratch, and
`Bundle::write_resumable(dir)` creates a fresh directory or resumes an existing
one — the ordinary sender entry point. Both refuse a different bundle already in
the directory.

### Exclusions

`Excluded { path, reason }` is the TEL-05 report. Exclusions are validated
(reason required, at most `MAX_EXCLUDED_REASON_BYTES` = 256 bytes), sorted, and
deduplicated, then written into the manifest and counted by `verify()`; they are
never dropped silently. An exclusion may name a secret-like path precisely
because it was left out.

`build` refuses a secret-like **file** path — the vault, a credential store,
`.env`, a private key — with `zero.pol.denied`, so a secret cannot enter a
bundle by accident. Supplying a path and also listing it as excluded is
contradictory and `zero.fnd.invalid_input`. This is a path/label check, not a
content scan; secret detection inside file bytes belongs to the secret layer and
the TEL-05 exclusion pass.

### Verify and materialize

`BundleReader::open(dir)` reads and validates `bundle.json`; it does not read
chunks. `verify()` then reads every unique chunk named by the manifest, checks
its hash and length, and checks that each file's chunks reassemble to the
declared `bytes`. A missing chunk or a hash mismatch is `zero.tru.tamper`; the
report carries the bundle id, manifest hash, file/chunk counts, stored and
logical bytes, and the exclusion count.

`materialize(target)` verifies first, then writes every file under `target`:

- the target and its parents are created; an intermediate symlink is refused;
- a destination that already holds identical bytes is counted in
  `already_present` and left alone;
- a destination with different content, a directory, or a symlink is
  `zero.pol.denied` and is **not overwritten**;
- each file is written to a hidden random `.part` name, `sync_all`'d, and
  renamed into place; Unix modes from `FileEntry::mode` are applied (masked to
  `0o7777`) and ignored on Windows;
- a manifest that records a symlink is refused with `zero.pol.denied` unless
  `materialize_with(target, MaterializeOptions { allow_symlinks: true })` is
  used. Symlink creation is Unix-only; on Windows a recorded symlink is still
  refused. The link target was validated as a safe relative path at build time.

`materialize` is not atomic: files written before an error stay in place, and
the caller gets the typed refusal. It never overwrites different content, which
is the safe half of TEL-08's "stage or reconcile, never overwrite"; the staged
full-tree restore with preflight, rollback, and adoption is
[`restore::restore`](#full-restore-t-tel-04) (T-TEL-04).

## Encrypted transfer (T-TEL-03)

`transfer::seal_bundle(bundle, recipient)` turns a built `Bundle` into a
`SealedBundle`; `transfer::open_bundle_verified(sealed, recipient_secret)`
returns a `VerifiedTransfer`. The envelope is a value: it opens no socket, and
the relay or any other transport never needs a key. The T-TEL-03 done criterion
— **a corrupted chunk fails verification** — is
`transfer::tests::a_corrupted_chunk_fails_verification`.

### Key agreement and the per-bundle key

- `RecipientSecret` is an X25519 secret; `RecipientKey` is its public half. The
  `recipient_id` is the lower-case hex blake3 of
  `"zero.teleport.transfer.recipient-id.v1\0" || public_key`, not the key
  itself, so it is safe in a log or a routing table.
- `seal_bundle` creates a one-use `SenderSecret` from OS entropy
  (`seal_bundle_with_seed` is the deterministic test seam) and computes
  `shared = X25519(ephemeral_secret, recipient_public)`. A non-contributory
  shared secret is refused with `zero.pol.denied`.
- `HKDF-SHA256(salt = ephemeral_public || recipient_public, ikm = shared,
  info = "zero.teleport.transfer.key.v1\0" || bundle_id)` yields the 32-byte
  ChaCha20-Poly1305 key. The bundle id travels in the clear header (it is a
  content hash) precisely so the receiver can derive the same key before the
  manifest is decrypted.

### Wire shape

```text
SealedBundle {
    schema_version: u32              1 in this build
    bundle_id: String                64 lower-case hex, cleartext
    manifest_hash: String            64 lower-case hex blake3, cleartext
    recipient_id: String             64 lower-case hex, cleartext
    ephemeral_public: String         base64 32-byte X25519 public key
    manifest_nonce: String           base64 12 bytes
    manifest_ciphertext: String      base64 ChaCha20-Poly1305 ciphertext + tag
    chunks: Vec<SealedChunk>         unique chunks, ascending by hash
    plaintext_bytes: u64             logical bytes of every file
    stored_bytes: u64                bytes of the unique plaintext chunks
}

SealedChunk {
    chunk_hash: String              64 lower-case hex blake3, cleartext
    bytes: u64                      plaintext length, cleartext
    nonce: String                   base64 12 bytes
    ciphertext: String              base64 ChaCha20-Poly1305 ciphertext + tag
}
```

The manifest is encrypted as compact JSON and exposed only as
`manifest_ciphertext`. The unique chunks are sealed in the manifest's ascending
`chunk_hashes()` order, so chunk index *i* is stable. There is no key field, no
plaintext field, and no accessor that decrypts: a relay can drop the envelope
or forward it byte for byte.

### Nonces and AAD

ChaCha20-Poly1305 uses a fresh 96-bit nonce for every AEAD operation, derived
with HKDF-Expand from the same per-bundle PRK:

- manifest: `expand("…nonce.manifest.v1\0" || bundle_id)`;
- chunk *i*: `expand("…nonce.chunk.v1\0" || bundle_id || u64_be(i))`.

The nonce is also stored in the envelope and must equal the derived nonce on
open; a changed nonce fails. Because the key is per-bundle and *i* is unique, a
nonce is never reused under one key. The manifest nonce uses a different domain,
so it cannot collide with a chunk nonce (the loader also rejects a duplicate
nonce in the envelope).

The associated data binds the plaintext identity:

- manifest: `"…aad.manifest.v1\0" || bundle_id || manifest_hash`;
- chunk *i*: `"…aad.chunk.v1\0" || bundle_id || u64_be(i) || chunk_hash`.

A swapped chunk, a reordered envelope, a changed chunk hash, or a changed
manifest hash therefore fails authentication even when the ciphertext bytes are
otherwise intact.

### Verification

`open_bundle_verified` runs, in order and without writing anything:

1. **Shape.** `SealedBundle::validate` checks the schema, the 64-hex ids, the
   base64 lengths, the 12-byte nonces, strict chunk order with no duplicates,
   nonce uniqueness, `ciphertext.len() == bytes + 16`, the declared stored
   bytes, and the bundle-wide caps. It needs no key.
2. **Recipient.** The envelope's `recipient_id` must equal the id derived from
   the supplied secret; a different key is `zero.pol.denied`.
3. **Key agreement.** ECDH and HKDF derive the per-bundle key.
4. **Manifest.** Decrypt, deserialize, run `canonical_bytes()`, and compare the
   computed manifest hash and bundle id with the cleartext header.
5. **Chunk set.** The sealed chunk hashes and order must equal
   `manifest.chunk_hashes()`.
6. **Chunks.** For each chunk: the stored nonce equals the derived nonce, the
   AEAD decrypts, the plaintext length matches `bytes`, and the plaintext blake3
   equals `chunk_hash`.
7. **Bundle.** `bundle::verify_bundle` re-checks every file, every chunk length,
   every file sum, and the manifest's content-derived id.

A failure returns a typed error and no `Bundle`; there is no partial
materialization because the transfer never writes to disk. `open_bundle` is the
plain `Bundle` form; `open_bundle_verified` returns the `VerifiedTransfer` with
`verified_chunks` and the canonical `manifest_hash`.

| Situation | Result |
|---|---|
| changed ciphertext, tag, nonce, or AAD | `zero.tru.tamper` |
| changed chunk hash or plaintext hash | `zero.tru.tamper` |
| missing or duplicate chunk | `zero.tru.tamper` |
| truncated ciphertext or chunk list | `zero.tru.tamper` |
| manifest hash or bundle id does not match | `zero.tru.tamper` |
| wrong recipient key | `zero.pol.denied` |
| malformed base64, bad hex, wrong nonce length, zero-length chunk | `zero.fnd.invalid_input` |
| unknown schema version | `zero.fnd.schema_version` |
| chunk, manifest, or bundle cap exceeded | `zero.fnd.limit_exceeded` |

### Retention until verified

`retain_until_verified(source_dir, target_dir, verified)` is the TEL-06 policy:

- `verified = None` (failed or unfinished): `kept_source` and `kept_staging`
  report whether each path exists, and `can_cleanup` is `false`; nothing is
  removed.
- `verified = Some(..)`: both paths are still reported as kept and
  `can_cleanup` is `true`; cleanup is permitted but not performed.

`retain_until_verified_with(.., RetentionOptions { cleanup_source: true })` is
the only form that deletes anything. A failed transfer still removes nothing.
A verified transfer removes **the source** and never the target, after refusing
a symlink source, a non-directory source or target, a source with no parent, a
source equal to the target, and either path containing the other. The helper is
a policy gate for a disposable transfer source, not a replacement for the OS
trash for user data.

### Transfer report

`transfer_report(sealed, verified)` returns the bundle id, manifest hash,
recipient id, unique chunk count, logical bytes, stored bytes, and ciphertext
bytes on the wire (including tags and the encrypted manifest). A sealed
envelope and a verified bundle that name different content is
`zero.fnd.invalid_input`. The report contains no key material.

### Dependency rationale

| Crate | Version | Licence / MSRV | Why this line |
|---|---|---|---|
| `x25519-dalek` | 2.0.1 | BSD-3-Clause, 1.60 (declared) | Shares `curve25519-dalek` 4 with `ed25519-dalek` 2.2; `static_secrets` gives a seedable ephemeral key. |
| `chacha20poly1305` | 0.10.1 | Apache-2.0 OR MIT, 1.60 (ecosystem) | Shares `aead` 0.5 with `aes-gcm` 0.10; `default-features = false, features = ["alloc"]` because nonces are derived, not sampled. |
| `hkdf` | 0.12.4 | MIT OR Apache-2.0, 1.60 (ecosystem) | `hmac` 0.12 / digest 0.10, reusing the workspace `sha2` 0.10. |

The 2026 majors (`x25519-dalek` 3, `chacha20poly1305` 0.11, `hkdf` 0.13) exist
but need digest 0.11, `aead` 0.6, and `curve25519-dalek` 5 — a second copy of
the same primitives alongside the ones this workspace already uses. The selected
lines keep one digest/aead/curve stack. `zeroize` (already a workspace
dependency) clears the derived key.

## Full restore (T-TEL-04)

`restore::restore(plan, target_root, options)` recreates workspace directories,
files, Unix modes, and recorded symlinks, then writes the teleport components and
the optional child registry. The T-TEL-04 done criterion is
`restore::tests::a_conflicting_file_is_staged_and_not_overwritten`: **restore
into a conflicting directory stages instead of overwriting**.

### Restore plan

```text
RestorePlan {
    bundle_id: String                      64 lower-case hex
    entries: Vec<RestoreEntry>             workspace paths
    contents: BTreeMap<String, Vec<u8>>    exact bytes for files and symlinks
    components: BTreeMap<Component, Vec<u8>>
    children: Option<Vec<u8>>              child registry
}

RestoreEntry {
    path: String                           safe, relative, forward slashes
    kind: File | Dir | Symlink { target }
    bytes: u64                             file/target bytes, zero for a directory
    hash: String                           lower-case hex blake3 of the content
    mode: Option<u32>                      Unix permission bits
    component: Option<Component>           provenance, not a second destination
}
```

`RestorePlan::from_bundle(bundle, components, children)` calls
`bundle::verify_bundle` first, reassembles every file in memory, hashes it, and
records the mode or the recorded symlink target. `build_plan` is the same
operation as a free function. `contents` is the verified payload; a caller that
constructs a plan by hand must keep every file and symlink's `bytes`, `hash`,
and `contents` consistent.

Validation runs before anything is written and refuses:

- a bundle id or entry hash that is not 64 lower-case hex characters;
- a path that is empty, absolute, has a drive letter, uses backslashes, has an
  empty/`.`/`..` component, or ends a component with a dot or space;
- a path inside `.zero` (internal state is never restored as a workspace entry);
- a duplicate path, a path nested under a file/symlink entry, or content with no
  matching entry;
- a file or symlink whose size or blake3 does not match `contents`;
- a symlink target that is absolute, uses a backslash, carries a drive letter,
  is empty, or resolves outside `target_root`;
- a mode above `0o7777`;
- a `Component::Manifest` component (the workspace manifest travels as entries),
  or a component larger than 16 MiB / a total above 64 MiB.

### Preflight, then apply

`restore` performs a full preflight before the first write:

1. **Plan validation.** Every path, hash, mode, symlink target, and component is
   checked.
2. **Internal paths.** `target_root` must be a real directory or absent.
   `.zero`, `.zero/restore-staging`, `.zero/teleport`, the bundle directory, and
   its `components` directory must be real directories when they exist; a
   symlink or file in any of those positions refuses the restore.
3. **Per-path decision.** Each entry becomes `Create`, `Skip` (identical
   content), or `Conflict` with the existing hash. A blocked parent directory, a
   destination symlink, a directory in the way of a file, and a file in the way
   of a directory are conflicts; they are never followed or replaced.
4. **Components.** An existing component file with identical bytes is `Skip`;
   different bytes, a symlink, or a directory is refused as tampering.

Only then does apply create `target_root`, `.zero`,
`.zero/teleport/<bundle_id>/components`, and any needed parent directories.
Every file or component is written to a hidden `.partial` file in the
destination directory, `sync_all`'d, mode-set on Unix, and renamed into place.
If an I/O failure occurs during apply, paths created by this call are removed
again in reverse order; if rollback itself fails, the error names what remains.
Pre-existing conflicting files are never touched.

### Conflict staging and adoption

A conflict stages the incoming content at:

```text
<target_root>/.zero/restore-staging/<bundle_id>/<path>
```

`RestoreReport::staged` records `{ path, existing_hash, incoming_hash,
staged_path }`, and `conflicts` is its count. A staged file is byte-identical to
the incoming file; a staged symlink is a link with the recorded target; a staged
directory is an empty directory. The existing path is left exactly as it was.
A second restore reuses an identical staged copy and stages nothing new.

`adopt(&mut report, path)` is the explicit user action from TEL-08:

- the target must be absent or still match `existing_hash`; a file that changed
  after review is refused;
- a target directory is never removed, and a staged directory is never adopted;
- a staged file is moved into place, a staged symlink is recreated after the old
  link/file is removed, and the conflict is removed from the report.

`RestoreOptions { overwrite_existing: true }` is the explicit per-path opt-in
for the same restore. It replaces a conflicting regular file, or a recorded
symlink with a different target, and still records the conflict and the staged
copy. It never performs a file/directory type change. A later failure cannot
restore the old bytes of an already-overwritten path; that path is named in the
rollback report.

### Modes and symlinks

- A new file or directory gets `RestoreEntry::mode & 0o7777` on Unix. Modes are
  recorded but ignored on Windows.
- A recorded symlink is created by default on Unix. Its target is validated as a
  relative forward-slash path that resolves inside the restore root, so
  `../escape` and `C:/Windows` are refused. On Windows a plan that records a
  symlink is refused during preflight, before any write.
- An existing destination symlink is never followed: it is a conflict, staged,
  and left in place. An unrecorded symlink at a path the plan wants is therefore
  preserved, and the file it points at outside the root is not touched.
- A plan already inside a symlinked parent is a conflict; restore does not
  create files through a link.

### Components and children

Components are written atomically under:

```text
<target_root>/.zero/teleport/<bundle_id>/components/
    session       the transcript (including descendant/child registry entries)
    kernel        kernel state or checkpoint
    artifacts     artifact index
    goals         goal state
    schedules     schedules and heartbeats
    ledger        usage ledger
    children      optional child-registry blob
```

Only `Component::Manifest` is refused as a component: the workspace manifest
travels as `RestoreEntry` values. The session component is the transcript replay
payload; the `children` file is the child registry TEL-07 rebinds. Components
are idempotent: a repeat restore with identical bytes reports
`skipped_components` and writes nothing.

### Report

`RestoreReport` returns the bundle id, root, created/replaced paths
(`restored`), paths replaced by the opt-in (`overwritten`), identical entry and
component counts, the staged conflicts, the conflict count, the component path
map, and the child-registry path. `RestorePlan`'s `Debug` prints ids and counts,
never file or component bytes.

## Fence and resume (T-TEL-05)

`fence` is the write-lease and generation model for teleport (TEL-10, TEL-11,
FS-10). The done criterion is
`fence::tests::a_stale_holder_cannot_write_after_handoff`: **the source cannot
write after fencing**.

### Lease and generation

```text
Lease {
    resource: String              session journal, workspace path, or opaque id
    holder: HolderId              opaque device/session label
    generation: LeaseGeneration   fencing token, 1 for the first lease
    acquired_ms: i64              caller clock at acquisition
    expires_ms: i64               caller clock; now >= expires is expired
}
```

`Lease::new(resource, holder, now_ms, ttl_ms)` creates generation 1.
`Lease::verify(now_ms)` refuses an expired or malformed lease with
`zero.ses.lease_held` / `zero.fnd.invalid_input`. TTLs are positive and at most
`MAX_LEASE_TTL_MS` (24 h); holder ids are at most `MAX_HOLDER_BYTES` (128) and
resource names at most `MAX_RESOURCE_BYTES` (512). The generation, not the
clock, orders holders: `now_ms` only expires a lease on its own host, while
cross-device compare-and-set uses the generation.

### Handoff and compare-and-set

`handoff(current, new_holder, now_ms, ttl_ms)` returns a new lease with
`generation + 1`, the new holder, a fresh `acquired_ms`, and a new expiry. It
does not mutate `current`; the store replaces it. An expired current lease may
still be handed off: expiry frees the resource, and a forced takeover must
advance the generation.

`handoff_if(current, expected_generation, new_holder, now_ms, ttl_ms)` is the
compare-and-set. It succeeds only while `current.generation` equals the
observed generation. Two contenders that both observed generation *G* produce
one winner; the loser's call against the committed generation *G+1* lease is
`zero.fs.conflict` (`ErrorCode::Conflict`). The generation is checked before it
is incremented and never wraps: `u64::MAX` is `zero.fnd.limit_exceeded`.

`renew(lease, now_ms, ttl_ms)` extends only a live lease, preserving the
resource, holder, generation, and acquisition time. An expired lease is
`zero.ses.lease_held`. Possession of the current lease is the authority; a
superseded copy can renew only itself, and its generation is still stale
against the store.

`release(lease, holder)` is holder-only: a different holder is
`zero.pol.denied`. It returns the generation that was released. The generation
is retained in the handoff history; the next acquisition advances it.

### Stale-holder refusal

`fence(current, observed_generation)` refuses anything but the current
generation with `zero.ses.lease_held`. `assert_can_write(lease, generation,
now_ms)` is the complete gate intended for restore and transfer paths: it
checks expiry first and then the generation. After a handoff the source
presents the old generation, fails the comparison, and cannot write. A future
generation is refused the same way.

The model is a value, not a lock. The store that owns the lease must pass its
current value and commit the winner of a CAS; `handoff_if` cannot detect a
stale argument that a caller supplies instead of the stored lease.

### Resume and snapshot

```text
ResumeCursor { generation, sequence }    sequence = last applied journal record
ResumePlan   { generation, from_seq, snapshot }
```

`resume(lease, cursor, journal_seq)`:

- **Current generation.** `from_seq = cursor.sequence + 1`; the client resumes
  events after the last one it applied. A cursor at the journal head yields
  `journal_seq + 1` (no events yet).
- **Older generation.** `snapshot = true`: no event crosses a fence. The plan
  adopts the current generation and starts after the journal head, and the
  client resets its effect state from the snapshot.
- **Future generation.** `zero.pol.denied`; a client cannot claim a generation
  the store has not reached.
- **Cursor ahead of the journal.** `zero.fnd.invalid_input`; it is corrupt, not
  clamped.
- **Monotonicity.** A plan never starts at or before a sequence the cursor
  already applied (`ResumePlan::replays_effect`), so a resumed turn never
  replays an effect. A snapshot replaces state and is not an event replay.

`Lease`, `HolderId`, `LeaseGeneration`, `ResumeCursor`, and `ResumePlan`
round-trip through serde.

## Portability (T-TEL-06)

Portability is the TEL-12/TEL-13/TEL-14 boundary around a cross-OS move. The
done criterion is **a Windows-to-Linux run and a no-git directory run pass**;
`portability::tests::windows_drive_and_unc_paths_remap_to_posix` and
`portability::tests::a_no_git_directory_passes_without_git` are the direct
evidence. Nothing in this section spawns a process, installs a package, or opens
a socket: it produces and checks values that a later executor can apply.

### Path maps and `remap_path`

```text
PathMap {
    from_root: String             absolute source root
    to_root: String               absolute target root
    case_insensitive_source: bool compare non-drive components ignoring case
}
```

`remap_path(path, map)` accepts one absolute path and returns the target path,
or a typed refusal:

| Situation | Result |
|---|---|
| `C:\Users\Alice\Proj\src\main.rs` -> `/home/alice/proj` | `/home/alice/proj/src/main.rs` |
| `\\Server\Share\Proj\src` -> `/mnt/share/proj` | `/mnt/share/proj/src` |
| `/home/alice/proj/src` -> `C:\Users\Alice\Proj` | `C:\Users\Alice\Proj\src` |
| `/mnt/share/proj/src` -> `\\Server\Share\Proj` | `\\Server\Share\Proj\src` |
| case-only difference, source case-insensitive | accepted; remainder case is preserved |
| case-only difference, source case-sensitive | `zero.fnd.invalid_input` |
| path outside `from_root` (including a prefix that is not a component boundary) | `zero.fnd.invalid_input` |
| any `..` component, a relative path, or a non-absolute root | `zero.fnd.invalid_input` |
| Windows device path (`\\?\`, `\\.\`) | `zero.fnd.invalid_input` |
| path or root above `MAX_REMAP_PATH_BYTES` (8 KiB) | `zero.fnd.limit_exceeded` |

Separators are converted in both directions (`\` and `/` are accepted on input;
a drive or UNC target is written with `\`, a POSIX target with `/`). Repeated
separators collapse and `.` components are removed. The drive letter and a UNC
server/share must match the source root; a drive letter always compares
case-insensitively, while every non-drive component follows
`case_insensitive_source`. Spaces and non-ASCII bytes in the remainder are
preserved exactly. A UNC path requires both a server and a share.

`working_directory_notice(map)` returns the TEL-12 context line (`The workspace
moved during teleport: ...`) for the caller to insert as a system message. This
module does not know the session format, so it does not edit the transcript
itself.

### Text remapping

`remap_text(text, maps)` scans a transcript or config fragment and rewrites only
tokens that are both absolute and inside a map's `from_root`:

- a plain token is a maximal run of non-whitespace path characters; surrounding
  punctuation is preserved, so a sentence-ending period is not part of the path;
- a quoted or backtick-delimited value whose whole content is a path is treated
  as one token, which is how `"C:\Users\Alice Smith\Proj"` survives;
- JSON-escaped backslashes are normalised before matching, so
  `"C:\\Users\\Alice\\Proj"` remaps correctly;
- the first map that claims a token wins, and a later map is not tried;
- a token outside every root (`/etc/hosts`, `C++`, a relative path) is copied
  verbatim and is not counted;
- a token under a root that cannot be remapped safely (a `..` component, a
  case-sensitive mismatch) is copied verbatim and counted as
  `RemapReport::skipped`;
- `RemapReport { map, substituted, skipped }` is returned per map, in map order.

The input is capped at `MAX_REMAP_TEXT_BYTES` (1 MiB), the output at
`MAX_REMAP_OUTPUT_BYTES` (2 MiB), the token count at `MAX_REMAP_TOKENS`, and the
map count at `MAX_PATH_MAPS`. A cap is `zero.fnd.limit_exceeded`.

### Snapshot remapping and re-signing

`remap_snapshot(snapshot, maps, target_key)` returns a new `Snapshot`;
`remap_snapshot_report` additionally returns the per-map reports and the changed
component list.

- Only `REMAPPABLE_COMPONENTS` — `Session` (transcript), `Kernel`
  (checkpoint/config), and `Manifest` (workspace-manifest metadata) — are
  scanned. `Artifacts`, `Goals`, `Schedules`, and `Ledger` pass through
  byte-identically, and a non-UTF-8 blob in a remappable component is also
  passed through unchanged.
- Remapping changes a blob's bytes, so its blake3, size, and the content-derived
  snapshot id change. The source snapshot's signature is therefore invalid **by
  construction**. The rebuilt manifest is re-signed with the target device key
  and the source signature is discarded intentionally. Verify the source with
  `verify_snapshot` before calling this function; a re-sign is a trusted-device
  action, not verification.
- Before signing, the function checks that the supplied blobs match the supplied
  manifest (size and blake3). A tampered or partial input is
  `zero.tru.tamper` and is never blessed with the target key.
- Two calls with the same snapshot, maps, and target key produce the same
  snapshot id and signature (Ed25519 is deterministic).

### Kernel rebuild plan

```text
KernelRebuildPlan {
    python: String          bare target command: `python3` on Unix, `python` on Windows
    packages: Vec<String>   documented, sorted set
    offline_cache: bool     true only for a same-OS move
}
```

`plan_kernel_rebuild(source_os, target_os, available_python)` accepts
`windows`/`win`, `linux`, and `macos`/`darwin`/`osx`. The plan never carries a
Windows path: a Unix target gets a bare `python3`, a Windows target gets a bare
`python`. A Windows absolute `available_python` is refused for a Unix target, a
POSIX absolute one is refused for Windows, and Python 2 or an ambiguous `python`
on Unix is refused with guidance. The package list is the documented
`KERNEL_PACKAGES` set: `cloudpickle` (checkpoint format), `ipykernel` (kernel
transport), and `jupyter_client` (client protocol). A cross-OS move sets
`offline_cache = false` because compiled wheels and virtual environments do not
move between operating systems; a same-OS rebuild and reuse of the local wheel
cache is the one case where it is true.

### Tool preflight and no-git directories

```text
PreflightReport {
    ok: bool
    required: Vec<String>                 normalised, sorted
    available: Vec<String>                required tools the probe found
    missing: Vec<String>                  required tools it did not find
    guidance: BTreeMap<String, String>    per-tool install line
}
```

`preflight(required, probe)` takes any `ToolProbe` (`ToolSet` is a fixed set;
`ToolPreflight` is the declared-required/declared-available form and also
implements the trait). Tool names are trimmed, lower-cased, and a trailing
`.exe` is ignored. Every missing tool gets install guidance; unknown tools get
a generic `install it and put it on PATH` line. No process is spawned.

`can_run(plan, report, no_git_dir)` checks, in order:

1. the plan is valid (bare interpreter, unique package names);
2. `no_git_dir` is true and the plan requires `git` — **refused even when git is
   installed**, because a directory with no repository must never need git;
3. a required tool is missing — refused with every missing tool and its
   guidance;
4. the preflight did not check `plan.python`, or it did and the interpreter is
   absent — refused with the interpreter's install line.

A no-git directory therefore passes with `required = [python3, pip]` and no
`git`, and fails with `required = [git, python3]` even if a probe reports git.

### Honest limits

- **Text tokenisation is heuristic.** A path with spaces must be the whole
  quoted value; a path split by whitespace inside a larger quoted command is
  remapped word by word. A URL such as `file:///C:/work` is not treated as a
  path token, and a path containing a quote character is not parsed.
- **Format escaping is textual.** JSON-escaped backslashes are normalised for
  matching, but the output uses the target style's raw separators. A
  Windows-target rewrite inside a JSON string that needs `\\` escaping remains
  the caller's format concern.
- **No case-collision merge.** Two distinct source paths that differ only by
  case remain distinct after a POSIX-to-Windows remap; resolving a
  case-insensitive collision is not done here.
- **No live state moves.** Processes, PTYs, open sockets, and unpicklable kernel
  objects do not move (TEL-14). The kernel plan names packages to rebuild; it
  does not re-run the user's setup or prove the rebuilt state equals the old
  state.
- **Preflight is a probe, not an install.** The report names what is missing and
  how to install it. Installing packages, creating a virtual environment, and
  checking versions are the executor's job.
- **Takeover is modelled, not scheduled.** Portability only prepares the target
  values after the fence decision. The forced takeover itself is the generation
  bump in [`fence`](#fence-and-resume-t-tel-05), exercised end to end by the
  [failure matrix](#failure-matrix-t-tel-08); no background job or clock expires
  a remote lease here.

## Vault transfer (T-TEL-07)

`vault_transfer` moves the project vault as ciphertext and requires exactly one
unlock on the target (TEL-07, SEC-11, TEL-05). The done criterion is
`vault_transfer::tests::a_second_unlock_is_refused_even_with_the_right_passphrase`:
**the target prompts once and cannot decrypt silently**.

### Envelope and KDF

```text
VaultEnvelope {
    schema_version: u32        1 in this build
    ciphertext: Vec<u8>        AES-256-GCM ciphertext including its 16-byte tag
    kdf: KdfParams {
        salt: Vec<u8>          random 16-byte Argon2id salt
        m_cost: u32            memory cost in KiB
        t_cost: u32            time cost
        p_cost: u32            parallelism
    }
    nonce: Vec<u8>             random 12-byte AES-GCM nonce
    aad: Vec<u8>               VAULT_AAD_DOMAIN || 32-byte passphrase key check
    created_ms: i64            caller clock
}
```

`seal_vault(bytes, passphrase, now_ms)` is the ordinary entry point;
`seal_vault_with_kdf` takes an explicit `KdfOptions` and is what tests use. A
fresh salt and nonce are drawn from OS entropy for every call, so two seals of
the same vault differ. The default Argon2id cost is 19 MiB, two passes, one
lane; `KdfOptions::default()` carries the same values. The plaintext is capped
at 64 MiB.

The Argon2id output is 64 bytes and is split in two:

- the first 32 bytes are the AES-256-GCM key;
- the second 32 bytes are a passphrase key check, stored after the domain
  separator in `aad`.

The whole `aad` value is also the AES-GCM associated data, so the KDF
parameters, the nonce, and the ciphertext are bound together. On unlock the
derived check is compared with the stored check in constant time. A mismatch
means the passphrase is wrong (or the check itself was edited) and returns
`zero.pol.ask`; a correct check with a damaged ciphertext or AAD body fails the
AES-GCM tag and returns `zero.tru.tamper`. The check is what lets "prompt for
the passphrase" and "treat this as tamper" be different outcomes instead of one
ambiguous AEAD failure.

`VaultEnvelope::envelope_id()` is the lower-case hex blake3 of the schema,
clock, KDF parameters, nonce, AAD, and ciphertext. It is the identity the
one-unlock rule and an approval bind to. A new seal necessarily has a new salt
and nonce, so a new envelope id, which is the only way to reset the rule.

The envelope has no `plaintext` field, no `key` field, and no accessor that
decrypts. Its `Debug` prints the id, lengths, KDF costs, and clock only;
`KdfParams::Debug` prints the salt length, not the salt. The serde shape is the
same six fields above.

### One unlock per transfer

`UnlockState` is the target-side value the caller keeps for a transfer. It
records consumed envelope ids and registered approvals, never a plaintext, a
passphrase, or a key. `UnlockState::unlock` and the free `unlock_vault` run the
same checks, in order:

1. the envelope shape validates;
2. the envelope id is not already consumed — a second unlock is
   `zero.pol.denied` **even with the correct passphrase**;
3. the request resolves to a key: a passphrase is derived and checked, or an
   approval is looked up, bound to this envelope, and unexpired;
4. a missing, empty, or wrong passphrase is `zero.pol.ask`; no plaintext is
   returned;
5. AES-256-GCM authenticates the ciphertext and associated data
   (`zero.tru.tamper` on failure);
6. the envelope id is marked consumed and `UnlockedVault` is returned.

`UnlockedVault` owns a `Zeroizing<Vec<u8>>`, exposes `bytes()`, `len()`, and
`into_bytes()`, and its `Debug` prints the id and length only. A failed attempt
does not consume the envelope: the user can retry with the right passphrase,
but the first success locks it for the rest of the transfer.

| Situation | Result | Plaintext |
|---|---|---|
| first correct passphrase | success | returned once |
| second unlock of the same envelope, correct passphrase | `zero.pol.denied` | none |
| a newly sealed envelope in the same state | success | returned once |
| empty, missing, or wrong passphrase | `zero.pol.ask` | none |
| tampered ciphertext | `zero.tru.tamper` | none |
| unknown schema | `zero.fnd.schema_version` | none |
| malformed salt, nonce, or KDF parameters | `zero.fnd.invalid_input` | none |
| ciphertext above the vault cap | `zero.fnd.limit_exceeded` | none |

### Approved transfer

`issue_approval(envelope, passphrase, approval_id, now_ms, ttl_ms)` is the
source-side action. It re-derives the key, so a wrong passphrase is
`zero.pol.ask` and produces no approval. The returned `TransferApproval` holds
the derived key in a `Zeroizing` buffer, has no `Clone` or serde implementation,
and redacts the key in `Debug`. It is bound to one envelope id and expires on
the caller clock; the TTL is positive and at most 24 hours.

The target registers it with `UnlockState::register_approval` and unlocks with
`UnlockRequest::ApprovedTransfer { approval_id }`. The unlock refuses:

- an unregistered label (`zero.pol.ask` — the user must be prompted);
- an approval bound to another envelope (`zero.pol.denied`);
- an approval at or past its expiry (`zero.pol.approval_expired`).

A successful approved unlock consumes the envelope and removes the approval, so
neither can be replayed. An approval is a bearer capability for exactly one
envelope: it must travel only through the authenticated channel, and the caller
must not log or persist it.

`UnlockRequest::Passphrase` owns its string, which is moved into the unlock and
wrapped in `Zeroizing` before Argon2id runs. Copies made by the caller before
the request, or by the OS (argv, environment, swap), are outside this module's
reach; zeroization here is best-effort.

### Integration with the transfer

```text
wrap_for_transfer(envelope, recipient) -> SealedVault
unwrap_envelope(sealed, recipient_secret) -> VaultEnvelope
receive(state, sealed, recipient_secret, unlock, now_ms) -> UnlockedVault
vault_transfer_report(sealed, unlocked) -> VaultTransferReport
```

`wrap_for_transfer` serializes the envelope into one bundle file named
`vault.envelope.json`, builds a normal bundle, and calls the existing
`seal_bundle`. The relay therefore forwards a `SealedBundle` exactly as it does
for workspace content: it sees chunk hashes, sizes, ids, the recipient id, and
ciphertext, never the vault bytes and never the passphrase. `unwrap_envelope`
verifies the sealed bundle, requires exactly the one envelope file, validates
the decoded envelope, and checks that its derived id equals the id the transfer
was wrapped with; a mismatch or a corrupted chunk is `zero.tru.tamper`.
`receive` is `unwrap_envelope` followed by the same single `unlock_vault`, so
the passphrase never crosses the transfer.

`VaultTransferReport { envelope_id, sealed_bytes, unlocked }` carries no
secret: `sealed_bytes` is the JSON size of the sealed envelope on the wire.

At the integration layer the caller reads the `.zero/vault` bytes that
`zero-secrets` owns and hands them to `seal_vault`; this crate never parses the
vault index, a tag, a scope, or a value. The unlocked result is the same vault
file the target's `Vault` can open.

### Test evidence

`cargo test -p zero-mesh -j 1` runs **230 tests on Windows and 233 on Unix**,
including **11 in `vault_transfer::tests`**. The direct evidence:

| Test | Proves |
|---|---|
| `seal_and_unlock_round_trip_returns_the_bytes` | Argon2id + AES-256-GCM seal and one passphrase unlock return the exact vault bytes; the envelope has a random salt and nonce and a stable content-derived id. |
| `a_second_unlock_is_refused_even_with_the_right_passphrase` | **Done criterion:** the first unlock succeeds, the second is `zero.pol.denied` with the same passphrase, and the approval path obeys the same rule. |
| `a_wrong_passphrase_is_a_prompt_and_returns_no_plaintext` | A wrong passphrase is `zero.pol.ask`, does not consume the envelope, and a later correct attempt still works. |
| `unlock_requests_are_validated_and_the_passphrase_is_moved_in` | An empty seal is invalid, an empty unlock asks, and an owned request passphrase unlocks and is dropped with the request. |
| `a_tampered_ciphertext_is_refused_as_tamper` | A flipped ciphertext byte is `zero.tru.tamper` and does not consume the envelope. |
| `approved_transfer_requires_a_matching_binding` | An approval for another envelope is `zero.pol.denied`, an unknown label asks, and a matching approval unlocks exactly once. |
| `an_expired_approval_is_refused` | The expiry boundary is inclusive: one millisecond before works, at expiry it is `zero.pol.approval_expired`. |
| `a_new_envelope_allows_a_new_single_unlock` | A fresh salt and nonce give a new envelope id and a new single unlock in the same state. |
| `ciphertext_travels_through_transfer_sealing_and_stays_opaque` | The sealed transfer JSON has no plaintext or passphrase, the recipient recovers the envelope, `receive` unlocks it, the report has no secret, and a corrupted sealed chunk fails. |
| `debug_and_errors_never_expose_plaintext_or_keys` | `Debug` for the envelope, unlocked vault, request, and approval, the serde JSON, and error messages never contain the passphrase, the derived key, or vault plaintext. |
| `envelope_shape_bounds_are_typed` | Unknown schema, short nonce, short salt, malformed AAD, and a truncated ciphertext are typed before any key work. |

## Failure matrix (T-TEL-08)

TEL-08, TEL-10, TEL-13, and TEL-14 are only satisfied if the failure paths hold.
`trip_matrix` runs four fixtures against the real `bundle`, `restore`, `fence`,
and `portability` modules. The only injected value is availability: the
`SourceProbe` seam reports the source reachable or unreachable, and no socket is
opened.

`run_matrix(&TripRequest, &probe)` returns a `TripMatrixReport` with one
`TripOutcome` per executed fixture; `run_trip` returns the same run as a `Trip`
with `FixtureRun` records. `assert_all_four(&report)` returns a typed
`TripMatrixError` that names the missing, duplicate, or failed fixture. A
`Direction::Forward` request deliberately omits the return leg, so a one-way
report can never pass the four-fixture gate; a `Direction::Return` request runs
all four. Each fixture writes only under
`<root>/trip-matrix/<safe-trip-id>/<fixture>/`, and the caller's trip id is
sanitised before it becomes a directory name.

| Fixture | Expected behaviour | Evidence |
|---|---|---|
| **Interrupted** | Two chunks are written, the writer is dropped, the checkpoint is reloaded, and only the rest is written. The durable chunk files are re-read and verified, then restored. The restored tree is byte-identical to the source. A second restore writes nothing (no duplicate effects). | `resume_already_present=2`, `byte_identical=true`, `skipped_identical` equals the plan's entry count. |
| **Unreachable source** | With the probe unreachable, the target refuses the pull with `zero.fnd.unavailable` and a reason naming the source. It writes nothing into the target and the already-restored local snapshot still verifies with an unchanged manifest hash and component bytes. A reachable probe fails the fixture honestly instead of reporting a false pass; this slice refuses rather than waits. | `refused_code=zero.fnd.unavailable`, `target_writes=0`, `local_snapshot_unchanged=true`. |
| **Forced takeover** | An expired source lease is handed to the target with `handoff`, which advances the generation. The new holder writes and restores through `assert_can_write`. The stale holder's write and gated restore are `zero.ses.lease_held`, its release is `zero.pol.denied`, and its resume cursor forces a snapshot instead of replaying effects. A refused stale restore creates no directory. | `old_generation=1`, `new_generation=2`, `stale_write_code=zero.ses.lease_held`, `stale_restore_written=false`. |
| **Return trip** | A→B remaps `C:\work\proj` to `/home/alice/proj` and re-signs with B's device key; B's key verifies and A's does not. B→A remaps back and re-signs with A's key; the components, snapshot id, and restored workspace are byte-identical to the original, and B's key no longer verifies. The first leg's lease generation is `zero.ses.lease_held` on the return leg and its cursor forces a snapshot. | `state_equal=true`, `identity_resigned=true`, `first_leg_generation=2`, `second_leg_generation=3`, `stale_generation_code=zero.ses.lease_held`. |

Harness limits: the probe models availability only, not latency or a partial
network stream; the refusal branch is the implemented behaviour (a waiting
target is not modelled). The lease store is an in-memory model, not the durable
store, and the workspace restore is local. The return-trip check uses synthetic
Windows/POSIX roots so its bytes are host-independent. The caller owns the
scratch root; the harness writes under it and does not delete it.

## UI summary

`inspect(snapshot)` returns:

```text
SnapshotSummary {
    id: String
    created_ms: i64
    project_id: String
    components: BTreeMap<Component, usize>   declared size per component
    total_bytes: usize
}
```

It reads the manifest and does not verify or hash anything. The full manifest
is available as `snapshot.manifest`; the UI can call `verify_snapshot` before
trusting it. A bundle's UI numbers are `BundleStats` from `Bundle::stats()`:
file count, chunk references, unique chunks, logical and stored bytes, dedupe
savings, and exclusions.

## TODO-07 persistence

TODO-07 requires a todo to survive compaction, teleport, and auto-resume. This
slice carries the session (and therefore the entries), goals, schedules,
ledger, and artifacts as components, so a later teleport step can restore them
on the target. The todo store's own format is `zero-tasks`' concern; it travels
inside `Session`/`Goals` or the bundle at the integration layer. This module
does not add a second persistence path for todos.

## Test evidence

Commands, run from the repository root on 2026-11-26:

```text
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-mesh trip -j 1
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-mesh --all-targets -j 1 -- -D warnings
```

The focused test command matched 16 tests (the 7 `trip_matrix` tests plus 9
unrelated tests whose names contain `trip`) and all passed. The suite is
**230 tests on Windows and 233 on Unix**: 13 in
`identity::tests`, 15 in `state::tests`, 17 in `discovery::tests`, 12 in
`presence::tests`, 14 in `relay::tests`, 16 in `partition::tests`, 14 in
`join_ux::tests`, 18 in `traversal::tests`, 17 in `snapshot::tests`, 16 in
`bundle::tests`, 17 in `transfer::tests`, **12 in `restore::tests` on
Windows / 15 on Unix** (three tests are `#[cfg(unix)]`), 12 in `fence::tests`,
19 in `portability::tests`, **11 in `vault_transfer::tests`**, and **7 in
`trip_matrix::tests`**. There are no integration tests, no sockets, and no
timers. `cargo clippy -p zero-mesh --all-targets -- -D warnings` is clean.

| Test | Proves |
|---|---|
| `a_snapshot_round_trips_on_the_same_device` | **Done criterion:** all seven components create, verify, restore, and read back byte-identically; `snapshot.json` round-trips; the manifest hash and paths are returned. |
| `the_manifest_is_written_after_every_component` | A probe sees components in `Component::ALL` order and no `snapshot.json` exists until the pass ends. |
| `a_tampered_blob_or_signature_is_refused_and_writes_nothing` | A changed blob is `zero.tru.tamper`, a changed signature and a foreign device key are `zero.pol.denied`, and `.zero` is not created. |
| `a_missing_required_component_is_refused` | `create` refuses a missing kernel; a partial snapshot fails verification and restore writes nothing. |
| `secret_like_components_are_refused_and_reported_as_exclusions` | Vault, credential, `.env`, and private-key labels are secret-like and refused; `.zero/key` is not; exclusions are recorded sorted and unique. |
| `per_component_and_total_size_caps_are_enforced` | One blob above 16 MiB and five 16 MiB blobs above the 64 MiB total are `zero.fnd.limit_exceeded`. |
| `a_duplicate_component_blob_is_refused` | Two blobs for one component are `zero.fnd.invalid_input`. |
| `the_snapshot_id_is_deterministic_and_content_bound` | Same inputs and reordered blobs give the same id and signature; a later clock or another project changes the id. |
| `inspect_summarises_the_snapshot_without_values` | The summary carries id, clock, project, per-component sizes, and the total, and its JSON contains no blob values. |
| `a_snapshot_survives_serde_and_still_restores` | A JSON round-trip is equal to the original, verifies, and restores. |
| `debug_redacts_blobs_and_the_signature` | `Snapshot`'s `Debug` has the id and project but no blob, signature, or key bytes. |
| `optional_components_may_be_absent_and_are_recorded_when_present` | Only the required three verify and restore; `missing_optional` lists artifacts, goals, schedules, and ledger; the full snapshot has none missing. |
| `restore_is_idempotent_and_never_overwrites_a_different_snapshot` | A repeat restore is `already_present`; a corrupted existing component is refused without repair; a different manifest in the same path is `zero.pol.denied` and the files stay. |
| `unsafe_ids_and_labels_are_refused_before_any_write` | A traversal id fails verification, no `.zero` or escaped path appears, and path labels are not components. |
| `exclusions_are_validated_and_capped` | Too many, too long, and contradicted exclusions are typed; duplicates are deduplicated. |
| `project_ids_are_validated` | Empty, padded, path-separated, `.`, `..`, and over-long ids are refused. |
| `a_crafted_manifest_with_a_wrong_schema_is_refused` | An unknown schema version is `zero.fnd.schema_version`. |

Bundle tests:

| Test | Proves |
|---|---|
| `files_split_into_content_addressed_chunks_and_reassemble` | A 2.5 KB file at a 1 KB chunk size yields three `ChunkRef`s, every stored chunk hashes to its ref, the chunks reassemble byte-identically, and the manifest totals match. |
| `identical_chunks_are_stored_once_and_savings_are_reported` | Two identical files share two unique chunks out of four references; `BundleStats` reports 4096 logical bytes, 2048 stored, and 2048 saved. |
| `an_empty_file_round_trips` | A zero-byte file has no chunks, writes no chunk files, verifies, and materializes as a zero-byte file. |
| `a_multi_chunk_file_materializes_byte_identically` | A 5 KB file at 512-byte chunks becomes ten chunks, verifies, and materializes byte-identically. |
| `an_interrupted_bundle_resumes` | **Done criterion:** after two chunks are written and the writer is dropped, `BundleWriter::resume` loads the checkpoint, writes only the rest, reports `already_present = 2`, verifies, and materializes byte-identically. |
| `a_corrupted_or_missing_chunk_is_rewritten_on_resume` | A corrupted chunk and a deleted chunk are both detected by hash, removed from `written`, rewritten, and the repaired bundle verifies. |
| `a_missing_chunk_is_a_typed_error` | `verify` and `read_chunk` return `zero.tru.tamper` for a missing chunk, a malformed hash is `zero.fnd.invalid_input`, a transfer map without a needed chunk is typed, and a directory without a manifest is not a bundle. |
| `the_manifest_hash_is_content_bound_and_tamper_is_refused` | Equal inputs give equal ids and hashes; a mutated sum, a mutated chunk hash, a tampered chunk file, and a tampered `bundle.json` are all refused with typed errors. |
| `unsafe_paths_and_symlink_targets_are_rejected` | Absolute paths, drive letters, `..`, empty components, backslashes, trailing dots/spaces, and unsafe symlink targets are `zero.fnd.invalid_input`; no file is written. |
| `exclusions_are_reported_and_never_silently_dropped` | Exclusions are sorted, deduplicated, kept in the manifest and `verify` report, change the bundle id, and a supplied file that is also excluded is refused; a supplied secret path is `zero.pol.denied`. |
| `materialize_never_overwrites_different_content` | A repeat materialize is `already_present`; different bytes, a directory in the way, and a destination symlink are refused without changing the destination. |
| `symlinks_are_refused_unless_recorded_and_allowed` | A recorded symlink is refused by default with nothing written; on Unix `allow_symlinks` creates the link; Windows refuses. |
| `modes_are_recorded_and_applied_on_unix` | A recorded `0o640` mode survives the manifest, serde, and materialize (checked on Unix). |
| `the_manifest_and_checkpoint_survive_serde` | The manifest and a checkpoint round-trip through JSON with equal canonical bytes and hashes. |
| `a_bundle_directory_refuses_a_different_manifest` | A second manifest cannot be created over an existing bundle directory; reopening the same manifest is idempotent. |
| `chunk_configuration_is_validated` | A zero chunk size or zero ceiling is `zero.fnd.invalid_input`; a chunk above 64 MiB is `zero.fnd.limit_exceeded`. |

Transfer tests:

| Test | Proves |
|---|---|
| `seal_and_open_round_trip_is_byte_identical` | A multi-file bundle seals and opens with identical manifest and chunk bytes; the verified evidence reports every chunk and the canonical manifest hash; the wire JSON carries no file content. |
| `an_empty_bundle_round_trips` | A bundle with no files and no chunks seals with an encrypted manifest and opens correctly. |
| `a_wrong_recipient_key_is_refused` | A different X25519 secret is `zero.pol.denied` and yields no bundle. |
| `tampered_ciphertext_or_tag_is_refused` | A flipped tag, a flipped ciphertext body, a flipped manifest ciphertext, and a changed nonce are all `zero.tru.tamper`. |
| `a_truncated_or_missing_chunk_is_refused` | A removed chunk, a one-byte-truncated ciphertext, and a duplicate chunk are typed failures. |
| `a_manifest_hash_or_bundle_id_mismatch_is_refused` | A changed cleartext manifest hash or bundle id fails authentication as `zero.tru.tamper`. |
| `nonces_are_unique_per_chunk_and_derived_deterministically` | Every chunk nonce differs, the manifest nonce differs from every chunk nonce, the same seed reproduces the envelope exactly, and a different bundle changes the nonce. |
| `aad_binding_refuses_a_reordered_chunk` | Swapping two equal-length ciphertexts (and swapping the chunk order) fails because index and hash are bound into the AAD and nonce. |
| `a_wrong_plaintext_hash_is_refused` | A changed chunk hash is `zero.tru.tamper`. |
| `a_corrupted_chunk_fails_verification` | **Done criterion:** a corrupted chunk is `zero.tru.tamper` and the failed open materializes nothing. |
| `debug_and_errors_never_expose_key_material` | `Debug` for the envelope and both secret keys is redacted; the derived key, seeds, and plaintext never appear in `Debug`, serde JSON, or an error message. |
| `sealed_envelopes_survive_serde_without_plaintext` | A JSON round-trip is equal, opens, and carries no plaintext or key field. |
| `recipient_keys_round_trip_through_base64_and_ids` | Base64 parsing, recipient-id stability, and typed refusals for bad or short keys. |
| `transfer_report_counts_chunks_and_bytes_without_keys` | Counts and bytes match the bundle; a mismatched envelope/report pair is refused; the report contains no key. |
| `schema_limits_and_nonce_reuse_are_typed` | Unknown schema, empty or oversized chunks, nonce reuse, and unordered chunks are typed. |
| `retention_keeps_source_on_failure_and_permits_cleanup_only_after_verify` | A failure keeps both paths with `can_cleanup = false`; a verified success permits cleanup; opt-in cleanup removes only the source. |
| `cleanup_refuses_a_nested_or_identical_target` | Cleanup refuses a target inside the source and a source equal to the target, leaving both on disk. |

Restore tests:

| Test | Proves |
|---|---|
| `a_clean_restore_writes_entries_and_components` | Files, a nested directory, six components, and the child registry restore byte-identically under `.zero/teleport/<bundle_id>/components/`; no staging directory is created. |
| `a_conflicting_file_is_staged_and_not_overwritten` | **Done criterion:** an existing file keeps its bytes, the incoming file is staged, the existing and incoming hashes are reported, and the staged path is exact. |
| `identical_files_are_skipped_and_not_staged` | An identical destination is left alone and counted; nothing is staged. |
| `a_file_directory_type_conflict_is_staged_and_never_replaced` | A directory in the way of a file is preserved, the file is staged, and `adopt` refuses to remove the directory. |
| `overwrite_existing_replaces_per_path_and_records_it` | The explicit opt-in replaces the file, records the conflict, and leaves a staged copy. |
| `modes_are_applied_on_unix` | A recorded `0o640` is applied to the restored file (Unix-only). |
| `a_recorded_symlink_inside_the_root_is_created` | A recorded relative symlink is created and reads back as the target (Unix-only). |
| `a_symlink_target_outside_the_root_is_refused_before_any_write` | `../escape` is `zero.fnd.invalid_input` and no target path is written. |
| `unsafe_entry_paths_are_refused_before_any_write` | `..`, absolute paths, backslashes, and drive letters are refused with no `.zero` created. |
| `preflight_prevents_a_partial_restore_on_an_invalid_plan` | A duplicate path and a file used as another entry's parent both invalidate the plan before the valid first entry is written. |
| `adopt_moves_a_staged_file_into_place` | Adoption moves the reviewed staged file into place, removes the staged copy, and clears the conflict. |
| `a_second_restore_stages_nothing_new` | A repeat restore reports every entry and component as identical and creates no staging state. |
| `the_component_set_and_modes_are_validated` | A workspace-manifest component and a mode above `0o7777` are refused before any write. |
| `an_unrecorded_symlink_is_staged_and_never_followed` | A destination symlink is preserved, the incoming file is staged, and the link's outside target is untouched (Unix-only). |
| `directory_entries_are_created_inside_the_root` | An explicit directory entry and a nested file restore under the root. |

Fence tests:

| Test | Proves |
|---|---|
| `a_stale_holder_cannot_write_after_handoff` | **Done criterion:** handoff moves the holder and increments the generation; the source's old generation is refused by `fence` and `assert_can_write`, while the target's generation writes. |
| `a_future_cursor_and_a_future_generation_write_are_refused` | A cursor or write generation ahead of the stored lease is `zero.pol.denied` / `zero.ses.lease_held`. |
| `an_expired_lease_is_refused` | Expiry is inclusive; an expired lease cannot write or renew, and one millisecond earlier still works. |
| `renew_preserves_the_holder_and_generation` | Renewal extends only the live lease, preserves holder/generation/acquisition, and a renewed superseded copy is still fenced off. |
| `a_stale_holder_cannot_release_the_current_lease` | Release is holder-only; the old holder is `zero.pol.denied`, and the current holder's release returns the retained generation. |
| `concurrent_handoffs_from_one_generation_have_one_winner` | Two compare-and-sets that observed one generation produce one winner and one `zero.fs.conflict`; the next handoff starts from the winner. |
| `an_older_cursor_forces_a_snapshot` | A cursor from an older (or zero) generation returns `snapshot = true` and no event is replayed. |
| `a_current_generation_cursor_resumes_events_after_it` | A current-generation cursor returns `sequence + 1`, including the caught-up case. |
| `resume_never_moves_the_sequence_backwards` | Every applied sequence yields a strictly later `from_seq`; a cursor ahead of the journal is `zero.fnd.invalid_input`. |
| `effects_are_not_replayed_across_a_fence` | The fenced cursor snapshots instead of replaying, and the next-generation cursor resumes only later events. |
| `leases_cursors_and_plans_survive_serde` | A lease, cursor, and plan round-trip through JSON and still gate writes and resume. |
| `invalid_leases_and_bounds_are_typed` | Empty/oversized holders, empty resources, zero/oversized TTLs, overflowing expiry, generation zero, and generation exhaustion are typed. |

Portability tests:

| Test | Proves |
|---|---|
| `windows_drive_and_unc_paths_remap_to_posix` | **Done criterion (Windows to Linux):** drive and UNC roots, backslash and mixed separators, a case-only source difference, spaces, and non-ASCII all remap to the POSIX target. |
| `posix_paths_remap_to_windows_drive_and_unc` | **Done criterion (Linux to Windows):** a POSIX root remaps to a drive root and to a UNC root with `\` separators, including spaces and non-ASCII. |
| `outside_root_and_traversal_are_refused` | A prefix that is not a component boundary, another drive, a relative path, a POSIX path under a Windows map, and every `..` are `zero.fnd.invalid_input`. |
| `case_sensitive_sources_refuse_a_case_only_difference` | A case-only prefix difference is refused when `case_insensitive_source` is false, and the exact case still remaps. |
| `maps_and_paths_are_bounded` | A path above 8 KiB is `zero.fnd.limit_exceeded`; empty, relative, `..`, drive-relative, and share-less UNC roots are invalid. |
| `a_working_directory_notice_names_both_roots` | The TEL-12 notice names the old and new roots and tells the model to use the new path. |
| `remap_text_rewrites_only_path_tokens` | Only the three path tokens under the root change; prose, `C++`, `/etc/hosts`, an unrelated POSIX path, and a trailing sentence period are untouched; the substituted count is exact. |
| `remap_text_handles_json_escaped_paths_and_quoted_spaces` | A JSON-escaped Windows path remaps inside its string, and a quoted path with spaces is rewritten as one token. |
| `remap_text_reports_skipped_tokens_and_is_bounded` | A `..` token under the root stays byte-identical and is counted as skipped; the text, map, and token caps are `zero.fnd.limit_exceeded`. |
| `remap_text_is_deterministic_and_the_first_map_wins` | Two overlapping maps give the first map the token under both roots; a repeat produces equal text and reports. |
| `remap_snapshot_re_signs_and_leaves_artifacts_alone` | **Snapshot re-sign:** session, kernel, and manifest are remapped; artifacts are byte-identical; the target key verifies; the source key is `zero.pol.denied`; the snapshot id changes. |
| `remap_snapshot_is_deterministic_and_passes_through_non_utf8` | Equal inputs and target key give an equal snapshot; a non-UTF-8 remappable blob is copied unchanged and the re-signed snapshot verifies. |
| `remap_snapshot_refuses_an_inconsistent_snapshot` | A changed blob that no longer matches its manifest is `zero.tru.tamper` and is never re-signed. |
| `kernel_plans_are_target_appropriate_and_deterministic` | Windows→Linux gives `python3`, Linux→Windows gives `python`, same-OS sets `offline_cache`, the package list is the documented set, and no plan python contains a path separator. |
| `kernel_plans_refuse_foreign_or_ambiguous_python` | A Windows path for Unix, a POSIX path for Windows, Python 2, an ambiguous `python`, an empty value, and an unknown OS are typed; a plan that carries a path fails validation. |
| `preflight_reports_missing_tools_with_per_tool_guidance` | Missing tools are sorted and each has install guidance; available tools have none; an unknown tool still gets a PATH line; duplicates are deduplicated. |
| `a_no_git_directory_passes_without_git` | **Done criterion (no-git directory):** `required = [python3, pip]` passes with `no_git_dir = true` because git is not required. |
| `a_no_git_directory_refuses_a_git_requirement` | A plan that requires `git` is `zero.pol.denied` in a no-git directory even when the probe reports git available, and is accepted when `no_git_dir = false`. |
| `can_run_refuses_missing_tools_and_unchecked_python` | A missing interpreter is refused with its install line; a preflight that never checked `plan.python` is `zero.fnd.invalid_input`. |

Trip-matrix tests:

| Test | Proves |
|---|---|
| `the_interrupted_fixture_resumes_byte_identically` | **Interrupted:** the checkpoint resumes with `already_present = 2`, the durable bundle verifies, the restored files are byte-identical, and the resumed chunk count is complete. |
| `the_unreachable_fixture_refuses_and_keeps_the_local_snapshot` | **Unreachable source:** the pull is `zero.fnd.unavailable`, writes nothing, and the local snapshot's manifest hash and component bytes are unchanged. |
| `the_forced_takeover_fixture_blocks_the_stale_holder` | **Forced takeover:** the new holder writes and restores at the new generation; the stale holder's write is `zero.ses.lease_held`, its restore creates nothing, and its cursor forces a snapshot. |
| `the_return_trip_fixture_restores_state_and_refuses_the_stale_generation` | **Return trip:** A→B→A restores components and workspace bytes, A's key verifies at the end, B's does not, and the first leg's generation is `zero.ses.lease_held`. |
| `the_failure_matrix_reports_ok_when_all_four_pass` | Four outcomes, all passing, `report.ok`, and `assert_all_four` returns `Ok`. |
| `a_skipped_fixture_flips_ok_and_is_named` | **Negative (missing):** a forward-only report has three outcomes, `ok = false`, and `assert_all_four` names `Missing(ReturnTrip)`. |
| `a_forced_failure_flips_ok_and_is_named` | **Negative (failed):** marking one outcome failed flips `ok` and `assert_all_four` names `Failed(ForcedTakeover)` with its notes. |

## Limitations

- **No network transport.** The transfer is an in-memory `SealedBundle`; this
  slice does not open a socket, resumably stream over one, or negotiate a
  transport session. The bundle's resume is local chunk-level resume.
- **Bundle is plaintext on disk.** `bundle::build` and `BundleWriter` write
  chunks into a local directory with no encryption or directory
  authentication. The encrypted form is `transfer::SealedBundle`; a caller that
  sends a bundle over a network must seal it and forward the envelope, not the
  directory.
- **Resume state is local.** `checkpoint.json` lives beside the chunks. Moving a
  partially written bundle to another host is not a protocol: the whole
  directory (manifest, checkpoint, chunks) must travel together, and
  `write_pending` still requires the caller to supply the chunk bytes for
  anything the checkpoint does not list.
- **Checkpoint rewrite is quadratic.** The spec requires an atomic checkpoint
  after each chunk, so a large transfer rewrites a growing JSON file once per
  chunk. For a million chunks the checkpoint itself is tens of megabytes. A
  future slice should replace it with an append-only journal plus a summary.
- **Fixed-size chunks.** Chunks are split at `chunk_bytes` boundaries, so an
  insertion near the start of a file re-chunks the rest of that file. Content-
  defined chunking is an optimisation, not part of this slice.
- **No chunk garbage collection.** A stale or orphaned chunk file (from a
  different attempt in the same directory) is ignored by `verify` but never
  deleted. `create` also leaves unrelated files alone.
- **`bundle::materialize` is not atomic.** It verifies before writing and never
  overwrites different content, but files written before a later refusal stay in
  place. It has no staged tree, journal, or rollback. The staged, preflighted
  full-tree path is `restore::restore`; use it when partial writes are not
  acceptable.
- **Restore preflight is not a lock.** `restore` reads every destination before
  writing and `write_atomic` refuses a path that appeared meanwhile, but a
  process with write access can still race a create or an `overwrite_existing`
  replace between the check and the rename. The `fence` module models the durable
  answer, but `restore` does not take a lease yet. Adoption re-checks the
  recorded existing hash, so a changed file is refused rather than clobbered.
- **Overwrite is not reversible.** `RestoreOptions::overwrite_existing` replaces
  a conflicting file's bytes; the old content is not journalled. If a later step
  fails, the path is named in the rollback report and stays replaced. The default
  path stages instead, so no existing bytes are lost.
- **Adopt never removes a directory.** A directory in the way, or a staged
  directory, cannot be adopted; resolve it manually. An adopted file or symlink
  still requires its parent chain to be real directories.
- **Component conflicts are refused, not staged.** A component file under
  `.zero/teleport/<bundle_id>/components/` that differs from the plan is
  `zero.tru.tamper`; there is no second copy for a component, because a bundle id
  names exactly one component set.
- **Restore stores the plan in memory.** `RestorePlan::contents` holds every
  workspace file and the components are in memory too before apply. A workspace
  larger than RAM cannot be restored in one call; chunk streaming into the target
  is future work.
- **Empty directories are not in the bundle.** `BundleManifest` records files and
  symlinks only, so `RestorePlan::from_bundle` creates the directories those
  paths need and no others. An explicit `RestoreKind::Dir` entry restores an
  empty directory, but a bundle cannot express one yet.
- **Components are caller-supplied, not signed here.** `from_bundle` verifies the
  bundle; the transcript, kernel, and other blobs are opaque values the caller
  passed in. Verify the signed snapshot (`verify_snapshot`) or the live session
  before handing them to `restore`; this module does not re-derive them from a
  `Snapshot`.
- **`.zero` is not a workspace entry.** A plan path under `.zero` is refused so a
  restore cannot clobber teleport, staging, audit, or project state. Project
  identity and mesh binding travel outside this path on their own (PRJ-06 and
  T-TEL-05); bundle a project identity only if the caller deliberately renames it
  into a workspace path.
- **Symlinks are Unix-only.** A recorded symlink is refused on Windows even with
  `allow_symlinks`, because Rust cannot choose file versus directory links
  portably here. Link targets must be safe relative paths, so a bundle cannot
  link outside its own tree. `restore` also refuses a Windows plan with a
  recorded symlink before writing anything.
- **No mode fidelity on Windows.** Modes are recorded but not applied; NTFS
  permissions are out of scope.
- **No case folding.** Two paths that differ only by case are distinct in the
  manifest, but collide on a case-insensitive target filesystem; materialize and
  restore would then treat the second one as a conflict rather than merge them.
- **Build is in memory.** `bundle::build` takes every file's bytes and returns
  the unique chunk bytes, so a workspace larger than RAM cannot be built in one
  call. A streaming builder is future work; the writer and reader themselves
  process one chunk at a time.
- **The fence is a model, not a live lock.** `fence` carries the lease,
  generation, handoff/CAS, renewal, release, and resume rules, and
  `assert_can_write` refuses a stale or expired generation. `restore` and
  `materialize` do not call it yet, and no daemon serialises handoffs: the
  compare-and-set is one winner only when the caller passes the store's current
  lease and commits the winner, as the concurrent-handoff test models.
- **Lease expiry uses a caller clock.** `now_ms` is a local reading, so an
  expired lease on one host and a live lease on another are ordered by the
  generation, not by comparing `expires_ms` across devices. A host whose clock
  jumps backwards can hold a lease past the intended wall-clock TTL; the next
  handoff still fences it.
- **Path remapping is a value transform, not a live session edit.** Workspace
  entry paths are relative and are recreated under the target root, so the tree
  moves without rewriting. `portability::remap_snapshot` rewrites absolute paths
  in the session, kernel, and workspace-manifest components and re-signs the
  result, and `working_directory_notice` gives the TEL-12 context line; inserting
  that line into a live transcript and replaying it is the session layer's job.
  Goals, schedules, ledger, and binary artifacts are passed through unchanged,
  so an absolute path hidden in those blobs is not rewritten. Text tokenisation
  is heuristic (see the portability honest limits), and there is no
  case-collision merge and no line-ending conversion.
- **Vault transfer is a value model, not the host prompt.** `unlock_vault`
  enforces the one-unlock rule over an in-memory `UnlockState` and returns
  `zero.pol.ask` when a secret is missing. Drawing the masked modal, queueing
  the request in headless mode, and persisting the request belong to the host
  UI and the secret-prompt layer (T-SEC-05/T-SEC-10); this module does not draw
  or persist a prompt.
- **One-unlock state is in memory.** A process restart with a fresh
  `UnlockState` can unlock the same envelope again. The stream that receives a
  vault must keep the state durable across restarts (the TEL-08 failure matrix
  and the session store are the owners); the envelope id is the key to persist.
- **Passphrase zeroization is best-effort.** The request's string is moved into
  a `Zeroizing` buffer before Argon2id, and the derived key, its key check, and
  the decrypted vault are zeroized on drop. Copies made by the caller before the
  request, by the OS (argv, environment, swap), or inside `argon2`'s internal
  buffers are outside this module's reach; there is no `mlock` or
  `VirtualLock`.
- **The key check cannot tell an edited check from a wrong passphrase.** Both
  yield `zero.pol.ask`. A modified check is therefore a prompt, not a tamper
  report; the ciphertext itself still authenticates with AES-GCM, and an edited
  AAD body or nonce is `zero.tru.tamper` once the stored check still matches.
  The check is public, so it does not weaken or strengthen offline guessing:
  the vault is only as strong as the passphrase against Argon2id.
- **An approval is a bearer capability.** `TransferApproval` holds the derived
  key in memory and binds it to one envelope id and expiry, but this slice does
  not sign it with the device identity or record the issuance in the audit log.
  Anyone who obtains the value can unlock that envelope before it expires, so it
  must travel only inside the authenticated transfer (or the host's own
  channel). Issuance authority is T-MESH-07/T-TEL-06 work.
- **No passphrase policy, rotation, or recovery.** An empty passphrase is
  refused at seal time, and there is no minimum length, no re-keying, and no
  recovery path. A forgotten passphrase loses the vault; a rotated passphrase
  requires a new envelope, which is also a new unlock.
- **Whole-vault in memory.** Seal and unlock both materialize the full vault
  plaintext and ciphertext, capped at 64 MiB. Streaming a larger vault is future
  work. The sealed transfer also holds every chunk in memory, as the transfer
  section already notes.
- **Vault bytes are opaque to this layer.** `zero-mesh` never parses the vault
  index or its values, so it cannot re-check a tag, a scope, or a binding. The
  caller must hand `seal_vault` the bytes `zero-secrets` wrote and treat the
  unlocked result as the same vault file.
- **No transport.** `wrap_for_transfer` produces a value and opens no socket;
  the relay/transfer path still only forwards the envelope.
- **Label check, not content scan.** Opaque blobs are not scanned for secret
  values, and the bundle's secret rule is also a path check: a secret-like path
  is refused, but a secret inside an allowed file is not detected. Redaction is
  TEL-05's exclusion pass and the session/secret layers.
- **No directory fsync.** Each snapshot component, each bundle chunk, each
  restored file/component, and the checkpoint is `sync_all`'d before its rename,
  and the snapshot staging directory is renamed into place, but the parent
  directory is not fsynced. A power loss can still lose a directory entry on
  some filesystems; the files are never half-written. A crashed restore can
  leave `.partial` files or a staged conflict copy; a later restore ignores them
  and uses a fresh random partial name.
- **TOCTOU on symlinks.** `.zero`, `.zero/teleport`, `.zero/restore-staging`,
  the component directory, and the destination are checked with
  `symlink_metadata` before use, but another process with write access to the
  target root could swap a path between the check and the write. There is no
  advisory lock in this slice; `fence` models the durable answer, but restore
  does not consume it. A missing
  `target_root` is created with `create_dir_all`, so ancestors outside it are not
  individually checked for symlinks; an existing target root is checked.
  Junctions/reparse points are covered only to the extent Rust reports them as
  symlinks.
- **Concurrent restores.** Two restores of the same snapshot use different
  random staging directories and the same destination. One publish wins; the
  loser's directory rename fails (or, on a Unix empty destination race, could
  replace an empty directory). The destination is still only ever the exact
  verified snapshot or a refusal. Serialize restores at the caller until
  restore takes a lease (`fence`).
- **Crash leaves staging debris.** A process killed between staging and publish
  leaves an unpublished `.snap-<id>.tmp-<random>` directory under
  `.zero/teleport`. It contains only fully written component files and was
  never published; a later restore uses a new random name and never reuses or
  trusts it. No garbage collector runs in this slice.
- **Whole-snapshot verification.** `verify` hashes every blob before restore
  writes anything, so a very large snapshot costs a full read. The transfer is
  also whole-envelope: it verifies every chunk before returning a bundle, and
  streaming decryption is future work.
- **Deserialisation allocates first.** A hostile JSON snapshot or sealed
  envelope can declare large byte arrays or base64 fields; the caps are
  enforced after parsing and decoding. The caller should bound the input size
  when reading an untrusted file.
- **Windows path length.** `snap-<64 hex>` plus the project root can approach
  the classic 260-character limit. Use a short target root or long-path support.
- **One signer, no mesh binding.** The snapshot signature is the local device
  key's. The sealed transfer binds content to an X25519 recipient, but it does
  not bind the sender to the mesh owner's Ed25519 identity or to an approved
  target device; that transport authentication is separate work.
- **No clock authority.** `created_ms` is caller-supplied and signed, but
  `verify` does not compare it with a wall clock and `restore` uses `now_ms`
  only as a stamp. A snapshot dated in the future verifies; cross-device clock
  skew is a teleport-preflight concern (TEL-01's target checks), not a local
  restore refusal.
- **Transfer metadata is cleartext.** The relay sees chunk hashes, chunk sizes,
  logical/stored byte totals, the bundle id, the manifest hash, the recipient
  id, and the ephemeral public key. Only the manifest body and the file content
  are confidential. Content-addressed verification needs the hashes in the
  clear; a transport that must hide even the shape needs padding or a different
  protocol.
- **No sender authentication.** Anyone who knows the recipient's public key can
  produce an envelope the recipient can open. The AEAD proves possession of the
  derived key, not the sender's device identity; mesh authentication and
  approval are a separate TEL-06/T-MESH-07 concern.
- **Static recipient key, no forward secrecy.** A recorded envelope can be
  decrypted later with the recipient secret. The sender side is one-use
  ephemeral, but there is no ratchet, rotation, or replay window in this slice.
- **No replay protection.** A valid envelope can be forwarded again. The
  target's lease and generation fence (`TEL-10`, `fence`) and session-level
  idempotency are the answer, not this value.
- **Whole-envelope in memory.** Sealing builds the manifest ciphertext and every
  chunk ciphertext in memory, and the bundle build is already in memory.
  Chunk-by-chunk streaming is future work.
- **Manifest JSON cap is 4× the canonical cap.** JSON framing can be larger than
  the 16 MiB canonical manifest, so the transfer allows up to 64 MiB of manifest
  plaintext and still validates the canonical form after decryption.
- **Cleanup is `remove_dir_all`, not the OS trash.** It is opt-in
  (`cleanup_source`), only after verification, and guarded against a symlink,
  a non-directory, a root, and either path containing the other. It is for a
  disposable transfer source, never user data; the caller must pass the right
  source and target pair.
- **HKDF PRK zeroization is best-effort.** `StaticSecret`, `SharedSecret`, and
  the derived AEAD key zeroize on drop; `hkdf` 0.12 does not expose its internal
  PRK for explicit zeroization. The PRK lives only for one seal or open call.
