# Release packaging

T-INST-01. Requirements: INST-01 (channels), INST-02 (an Ed25519 key embedded in
the installer verifies the release manifest), and INST-11 (per-platform
artifacts and an SBOM with each release).

The implementation is `zero_cli::packaging` (`crates/zero-cli/src/packaging.rs`).
It is local and offline: it hashes, signs, verifies, and reads or writes one
strict-JSON file. It does not build archives, upload them, or contact a server.

The update and rollback half of INST-08/INST-10 (T-INST-04) is implemented in
`zero_cli::update` (`crates/zero-cli/src/update.rs`) and documented under
[Update and rollback](#update-and-rollback-t-inst-04). It reuses the signed
manifest, artifact names, and embedded key from this module.

The kernel bootstrap (T-INST-06) is implemented in `zero_cli::bootstrap`
(`crates/zero-cli/src/bootstrap.rs`) and documented under
[Kernel bootstrap](#kernel-bootstrap-t-inst-06).

The service units and lifecycle (T-INST-05) are implemented in `zero_cli::service`
(`crates/zero-cli/src/service.rs`) and documented under
[Service units](#service-units-t-inst-05).

The uninstall surface (T-INST-07) is implemented in `zero_cli::uninstall`
(`crates/zero-cli/src/uninstall.rs`) and documented under
[Uninstall](#uninstall-t-inst-07).

The Unix installer (T-INST-03) is `installer/unix.sh`, with the Rust seam in
`zero_cli::unix_install` (`crates/zero-cli/src/unix_install.rs`), documented
under [Unix installer](#unix-installer-t-inst-03).

The Windows installer (T-INST-02) is `installer/windows.ps1`, with the Rust seam
in `zero_cli::windows_install` (`crates/zero-cli/src/windows_install.rs`),
documented under [Windows installer](#windows-installer-t-inst-02).

## Manifest schema

One file describes one release. Every object refuses unknown fields.

```json
{
  "schema_version": 1,
  "version": "0.1.0",
  "git_sha": "0123456789abcdef0123456789abcdef01234567",
  "created_ms": 1764000000000,
  "artifacts": [
    {
      "target": "x86_64-unknown-linux-gnu",
      "name": "zero-0.1.0-x86_64-unknown-linux-gnu.tar.gz",
      "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
      "bytes": 1041
    }
  ],
  "sbom": [
    {
      "name": "zero",
      "version": "0.1.0",
      "licence": "see package metadata",
      "source": "workspace"
    }
  ],
  "channel": "stable"
}
```

| Field | Rule |
|---|---|
| `schema_version` | Must be `1` (`MANIFEST_SCHEMA_VERSION`). |
| `version` | Non-empty, at most 64 bytes, starts alphanumeric, only `A-Z a-z 0-9 . + -`, no `..`. |
| `git_sha` | 7 to 64 lowercase hex characters. |
| `created_ms` | Unix milliseconds; zero is refused. |
| `channel` | `stable` or `beta` (INST-01). |
| `artifacts` | 1 to 64 entries (`MAX_ARTIFACTS`), unique targets, unique names, each name equal to the helper name below. |
| `artifacts[].sha256` | Exactly 64 lowercase hex characters. |
| `artifacts[].bytes` | Greater than zero. |
| `artifacts[].target` | One of the six supported triples. |
| `sbom` | 1 to 4096 entries (`MAX_SBOM_COMPONENTS`), no exact duplicate, every field non-empty and at most 256 bytes. |

`ReleaseManifest::new` sets `schema_version` and validates. `validate` is also
called by every parse, sign, save, and load path.

### Canonical bytes and `manifest_hash`

The signature does not cover JSON text. It covers
`ReleaseManifest::canonical_bytes`:

- the domain tag `zero.release.manifest\0v1\0`;
- `schema_version` as little-endian `u32`;
- length-prefixed (`u64` little-endian) `version`, `git_sha`, `created_ms`, and
  `channel`;
- artifacts sorted by `(target, name)`, then each `(target, name, sha256,
  bytes)`;
- SBOM components sorted by `(name, version, source, licence)`, then each of the
  four strings.

`manifest_hash()` is the lowercase hex SHA-256 of those bytes. Because the
encoder sorts, two manifests that differ only in list order have the same hash
and the same signature. `normalized()` returns the sorted form; `to_json` and
`save_signed` always write the normalized form, so reruns are byte-identical.

## Artifact naming

`artifact_name(target, version)` produces the archive name;
`executable_name(target)` produces the binary name inside it.

| Target | Archive | Executable |
|---|---|---|
| `x86_64-unknown-linux-gnu` | `zero-<version>-x86_64-unknown-linux-gnu.tar.gz` | `zero` |
| `aarch64-unknown-linux-gnu` | `zero-<version>-aarch64-unknown-linux-gnu.tar.gz` | `zero` |
| `x86_64-apple-darwin` | `zero-<version>-x86_64-apple-darwin.tar.gz` | `zero` |
| `aarch64-apple-darwin` | `zero-<version>-aarch64-apple-darwin.tar.gz` | `zero` |
| `x86_64-pc-windows-msvc` | `zero-<version>-x86_64-pc-windows-msvc.zip` | `zero.exe` |
| `aarch64-pc-windows-msvc` | `zero-<version>-aarch64-pc-windows-msvc.zip` | `zero.exe` |

The version is validated before it is embedded, so a name can never contain a
path separator or `..`. Unknown targets are refused. The result is bounded by
256 bytes.

## Signing and the embedded key

`sign_manifest(manifest, signing_key)` validates the manifest, signs the
canonical bytes with Ed25519, and returns:

```json
{
  "manifest": { "schema_version": 1, "...": "..." },
  "signature_b64": "<base64 STANDARD, padded, 64 bytes>"
}
```

`verify_signed(signed, public_key)` validates the manifest, decodes a strict
64-byte signature, and calls `VerifyingKey::verify_strict`. `verify_embedded`
uses `EMBEDDED_KEY_B64`, the public key compiled into the installer (INST-02).

> **Placeholder key.** `EMBEDDED_KEY_B64` in the source is a clearly marked
> test key. Release tooling replaces it with the public half of the offline
> release signing key. The production module never derives or stores a private
> key; the matching private half of the placeholder exists only under
> `#[cfg(test)]` so the embedded-key path is exercised end to end. A structural
> test scans the crate for PEM private keys and refuses the build if one is
> found.

Recommended release flow:

1. Build and archive each target, recording SHA-256 and size.
2. Run `sbom_from_cargo_lock` over the release checkout's `Cargo.lock`.
3. Build the manifest with `ReleaseManifest::new`.
4. `verify_sbom(&manifest, lock_text)`.
5. Sign on the offline signer with `sign_manifest`.
6. Publish the archives, the manifest, and the SBOM.
7. The installer calls `load_signed` then `verify_embedded`.

## SBOM

`sbom_from_cargo_lock(lock_text, version)` scans `Cargo.lock` line by line; it
needs no TOML dependency. It:

- starts with the product component `zero` at the release `version`,
  `source = "workspace"`;
- reads each `[[package]]` block's `name`, `version`, and, when present,
  `source`;
- records a missing source as `workspace` (Cargo.lock omits it for path
  packages);
- sets every licence to `see package metadata` and never guesses one;
- dedupes by `(name, version, source)` and sorts by `(name, version, source,
  licence)`;
- stops at `MAX_SBOM_COMPONENTS` (4096) entries, deterministically.

`verify_sbom(manifest, lock_text)` validates every component, regenerates the
list, and requires the component count and contents to match exactly.

## Loading and saving

- `load_signed(path)` refuses a file larger than 1 MiB
  (`MAX_MANIFEST_BYTES`), parses strict JSON, validates the manifest, and checks
  the signature's shape. Authenticity is a separate `verify_embedded` call.
- `save_signed(path, signed)` validates, serializes the normalized form, writes
  a temporary file beside the target with `create` + `sync_all`, and renames it
  over the target. A failed rename removes the temporary file.

Parsing is strict: unknown fields, duplicate JSON fields, trailing data, an
unsorted-but-otherwise-valid list (accepted, then normalized), a bad digest, a
duplicate target or name, or an unsupported channel is refused.

## Errors

`PackagingError::kind()` returns one of these stable strings; the message never
contains key material.

| Kind | Meaning |
|---|---|
| `manifest_invalid` | A manifest field or the channel is wrong. |
| `signature_invalid` | The signature is malformed or does not verify. |
| `artifact_invalid` | A name, digest, size, or version is wrong. |
| `sbom_invalid` | A component is empty, duplicated, or does not match the lock. |
| `unsupported_target` | The target is not one of the six triples. |
| `limit_exceeded` | A count, field, or file exceeds its bound. |
| `io` | The manifest file could not be read or written. |
| `json` | The file is not strict JSON matching the schema. |

## Update and rollback (T-INST-04)

Requirements: INST-04 (clean temporary directories; the install lock and
terminal restore belong to the installer), INST-08 (install, update atomically
and signed, with rollback), and INST-10 (upgrade from a local signed package).

The implementation is `zero_cli::update` (`crates/zero-cli/src/update.rs`). It
is local and offline. A *verified update* is a signed manifest plus the exact
bytes to install, and the apply path either installs all of it or restores the
previous tree.

### The archive seam

This crate has no archive dependency, so a real `.tar.gz` or `.zip` is not
decoded here. The decoded archive is modelled as `UpdatePayload`, a sorted map
from a relative `/`-separated path to the exact file bytes. Decoding a real
archive into that tree, and setting executable bits, is installer work.

The signed manifest is still authoritative. Its artifact entry names the
archive SHA-256 and size, and the update digest is computed over the tree:

- the tag `zero.update.payload\0v1\0`;
- the file count as little-endian `u64`;
- for each file in sorted path order, the path length and path, then the file
  length and bytes, all length-prefixed little-endian.

`UpdatePayload::sha256()` must equal the manifest artifact's `sha256`, and
`UpdatePayload::total_bytes()` must equal its `bytes`. A reader that decodes
different bytes, or a release signed with the wrong digest, is refused before
anything is written.

### Verification

`verify_update(artifact, policy)` uses the embedded key (INST-02);
`verify_update_with_key` takes an explicit key. The policy names the expected
target (`UpdatePolicy::expected_target`), the installed version, and whether a
downgrade is allowed. Checks run in this order, touching no files:

1. every payload path is safe and every size bound holds;
2. the manifest is valid, its signature is well formed (a missing or short
   signature is refused);
3. the manifest has an artifact for the expected target (a wrong or unsupported
   target is refused);
4. the payload digest and size match the signed artifact entry (a missing or
   changed digest is refused);
5. the Ed25519 signature verifies (`verify_strict`);
6. the new version does not sort before the installed version unless
   `allow_downgrade` is set.

Nothing is written by verification, so a refused update leaves the tree
untouched.

### Version order and the downgrade rule

`compare_versions` orders the numeric core segment by segment (a missing segment
is zero), then the pre-release: no pre-release is greater than one, identifiers
compare numerically when both are digits, a numeric identifier sorts below a
textual one, and build metadata is ignored. Examples: `0.10.0 > 0.9.9`,
`1.0.0-beta.1 < 1.0.0`, `1.0.0+build.7 == 1.0.0`.

An update that sorts below the installed version is refused with
`downgrade_refused`. `allow_downgrade: true` accepts it deliberately, which is
the local-package path for INST-10 and manual rollback. Reinstalling the same
version is allowed.

`current_version(install_root)` reads `.zero-version` (trimmed; `None` when the
file is absent). An empty or path-like value is refused with `version_invalid`
rather than trusted.

### Staging

`apply_update(verified, install_root, staging_root, now_ms)` requires absolute
roots, with the staging root outside the install root (and not containing it).
Files are staged under `staging_root/<version>`:

- a staging directory for a different version, or one without the
  `.zero-staging` marker, is refused (`staging_conflict`); a stale directory for
  the same version is removed and recreated;
- every file is written with `create_new`, so staging never overwrites;
- every staged file is read back and compared with the verified payload before
  the install is touched.

An injected `DiskProbe` is asked for free bytes before staging. The requirement
is the new payload plus the current install size plus `DISK_HEADROOM_BYTES`
(64 KiB); less free space is refused with `disk_space`. The default probe
reports an unbounded disk; real installers inject a platform probe.

### Snapshot and atomic swap

The current install is snapshotted to
`install_root/.backup-<old_version>-<now_ms>` (a numeric suffix is added if that
name is taken; `unknown` is used when no version file exists). Every file is
copied, hashed while copying, and listed in the snapshot's `manifest.json` with
its SHA-256 and size. Snapshot copies are written to a temporary file and
renamed, so a snapshot is never half-written.

The swap writes each file to `.zero-update.tmp-<pid>-<n>` beside its target,
syncs it, and renames it over the target. This is atomic per file, so no reader
sees a partially written file. After the payload, `.zero-version` is written
the same way. Directories are not renamed as a unit; see
[Limitations](#limitations).

Then the module re-hashes every installed file and the version file. An injected
`HealthCheck` runs after that (real installers start the new binary). Any
failure — bad hash, failed health check, I/O error, or an injected swap-hook
error — restores the snapshot and returns an error whose `rollback_state()` is
`RolledBack`, or `RollbackFailed(reason)` if the restore itself failed. The
message says which happened. This is the T-INST-04 done criterion: a corrupted
update rolls back cleanly.

### Rollback

`rollback(report)` restores the snapshot named by an `UpdateReport`:

- the backup directory must be a `.backup-*` directory inside the install root;
- its manifest must parse, stay inside its size bound, and name only safe
  relative paths;
- each file is copied to a temporary file, hashed, compared with the manifest
  entry, and only then renamed into place;
- files the update introduced, plus the new version file, are removed when the
  snapshot did not contain them;
- the version file must read the old version afterwards, or the rollback is
  reported as failed.

The snapshot is kept after a successful rollback for inspection; the staging
directory is removed. A failure during apply performs the same restore
internally and cleans staging best-effort.

### Refusals

| Condition | Kind |
|---|---|
| Payload digest or size differs from the signed artifact | `artifact_invalid` |
| Signature missing, malformed, or wrong key | `signature_invalid` |
| Manifest invalid, or a missing artifact digest | `artifact_invalid` / `manifest_invalid` |
| Target not one of the six, or absent from the manifest | `wrong_target` |
| Version sorts below the installed one without permission | `downgrade_refused` |
| Version file empty or path-like | `version_invalid` |
| `..`, absolute path, `\`, `:`, empty/`.` component, control character, trailing dot or space, reserved Windows name | `path_escape` |
| More than 8,192 files, one file above 32 MiB, or a payload above 256 MiB | `limit_exceeded` |
| Staging directory owned by another version, unmarked, or a bad root | `staging_conflict` |
| Injected probe reports too little free space | `disk_space` |
| Health check or post-install hash comparison fails | `health_check` |
| Restore failed | `rollback_failed` |
| Filesystem error | `io` |
| Backup manifest is not valid JSON | `json` |

### Update test evidence

Run on Windows from the repository root on 2026-11-26:

```text
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-cli update -j 1
running 17 tests ... test result: ok. 17 passed; 0 failed

$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-cli --all-targets -j 1 -- -D warnings
Finished `dev` profile ... (no warnings)
```

| Test | What it checks |
|---|---|
| `valid_update_stages_verifies_installs_and_bumps_version` | Verify, stage, snapshot, swap, health pass, version bump, user data untouched, staging cleaned, backup manifest hashes. |
| `corrupted_payload_is_refused_before_any_swap` | A payload changed after signing fails verification; a hand-built verified update with a bad digest is refused; the tree is unchanged. |
| `health_check_failure_restores_the_backup_byte_for_byte` | Injected health failure returns `health_check` with `RolledBack`; the full file tree matches the pre-update snapshot; staging is cleaned. |
| `a_mid_swap_failure_rolls_back` | An injected failure after two swaps restores every swapped file and returns `RolledBack`. |
| `downgrade_is_refused_unless_allowed` | Lower version refused; explicit allowance, same version, and a fresh install accepted. |
| `version_comparison_follows_semver_order` | Numeric cores, `0.10.0` vs `0.9.9`, pre-release order, build metadata ignored. |
| `path_escapes_and_reserved_names_are_refused` | `..`, absolute, nested `..`, backslash, drive, empty/`//`/`.` components, trailing dot/space, reserved device names; safe paths accepted. |
| `payload_limits_are_enforced` | Path length, depth, per-file size, and file count bounds. |
| `wrong_target_missing_signature_and_missing_digest_are_refused` | Wrong and unsupported target, empty and short signature, cleared digest, wrong key. |
| `staging_from_another_version_is_refused_and_same_version_is_cleaned` | Foreign and unmarked staging refused with the tree unchanged; stale same-version staging cleaned. |
| `staging_roots_must_be_absolute_and_outside_the_install_root` | Nested staging and a relative install root are refused. |
| `an_insufficient_disk_probe_refuses_before_staging` | Injected probe refusal leaves the tree unchanged and creates no staging directory. |
| `explicit_rollback_restores_the_pre_update_tree` | `rollback(report)` restores the snapshot and old version file and keeps the snapshot directory. |
| `version_file_round_trips_and_rejects_unsafe_values` | Missing file, surrounding whitespace, `../` value, and empty value. |
| `verify_staged_detects_a_tampered_stage` | A staged file changed after staging fails the read-back check. |
| `an_unknown_version_is_still_accepted_as_a_local_package` | A local pre-release package installs and is recorded in the version file. |
| `the_update_path_has_no_network_or_shell_surface` | Production source has no socket, HTTP client, shell command, or private-key derivation. |

## Test evidence

Run on Windows from the repository root on 2026-11-26:

```text
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-cli packaging -j 1
running 10 tests ... test result: ok. 10 passed; 0 failed

$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-cli --all-targets -j 1 -- -D warnings
Finished `dev` profile ... (no warnings)
```

| Test | What it checks |
|---|---|
| `canonical_bytes_and_signature_round_trip` | Deterministic bytes and hash; list order does not change either; sign and verify with the test key. |
| `embedded_key_verifies_a_signed_manifest` | The signed manifest verifies with `EMBEDDED_KEY_B64` (the T-INST-01 done criterion). |
| `a_tampered_manifest_and_a_tampered_signature_fail` | A changed artifact digest, zero signature, and short signature all fail. |
| `a_wrong_key_fails` | A different Ed25519 key fails and the error leaks no key material. |
| `validation_rejects_duplicates_bad_sha_and_unknown_targets` | Duplicate targets and names, uppercase/short digests, zero bytes, unknown targets, bad channel, path-like version, empty artifacts, empty SBOM. |
| `artifact_names_cover_the_six_targets` | All six archive names, `.zip` vs `.tar.gz`, `zero.exe`, no separators; unknown target and bad version refused. |
| `sbom_parses_dedupes_sorts_and_stays_bounded` | Fixture parse, dedupe, sort, licence text, workspace source, 4096-component bound. |
| `verify_sbom_matches_the_lock_and_rejects_a_changed_count` | Matching SBOM passes; an extra component fails on the count. |
| `save_and_load_round_trip_and_json_is_strict` | Atomic save/replace, load, embedded verification, unknown field, duplicate field, and over-size file refused. |
| `no_private_key_or_network_surface_is_shipped` | Production source has no private-key derivation and no network imports; crate scan finds no PEM or key file. |

## Kernel bootstrap (T-INST-06)

Requirements: INST-06 (report the PATH entry the installer adds) and INST-07
(install `uv`, Python, and `ipykernel` on request with checksum verification and
an offline mode).

The implementation is `zero_cli::bootstrap` (`crates/zero-cli/src/bootstrap.rs`).
The module has no network code of its own. Downloads go through the injected
`Downloader`; the local cache is a `Cache`, with `FsCache` as the filesystem
implementation. All tests use fakes, so the suite is offline.

### Plan

A `BootstrapPlan` is the pinned dependency set:

| Field | Rule |
|---|---|
| `schema_version` | Must be `1` (`BOOTSTRAP_SCHEMA_VERSION`). |
| `manifest_version` | Non-empty, at most 128 bytes, starts alphanumeric, only `A-Z a-z 0-9 . + - _`, no `..`. A release-time plan names the manifest it came from. |
| `python_version` | Dot-separated numeric segments, e.g. `3.12.7`. |
| `cache_dir` | Advisory cache directory recorded by the plan; the path actually used is `BootstrapEnv::cache_dir`. Non-empty, at most 256 bytes, no control characters. |
| `components` | 1 to 32 (`MAX_BOOTSTRAP_COMPONENTS`) entries in install order. |
| `components[].kind` | `uv`, `python`, `ipykernel`, `pyzmq`, or `wheel { name, version }`. One of each fixed kind, and wheel names, must be unique. |
| `components[].version_req` | Non-empty, at most 128 bytes, no control characters or surrounding whitespace. Recorded, not resolved here. |
| `components[].url` | `https://` only, at most 512 bytes (`MAX_URL_BYTES`), non-empty host, no whitespace, control character, backslash, or embedded credentials (`@`). |
| `components[].sha256` | Exactly 64 lowercase hex characters. |
| `components[].optional` | An optional component may fail without failing the bootstrap. |

Wheel names and versions are restricted to a safe token (letters, digits, `.`,
`_`, `+`, `-`, starting alphanumeric, no `..`). Validation also derives the
install file name, so a component that would install under an unsafe name is
refused at plan time.

`default_plan(python_version)` returns a representative plan with one component
of each kind. **Every digest is `PLACEHOLDER_SHA256` (64 zeros) and
`manifest_version` is `PLACEHOLDER_MANIFEST_VERSION`; the URLs are
`example.invalid` locations.** The plan validates, but the executor refuses each
placeholder with `placeholder_checksum`. Release tooling replaces the URL,
digest, and manifest version with real values; placeholder digests must never be
downloadable.

### Cache and the offline rule

The cache is content-addressed: `<cache_dir>/<sha256>.bin`. The directory is
created on first write and the digest is validated before it is used in a path,
so a cache path cannot escape the cache root.

`BootstrapEnv` carries `cache_dir`, `bin_dir`, and `offline`. For each component
in plan order:

1. The cache is consulted by SHA-256.
2. **Offline, the cache is the only source.** A miss produces a `cache_miss`
   failure that names the component, the required digest, and the exact file to
   seed (`<cache_dir>/<sha256>.bin`). The downloader is never called; a test
   asserts a zero call count.
3. Online, a miss is downloaded, bounded by `MAX_COMPONENT_BYTES` (256 MiB),
   hashed, and refused on any mismatch **before** it is cached or installed.
   Verified bytes are written to the cache with a temporary file, `sync_all`,
   and a rename, so a reader never sees a partial entry.
4. A cache hit is hashed again before use. A corrupted entry is `cache_tampered`
   and is not installed or replaced automatically; online mode does not silently
   fall back to the network.

The Done criterion for T-INST-06 is covered by
`offline_bootstrap_from_a_populated_cache_succeeds`: with every component in a
filesystem cache, an offline bootstrap installs all of them and makes zero
downloader calls.

### Checksum verification

- The pinned digest is exactly 64 lowercase hex characters.
- Downloaded bytes must hash to the pinned digest. A mismatch is a
  `checksum_mismatch` tamper error: nothing is installed and nothing is cached.
- Cached bytes are re-hashed on every use, so editing a cache file is detected.
- A placeholder digest is refused explicitly, rather than producing a confusing
  mismatch against bytes that could never match 64 zeros.
- The installed file is compared by SHA-256 with the pinned digest on a rerun,
  so reuse is as strict as a fresh install.

### Install layout

| Kind | Installed file in `bin_dir` |
|---|---|
| `uv` | `uv` (`.exe` on Windows) |
| `python` | `python` (`.exe` on Windows) |
| `ipykernel` | `ipykernel` |
| `pyzmq` | `pyzmq` |
| wheel | `<name>-<version>.whl` |

Every name is a single safe file name: no `/`, `\`, `:`, control character,
`.`/`..`, leading dot, trailing dot or space, or reserved Windows device name.
`uv` and `python` are written with mode `0o755` on Unix; data files use `0o644`.

A new file is written to `.zero-bootstrap.tmp-<pid>-<n>` inside `bin_dir`,
synced, given its mode, and renamed into place. If the target already exists:

- the same digest means the component is reused (idempotent rerun);
- a different digest or size is `install_conflict`; the existing file is never
  overwritten.

`BootstrapReport` records `installed` (written this run), `already_installed`
(reused with the expected digest), `reused_from_cache`, `downloaded`, `failed`,
and `env_vars`. `env_vars` contains exactly one PATH-like entry, `PATH` pointing
at `bin_dir`; it never contains a secret. The installer is responsible for
merging that entry into the user PATH and for explaining manual steps when it
cannot (INST-06).

A required failure stops the run. An optional failure is recorded and the next
component is attempted; `is_success()` is true when every failure was optional.

### Kernel probe

`probe_kernel(env, probe)` asks an injected `KernelProbe` for Python and
`ipykernel` and returns `KernelStatus { python, ipykernel, ready }`, where
`ready` is true only when both are present. `BinDirProbe` checks the bootstrap
`bin_dir`; a real probe runs the interpreter and reports versions.

### Refusals

| Condition | Kind |
|---|---|
| Bad schema, duplicate kind or wheel name, bad Python version, bad manifest version, non-HTTPS or credentialed URL | `plan_invalid` |
| More than 32 components, an over-long field or URL | `limit_exceeded` |
| Placeholder digest in the plan | `placeholder_checksum` |
| Offline component absent from the cache | `cache_miss` |
| Cached bytes do not match their key | `cache_tampered` |
| The cache could not store verified bytes | `cache_write` |
| The downloader failed | `download` |
| Downloaded bytes do not match the pinned digest | `checksum_mismatch` |
| A different file already occupies the install name | `install_conflict` |
| Unsafe install or cache path | `path_unsafe` |
| Component or cached entry above 256 MiB | `too_large` |
| Filesystem error | `io` |

### Kernel bootstrap test evidence

Run on Windows from the repository root on 2026-11-26:

```text
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-cli bootstrap -j 1
running 16 tests ... test result: ok. 16 passed; 0 failed

$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-cli --all-targets -j 1 -- -D warnings
Finished `dev` profile ... (no warnings)
```

| Test | What it checks |
|---|---|
| `the_default_plan_is_clearly_marked_as_a_placeholder` | Schema, manifest version, all five kinds, validated placeholder digests; the executor refuses the first placeholder and never downloads. |
| `plan_validation_rejects_duplicates_bad_digests_and_insecure_urls` | Duplicate kind and wheel name, uppercase/short digest, `http://`, empty host, whitespace, credentials, backslash, wrong schema, empty plan, empty manifest version, bad Python version, empty cache directory. |
| `component_limits_and_unsafe_names_are_enforced` | 33-component bound, over-long URL, every kind's install name, wheel `../`, separators, trailing space, `..` version, reserved device names, leading and trailing dots. |
| `offline_bootstrap_from_a_populated_cache_succeeds` | The Done criterion: three cached components install offline, zero downloads, PATH entry returned, bytes and Unix modes correct. |
| `offline_missing_component_fails_with_guidance_and_no_download` | `cache_miss` names the component, digest, and seed path; nothing is installed; the downloader is not called. |
| `online_miss_downloads_verifies_and_stores_in_the_cache` | Three misses download, verify, cache, and install; the cache reads back the exact bytes. |
| `a_bad_checksum_is_refused_and_nothing_is_installed_or_cached` | Tampered download is `checksum_mismatch`; bin directory and cache stay empty. |
| `a_tampered_cache_entry_is_refused_without_a_download` | A corrupted cache file is `cache_tampered`, is not installed, and does not trigger a download. |
| `a_cache_hit_does_not_download` | Cache hit installs without a download and without rewriting the cache. |
| `a_second_run_reuses_installed_components` | Rerun writes nothing, reuses all three installed files, downloads nothing, and leaves bytes unchanged. |
| `an_install_conflict_does_not_overwrite_another_hash` | A different file at the install name is `install_conflict` and keeps its bytes. |
| `a_download_error_is_reported_without_installing` | Downloader failure is typed and carries its message in guidance; nothing is installed. |
| `an_optional_component_failure_does_not_fail_the_bootstrap` | A missing optional component is recorded while the required component installs and the report succeeds. |
| `env_vars_are_path_like_and_carry_no_secrets` | Exactly one entry, `PATH`, equal to `bin_dir`, with no token or secret text. |
| `probe_reports_ready_only_when_python_and_ipykernel_are_present` | Default probe before and after each file; injected probe with one and both versions. |
| `the_offline_path_has_no_network_or_shell_surface` | Production source has no socket, HTTP client, plaintext HTTP, or shell command; offline and downloader branches exist. |

## Service units (T-INST-05)

Requirements: INST-05 (start, stop, and status without a TTY and in CI) and
INST-09 (install systemd, Windows service, and launchd units).

The implementation is `zero_cli::service` (`crates/zero-cli/src/service.rs`).
The module renders unit text and drives the lifecycle; it never runs a command,
writes to a system directory, reads a terminal, or prompts. Installation,
start, stop, status, and removal go through the injected `ServiceManager` seam,
so the tests are scripted and the host owns privileged operations.

### The spec

`ServiceSpec` is one validated unit:

| Field | Rule |
|---|---|
| `platform` | `systemd`, `windows_service`, or `launchd`. |
| `binary_path` | Absolute for the target platform, at most 512 bytes (`MAX_SERVICE_PATH_BYTES`), no control characters, no `..` component, valid UTF-8. |
| `args` | At most 64 (`MAX_SERVICE_ARGS`), each non-empty, at most 512 bytes (`MAX_SERVICE_ARG_BYTES`), no control characters. |
| `working_dir` | Same path rules as `binary_path`. |
| `log_dir` | Same path rules; the service writes `zero.out.log` and `zero.err.log` there. |
| `user` | Optional; systemd and launchd only. At most 64 bytes (`MAX_SERVICE_USER_BYTES`), starts alphanumeric, then letters, digits, `.`, `_`, `-`, `@`. A Windows spec with a user is refused because the service control manager owns the account. |
| `restart` | `always`, `on_failure` (the default), or `never`. |
| `env` | At most 32 entries (`MAX_SERVICE_ENV_ENTRIES`); names start with a letter or `_` and contain ASCII letters, digits, and `_`; values at most 512 bytes; no control characters; no secret-looking names. |

`ServiceSpec::validate` enforces all of it. `render_unit(spec)` validates first
and returns `ServiceResult<String>`, so a refusal is a typed
`ServiceErrorKind` instead of text. That fallible signature is deliberate: a
relative path or a secret can never reach a unit file.

Absolute paths are checked in the style of the **target** platform, not the
host: systemd and launchd require a leading `/`, while the Windows config
requires `X:\`, `X:/`, or a `\\` UNC prefix. Units can therefore be generated
for another platform from any host, though only the host platform can install
one.

Environment names are refused by token when they contain `SECRET`, `TOKEN`,
`PASSWORD`, `PASSWD`, `CREDENTIAL`, `CREDENTIALS`, `PASSPHRASE`, or `KEY`.
Token matching allows `MONKEY` and leaves `OPENAI_API_KEY`, `GITHUB_TOKEN`,
`DB_PASSWORD`, and `AWS_SECRET_ACCESS_KEY` refused with `secret_in_env`.
Credentials belong in the credential store, not in a unit that is world-readable.

### Systemd unit

```ini
[Unit]
Description=Zero agent service
Documentation=man:zero(1)

[Service]
Type=simple
ExecStart=/usr/local/bin/zero serve --no-tty
WorkingDirectory=/var/lib/zero
Environment="ZERO_LOG_LEVEL=info"
User=zero
Restart=always
RestartSec=5
StandardOutput=append:/var/log/zero/zero.out.log
StandardError=append:/var/log/zero/zero.err.log
NoNewPrivileges=true

[Install]
WantedBy=default.target
```

`Restart=` maps `always` → `always`, `on_failure` → `on-failure`, and `never` →
`no`. `User=` is emitted only when a user is set. `NoNewPrivileges=true` is
always present. Arguments, the working directory, and environment pairs are
double-quoted when they contain whitespace or shell/systemd metacharacters;
inside quotes, `"` and `\` are escaped and `%` is doubled so systemd specifier
expansion cannot change the value. Environment output is sorted by name.

### Windows service wrapper config

The Windows unit is a strict-JSON wrapper config consumed by the host service
wrapper; creating the service in the service control manager is host work.

```json
{
  "name": "zero",
  "display_name": "Zero",
  "binary_path": "C:\\Program Files\\Zero\\zero.exe",
  "args": [
    "serve"
  ],
  "working_dir": "C:\\ProgramData\\Zero",
  "log_dir": "C:\\ProgramData\\Zero\\logs",
  "restart": "on_failure",
  "env": {
    "ZERO_LOG_LEVEL": "info"
  }
}
```

`restart` is `always`, `on_failure`, or `never`. Paths use `\` separators for
the log files. Strings are JSON-escaped; the output is deterministic (fixed key
order, sorted environment).

### Launchd property list

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.zero.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/zero/bin/zero</string>
    <string>serve</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>WorkingDirectory</key>
  <string>/usr/local/lib/zero</string>
  <key>StandardOutPath</key>
  <string>/var/log/zero/zero.out.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/zero/zero.err.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>ZERO_LOG_LEVEL</key>
    <string>info</string>
  </dict>
</dict>
</plist>
```

`RunAtLoad` is always true. `KeepAlive` maps `always` → `<true/>`,
`on_failure` → `{ "SuccessfulExit": false }`, and `never` → `<false/>`. Every
value is XML-escaped (`& < > " '`), and `UserName` is emitted only when a user
is set. The plist above is illustrative; the test suite asserts every required
key and the escaping.

### Default unit paths

| Platform | Unit file | Default path |
|---|---|---|
| systemd | `zero.service` | `/etc/systemd/system/zero.service` |
| Windows service | `zero-service.json` | `C:\ProgramData\Zero\zero-service.json` |
| launchd | `com.zero.agent.plist` | `/Library/LaunchDaemons/com.zero.agent.plist` |

These are names only. The module does not write them: the host manager stages
the rendered text and registers the unit, which is also where the required
privileges live.

### Management seam

```rust
pub trait ServiceManager {
    fn start(&self, name: &str) -> ServiceResult<()>;
    fn stop(&self, name: &str) -> ServiceResult<()>;
    fn status(&self, name: &str) -> ServiceResult<ServiceStatus>;
    fn install(&self, unit_path: &Path) -> ServiceResult<()>;
    fn uninstall(&self, name: &str) -> ServiceResult<()>;
}
```

`ServiceStatus` is `Running`, `Stopped`, or `Failed { reason }`. A real manager
calls the platform host (`systemctl`, the Windows service control manager, or
`launchctl`) with non-interactive flags; the module itself has no shell or
execution surface (a test scans the production source for `Command::new`,
`std::process`, sockets, and unsafe blocks).

`manage(platform, spec, manager)` requires the platform to match
`spec.platform`, validates and renders the unit, asks the manager to install it
at the default path, and returns a `ServiceResult<ServiceReport>` with the unit
text, unit path, and observed status. Validation and manager failures are typed
refusals; nothing is reported as installed when the install call failed.

`lifecycle(spec, manager)` runs:

1. validate and render the unit;
2. `install`;
3. `start` — **one attempt only**;
4. `status`;
5. `stop`;
6. `status`.

`LifecycleReport` records `installed`, `started`, `status`, `stopped`,
`final_status`, and the first `failure` with the operation that produced it. A
failure stops the cycle: a failed install never attempts a start, a failed start
is reported and never retried, and a failed start is not followed by a stop. A
start that returns success but whose status is not `Running` is reported as a
failure after the status call, and the cycle still stops the service.

`platform_for_current_os()` maps `linux` → systemd, `macos` → launchd, and
`windows` → the Windows service config. Every other OS is a typed
`unsupported` refusal; nothing is guessed.

### Service test evidence

Run on Windows from the repository root on 2026-11-26:

```text
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-cli service -j 1
running 19 tests ... test result: ok. 19 passed; 0 failed

$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-cli --all-targets -j 1 -- -D warnings
Finished `dev` profile ... (no warnings)
```

| Test | What it checks |
|---|---|
| `systemd_unit_contains_every_required_field` | `[Unit]`/`[Service]`/`[Install]`, `ExecStart`, `WorkingDirectory`, `User`, `Restart`, log redirection, `NoNewPrivileges`, `WantedBy`, environment. |
| `windows_service_config_contains_every_required_field` | The output parses as JSON and carries name, display name, binary, args, working and log directories, restart policy, and environment. |
| `launchd_plist_contains_every_required_field` | Label, `ProgramArguments`, `RunAtLoad`, `KeepAlive`, working directory, both log paths, environment, and user. |
| `launchd_plist_escapes_xml_values` | `< > & " '` are escaped in arguments and paths; no raw XML leaks. |
| `systemd_arguments_and_environment_are_quoted` | Spaces, quotes, and `%` are quoted/escaped; environment pairs are quoted. |
| `restart_policy_is_rendered_for_every_platform` | `always`, `on_failure`, and `never` on systemd, Windows, and launchd. |
| `env_validation_rejects_secret_looking_names` | Seven secret-looking names refused with `secret_in_env`; `MONKEY` and `ZERO_LOG_LEVEL` accepted. |
| `relative_and_non_native_paths_are_refused` | Relative paths, a Windows path in a systemd spec, a Unix path in a Windows spec, and `..` components. |
| `bounded_arguments_and_environment_are_enforced` | Argument count and length, empty and control-character arguments, environment count, name length and syntax, value length. |
| `user_is_refused_for_windows_service` | A Windows user and invalid or empty systemd/launchd users. |
| `unsupported_platform_is_typed` | Linux, macOS, and Windows mapping; an unknown OS is `unsupported`; the current OS matches the table. |
| `unit_rendering_is_deterministic` | Two renders are byte-identical on all three platforms; environment insertion order does not change output. |
| `lifecycle_starts_stops_and_reports_on_all_three_platforms` | The Done criterion: install, start, running status, stop, stopped status on systemd, Windows, and launchd; exact call order. |
| `manage_installs_registers_and_reports_status` | Report fields, unit text, default path, install and status calls, and uninstall through the seam. |
| `a_platform_mismatch_is_refused` | `manage` refuses a mismatched platform and makes no manager call. |
| `a_failed_start_is_reported_and_not_retried` | Exactly one start attempt, no stop, `Failed` status, and the failure text. |
| `a_failed_install_is_reported_without_a_start` | Install failure stops the cycle before start. |
| `a_failed_stop_is_reported_and_the_final_status_is_observed` | A failed stop is reported and the final status is still queried. |
| `the_service_module_has_no_shell_or_execution_surface` | Production source has no `Command::new`, `std::process`, sockets, HTTP client, or unsafe block; the manager seam is present. |

## Uninstall (T-INST-07)

Requirements: INST-07 (uninstall trashes user data after confirmation) and
INST-12 (no orphaned service, PATH entry, or data without explicit consent).
The Done criterion is that no orphaned state remains after a successful run.

The implementation is `zero_cli::uninstall` (`crates/zero-cli/src/uninstall.rs`).
It plans, previews, confirms, and executes one uninstall. It deletes no user
data: data and config go through `zero_fs::TrashService`, the service goes
through `zero_cli::service::ServiceManager`, and the PATH entry is removed from
an injected `Vec<String>` that models the user PATH (the Windows registry value
or the shell equivalent).

### Scopes

`UninstallScope` is the only thing that decides whether user data survives:

| Scope | Service + PATH + binaries | Config | User data |
|---|---|---|---|
| `BinaryOnly` | removed | kept | kept |
| `KeepData` | removed | trashed | kept |
| `Everything` | removed | trashed | trashed |

`BinaryOnly` and `KeepData` are the explicit-consent paths for INST-12: kept
data is not treated as an orphan, so `remaining` excludes it and a successful
`BinaryOnly` or `KeepData` run reports `orphaned == false`.

### Plan and validation

`plan_uninstall(scope, install_root, data_root, config_root, service)` builds an
`UninstallPlan`:

| Field | Rule |
|---|---|
| `binary_dir` | Absolute, at most 512 bytes (`MAX_UNINSTALL_PATH_BYTES`), valid UTF-8, no `.` or `..` component, not the filesystem root. |
| `data_dir`, `config_dir` | Same path rules. The three directories must be disjoint: none may equal or contain another, so a plan cannot trash the install root or a root through its parent. |
| `service_name` | Optional. Non-empty, at most 64 bytes (`MAX_SERVICE_NAME_BYTES`), starts with an ASCII letter or digit, then letters, digits, `.`, `_`, `-`, `@`. |
| `path_entry` | Optional. Non-empty, at most 4096 bytes (`MAX_PATH_ENTRY_BYTES`), no control character. |
| `remove_path_entry` | When true, `path_entry` must be present. |

`UninstallPlan::validate` is called by both `request_confirmation` and
`uninstall`, so a hand-built plan cannot skip the checks. A relative root, `..`,
a shared/nested root, an over-long field, or a malformed service name is a
`zero.fnd.invalid_input` refusal before anything is touched.

`preview(plan)` returns one line per action in execution order and lists exactly
the scope's targets:

- "stop and uninstall service `<name>`";
- "remove PATH entry `<entry>`";
- "move `<data>` to the trash" (Everything only);
- "move `<config>` to the trash" (KeepData and Everything);
- "remove binary `<binary_dir>/zero`" and "`.../zero.exe`".

The preview contains paths and the service name only. It never contains an
environment value, credential, token, or file content.

### Confirmation

An uninstall must present a `Confirmation` minted by
`request_confirmation(plan, now_ms)`. The confirmation carries:

- a SHA-256 fingerprint of the canonical plan (scope, three paths, service,
  PATH entry, and the removal flag, all length-prefixed);
- the issue and expiry timestamps, with a fixed `CONFIRMATION_TTL_MS` of five
  minutes;
- an opaque token derived from the fingerprint, `now_ms`, the process id, and a
  monotonic nonce.

`uninstall` refuses an empty token, a token minted for a different plan (the
fingerprint differs), or a timestamp outside `[issued_ms, expires_ms]`. Every
refusal is `zero.pol.ask`, before any manager, trash, PATH, or filesystem call.
A confirmation cannot be reused for another plan or after it expires; request a
fresh one.

### Execution order

`uninstall(plan, confirmation, now_ms, trash, services, path_env)` runs exactly
this sequence:

1. validate the plan and the confirmation;
2. `services.stop(name)`, then `services.uninstall(name)`;
3. remove the PATH entry by **exact string match**;
4. move config and/or data to the trash, according to the scope;
5. remove the binary files last.

A failure runs no later step. In particular, if the service step fails, the
PATH entry, data, config, and binaries are left untouched, so an installed
service never points at a removed executable. If a trash step fails, the
binaries are still present and the service is already gone; that is incomplete,
not an orphaned service.

The PATH removal uses `Vec::retain(|entry| entry != path_entry)`: only the exact
entry is removed. `<entry>-old`, `old-<entry>`, and every other prefix or suffix
survive. The Windows registry value is modelled by the same vector; no
separator, prefix, or substring trick is used.

Data and config are never deleted with `remove_dir_all`. Each existing root is
passed to `TrashService::trash`; a `Trashed` outcome is recorded in
`report.trashed`, and a `Refused` outcome or an error stops the uninstall before
the binaries. Binaries (`zero` and `zero.exe`) are regular files and are
removed with `remove_file`; the install directory is removed only when it is
empty, so unrelated files are left alone.

### Report and orphan check

`UninstallReport` records:

| Field | Meaning |
|---|---|
| `service_removed` | The planned service is gone (vacuously true when no service is planned). |
| `path_entry_removed` | The planned exact PATH entry is absent (vacuously true when no removal is planned). |
| `trashed` | Roots the trash service confirmed it moved. |
| `binaries_removed` | Every planned binary file is gone (vacuously true when none existed). |
| `remaining` | Planned removals that still exist; excludes data/config a scope keeps. |
| `orphaned` | Any service, PATH entry, binary, or data the plan meant to remove survives. |

A partial failure returns `Ok(report)` with a non-empty `remaining` and/or
`orphaned == true`; it is never reported as success. `report.is_complete()` is
true only when `remaining` is empty and `orphaned` is false. A successful run
has both, which is the T-INST-07 Done criterion: no orphaned state remains.

### Uninstall test evidence

Run on Windows from the repository root on 2026-11-26:

```text
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-cli uninstall -j 1
running 9 tests ... test result: ok. 9 passed; 0 failed

$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-cli --all-targets -j 1 -- -D warnings
Finished `dev` profile ... (no warnings)
```

| Test | What it checks |
|---|---|
| `confirmation_is_required_unexpired_and_bound_to_one_plan` | Empty token, a different plan, and an expired timestamp are each `zero.pol.ask`; no manager call and no filesystem change before consent. |
| `everything_trashes_data_and_config_and_removes_service_path_and_binaries` | Everything trashes both roots, removes the exact PATH entry, keeps other entries and `<entry>-old`, removes the binary and empty install directory, and reports complete/non-orphaned; the binary still exists during service removal. |
| `keep_data_trashes_only_config` | Config is trashed, user data survives, and the report is complete. |
| `binary_only_keeps_all_data_and_config` | Neither root is trashed; service, PATH entry, and binary are still removed. |
| `a_path_entry_prefix_is_not_removed` | `<entry>-old` and `old-<entry>` survive an exact-match removal. |
| `a_service_failure_stops_before_binaries_and_reports_remaining` | A failed service uninstall leaves PATH, data, config, and binaries untouched; `remaining` and `orphaned` report the incomplete state. |
| `a_trash_failure_reports_remaining_and_keeps_the_binaries` | A refused config trash is recorded after the data trash; config and binaries remain, `remaining`/`orphaned` are accurate, and the service/PATH entry are already gone. |
| `preview_lists_the_scope_only_and_has_no_secrets` | Everything lists data and config, KeepData lists config only, BinaryOnly lists neither; no secret-looking text. |
| `invalid_plans_are_refused_before_confirmation` | Relative, `..`, shared, and nested roots, a malformed service name, and a removal flag without an entry are refused as invalid input. |

## Unix installer (T-INST-03)

Requirements: INST-03 (no Node or other runtime prerequisite), INST-04 (an
install lock, a terminal restore on trap, and temporary cleanup), and INST-05
(non-interactive: runs without a TTY and in CI without hanging).

The installer is `installer/unix.sh`, a POSIX `sh` script with no bashisms. It
runs under `dash`, `ash`, and the macOS system shell, and installs one
already-downloaded executable; downloading, archive decoding, and manifest
signature checks stay in the release tooling. The Rust seam is
`zero_cli::unix_install` (`crates/zero-cli/src/unix_install.rs`):
`script_path()`, `validate_script()`, and `install_command()` name the script,
audit it, and build the argv a caller runs.

### Flags

| Flag | Rule |
|---|---|
| `--prefix DIR` | Install root; the binary goes to `DIR/bin`. Default `$HOME/.local`. Must be absolute and writable by this user. |
| `--file PATH` | Artifact to install. Required unless `--uninstall`. |
| `--name NAME` | Installed file name. Default `zero`. Must be a plain file name. |
| `--sha256 HEX` | Expected digest, exactly 64 lowercase hex characters. Required unless `--uninstall`. |
| `--force` | Replace an existing binary whose content differs. |
| `--uninstall` | Remove the installed binary and the lock. User data is kept. |
| `--no-path` | Print no PATH guidance and never edit a shell profile. |
| `--update-path` | Append the PATH line to `~/.profile` (`~/.zshrc` when `$SHELL` ends in `zsh`), once. |
| `--help` | Print usage and exit 0. |

`--prefix`, `--file`, `--name`, and `--sha256` also accept `--flag=value`.
`--no-path` and `--update-path` are mutually exclusive.

### Safety

- **Non-admin only.** The installer never escalates. Before creating anything it
  walks to the nearest existing ancestor of the prefix; if that is not writable
  it refuses (exit 3) and names `$HOME/.local` as the user alternative. A prefix
  at the filesystem root is refused, as is a relative prefix.
- **Checksum first.** The digest is validated (length and lowercase hex) and the
  artifact is hashed with `sha256sum`, falling back to `shasum -a 256`. A
  mismatch is refused before the lock is taken or any file is created.
- **Lock.** `$PREFIX/.zero-install.lock` is created with `mkdir`, so creation is
  atomic without `flock`. The directory holds a `pid` file. A live owner PID
  refuses a concurrent install (exit 3); a stale lock (dead PID, or a
  non-numeric PID file) is removed and recreated.
- **Conflict detection.** An existing binary with the same SHA-256 is an
  idempotent success and only has its executable bit re-applied. A different
  binary is refused unless `--force` is passed.
- **Atomic install.** The artifact is copied to `$PREFIX/bin/.<name>.tmp.<pid>`,
  made executable with `chmod 755`, re-hashed, and renamed over the target with
  `mv -f`. A reader never sees a half-written binary, and any failed check
  removes the temporary file.
- **Traps.** `EXIT`, `INT`, and `TERM` call one idempotent cleanup that removes
  the staged file, removes the lock's PID file and the lock directory, and
  restores the terminal. The terminal state is captured with `stty -g` only when
  stdin is a TTY, and `stty sane` runs only if the captured state changed.
- **No TTY, no prompts.** The script never reads stdin. `-t 0` only decides
  whether to capture terminal state and which mode line to print. Every CI
  invocation redirects stdin from `/dev/null`.

### PATH

The installer prints the exact line but does not edit a shell profile:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

`--update-path` appends it (with a comment) to `~/.profile`, or `~/.zshrc` when
the login shell is zsh, and skips it when the exact line is already present.
`--no-path` suppresses the guidance entirely. The profile file is created when
it is absent.

### Uninstall

`--uninstall` removes only `$PREFIX/bin/<name>` and the lock. It never touches
the Zero data or configuration directories, and it prints that they were kept.
An already-absent binary is reported as `not installed` and still exits 0, so
the script is safe to rerun.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Installed, already installed, or uninstalled. |
| 2 | Bad usage (unknown flag, relative prefix, bad digest, combined PATH flags). |
| 3 | Refused: lock, checksum, conflict, or permissions. |
| 4 | Missing tool, unreadable artifact, or I/O failure. |

### Test evidence

Local Linux (WSL, `dash` as `sh`) end-to-end run on 2026-11-26 with a temporary
prefix and two synthetic executables:

```text
installed /tmp/.../prefix/bin/zero
mode: non-interactive (stdin is not a TTY); no prompts were shown
already installed: .../bin/zero (identical sha256)
checksum mismatch ... refusing to install an artifact that does not match --sha256   (exit 3)
... already exists with different content; pass --force to replace it               (exit 3)
another install is already running for ... (pid ...)                                 (exit 3)
removing a stale install lock at ...
appended the PATH line to .../.profile
PATH lines in .profile: 1
removed .../bin/zero
binary and lock gone, data kept
```

Rust: `cargo test -p zero-cli unix_install -j 1` runs 9 tests; see the table
below. macOS was not run on this host; the `installer (unix)` CI job covers
`macos-15`.

CI job `installer (unix)` (job id `installer-unix`, matrix `ubuntu-latest` and
`macos-15`) checks out the branch and uses only shell tooling, with no Rust
build. It asserts: `--help` lists the flags; install puts an executable on disk
and it runs; a rerun is idempotent; a wrong checksum, a conflicting binary, and
a live lock are refused; `--force` replaces the binary; `--update-path` appends
exactly one line; `--no-path` prints no guidance; no prompt text appears and
every run reads stdin from `/dev/null`; and `--uninstall` removes the binary and
the lock while keeping a data file. The hosted macOS result is recorded on the
pull request; this branch has only the Linux (WSL) run above.

| Test | What it checks |
|---|---|
| `script_path_points_at_the_repository_installer` | `script_path()` ends in `installer/unix.sh` and the file exists. |
| `the_shipped_script_is_posix_and_carries_every_requirement` | The shipped text passes `validate_script` and starts with `#!/bin/sh`. |
| `validation_rejects_bash_only_syntax` | `[[ ]]`, `function`, `local`, and `pipefail` are refused with a typed `script_invalid`. |
| `validation_rejects_a_missing_flag_lock_trap_or_checksum` | Removing a flag arm, the EXIT trap, the lock creation, the `shasum` fallback, the terminal restore, or the atomic rename fails validation. |
| `validation_rejects_a_stdin_read` | A `read` line is refused because the installer must never prompt. |
| `install_command_builds_the_exact_argument_vector` | `["sh", script, "--prefix", ..., "--file", ..., "--sha256", ...]`. |
| `install_command_refuses_an_invalid_checksum_or_path` | Empty, short, uppercase, and non-hex digests; empty prefix and file. |
| `an_error_names_its_kind_and_every_problem` | `zero.installer.script_invalid` plus every problem in the message. |
| `the_generator_does_not_execute_commands` | Production source has no `Command::new`, `std::process`, or `sh -c`. |

## Windows installer (T-INST-02)

Requirements: INST-02 (the caller passes the SHA-256 of the exact bytes; the
signed release manifest is verified by the release tooling before it hands the
artifact over), INST-04 (an install lock and clean temporary files), INST-05
(non-interactive: no TTY, no prompts, CI-safe), and INST-06 (update the user PATH
and explain manual steps when it cannot).

The installer is `installer/windows.ps1`, a PowerShell 5.1 script. It installs
one already-downloaded executable and needs no Node and no other runtime beyond
Windows PowerShell. Downloading, archive decoding, manifest signature checks,
and service registration stay in the release tooling. The Rust seam is
`zero_cli::windows_install` (`crates/zero-cli/src/windows_install.rs`):
`script_path()`, `validate_script()`, and `install_command()` name the script,
audit it, and build the argv a caller runs.

`install_command(prefix, file, sha256)` returns:

```text
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass
  -File <installer/windows.ps1> -Prefix <prefix> -File <file> -Sha256 <sha256>
```

The digest must already be 64 lowercase hex characters, so a caller cannot pass
an unverifiable artifact to the script.

### Parameters

| Parameter | Rule |
|---|---|
| `-Prefix DIR` | Install root; the executable goes directly in `DIR`. Default `%LOCALAPPDATA%\Zero`. Must be an absolute path this user can write. |
| `-File PATH` | Artifact to install. Required unless `-Uninstall`. |
| `-Name NAME` | Installed executable name. Default `zero`; `.exe` is added when `NAME` has no extension. Must be a plain file name. |
| `-Sha256 HEX` | Expected digest, exactly 64 hex characters. Required to install. |
| `-Force` | Replace an existing binary whose content differs. |
| `-Uninstall` | Remove the installed binary and the lock. User data and configuration are kept. |
| `-NoPath` | Print no PATH guidance and never change the user PATH. |
| `-UpdatePath` | Append the install directory to the user PATH, once. |
| `-WhatIf` | Print what would happen without changing anything. |
| `-Help` | Print usage and exit 0. |

`-NoPath` and `-UpdatePath` are mutually exclusive. The script accepts
environment variables in `-Prefix` (for example `%LOCALAPPDATA%`) and a leading
`~`.

### Safety

- **Non-admin only.** The script never elevates and never calls
  `Start-Process -Verb RunAs`. It refuses a relative or drive-relative prefix
  (exit 2) and a prefix that is, or is under, Program Files, Program Files
  (x86), the Windows directory, System32, the Common Program Files directories,
  or a drive root (exit 3), naming `%LOCALAPPDATA%\Zero` as the user
  alternative. It also probes the nearest existing ancestor for write access
  before creating the install directory.
- **Checksum first.** `Get-FileHash -Algorithm SHA256` runs before the lock is
  taken or any file is created. A mismatch prints the expected and actual
  digests and exits 3 with the existing binary untouched. The staged copy is
  hashed again before the rename.
- **Conflict detection.** An existing binary with the same SHA-256 is an
  idempotent success. A different binary is refused (exit 3) unless `-Force` is
  passed.
- **Lock.** `<prefix>\.zero-install.lock` is opened with
  `[IO.File]::Open(..., CreateNew, ..., FileShare.None)`, so creation and
  exclusivity are one atomic operation. The owner PID is written to the file. A
  lock whose PID is alive refuses a concurrent install (exit 3); a lock whose
  PID is dead, or whose PID file cannot be parsed, is removed and recreated. A
  lock that cannot be read is held by a live installer and is refused rather
  than stolen.
- **Atomic install.** The artifact is copied to
  `<prefix>\.<name>.tmp.<pid>`, re-hashed, and moved over the target with
  `Move-Item -Force`. A reader never sees a half-written binary.
- **Cleanup.** An outer `finally` block disposes the lock stream, deletes the
  lock file, and removes any staged temporary file, including on a refusal or an
  unexpected error.
- **No prompts.** The script never calls `Read-Host`, reads stdin, or pauses.
  Every run is non-interactive, and CI invokes it with
  `-NoProfile -NonInteractive`.

### PATH

The installer never edits the machine PATH. It prints the directory and a
manual command, and only with `-UpdatePath` does it write the **user** PATH:

```powershell
# The script performs the equivalent of this, with an exact-entry check first.
[Environment]::SetEnvironmentVariable('Path', $userPath + ';<prefix>', 'User')
```

The entry is compared case-insensitively and by exact directory, so a second run
does not duplicate it, and a prefix or suffix of the path is not treated as a
match. The combined value is bounded at 8192 characters; a value that would
exceed the bound prints manual guidance instead of being written. A successful
update prints that a new terminal or a fresh sign-in is needed because already
running processes keep their old environment. `-NoPath` suppresses all of the
above.

### Uninstall

`-Uninstall` removes only `<prefix>\<name>.exe` and
`<prefix>\.zero-install.lock`. Pass the same `-Name` used at install time when it
was not the default. It never touches the Zero data or configuration
directories, prints that they were kept, and does not edit the user PATH. An
already-absent binary is reported as `not installed` and still exits 0, so the
command is safe to rerun.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Installed, already installed, or uninstalled. |
| 2 | Bad usage: relative prefix, missing artifact, bad digest, conflicting PATH flags. |
| 3 | Refused: lock, checksum, conflict, protected location, or permissions. |

The script has no exit code 4; an unexpected I/O error is reported and exits 3.

### Windows installer test evidence

Local Windows PowerShell 5.1 end-to-end run on 2026-11-26 with a temporary prefix
and two synthetic executables (copies of `cmd.exe` and `hostname.exe`):

```text
PASS install exit 0
PASS installed file exists
PASS installed binary runs
PASS idempotent exit 0
PASS idempotent message
PASS idempotent bytes unchanged
PASS wrong checksum exit 3
PASS wrong checksum message
PASS wrong checksum left binary
PASS conflict exit 3
PASS conflict message
PASS conflict left binary
PASS force exit 0
PASS force replaced bytes
PASS replaced binary runs
PASS live lock exit 3
PASS live lock message
PASS live lock kept file
PASS stale lock exit 0
PASS stale lock message
PASS stale lock installs
PASS lock removed after run
PASS no-path leaves user PATH
PASS update-path exit 0
PASS update-path entry exactly once
PASS update-path idempotent
PASS user PATH restored
PASS relative prefix exit 2
PASS Program Files refused 3
PASS Program Files guidance
PASS System32 refused 3
PASS no-path + update-path exit 2
PASS whatif exit 0
PASS whatif kept file
PASS uninstall exit 0
PASS uninstall removed binary
PASS uninstall removed lock
PASS uninstall kept data
PASS uninstall rerun not installed
FAILURES=0
```

The exact PowerShell body of the `installer (windows)` CI job was also run on
this host (Windows PowerShell 5.1, `RUNNER_TEMP` pointed at a temporary
directory) and exited 0.

Rust: `cargo test -p zero-cli windows_install -j 1` runs 9 tests; see the table.

CI job `installer (windows)` (job id `installer-windows`, `windows-latest`,
`shell: pwsh`, 10-minute timeout) checks out the branch and uses only shell
tooling, with no Rust build. It asserts: `-Help` lists the flags; install puts
an executable in `$env:RUNNER_TEMP\zero-prefix` and it runs; a rerun is
idempotent; a wrong checksum, a conflicting binary, and a live lock are refused
with the documented exit codes; a stale lock is recovered; `-Force` replaces the
binary; `-NoPath` leaves the user PATH unchanged; `-UpdatePath` appends exactly
one entry and is idempotent; the machine PATH is unchanged; a relative prefix and
a Program Files prefix are refused; `-WhatIf` changes nothing; and `-Uninstall`
removes the binary and the lock while keeping a data file. This is the T-INST-02
"clean VM install in CI" criterion: `windows-latest` is a fresh VM. The hosted
result is recorded on the pull request; this branch's evidence is the local run
above.

| Test | What it checks |
|---|---|
| `script_path_points_at_the_repository_installer` | `script_path()` ends in `installer/windows.ps1` and the file exists. |
| `the_shipped_script_is_powershell_51_and_carries_every_requirement` | The shipped text passes `validate_script` and starts with `#requires -Version 5.1`. |
| `every_parameter_is_documented_in_the_usage_text` | Every entry in `REQUIRED_PARAMETERS` has a line in the usage text. |
| `validation_rejects_a_missing_parameter_or_safety_marker` | Removing `-UpdatePath`, `-WhatIf`, the `Get-FileHash` check, the exclusive lock, the atomic rename, the user PATH update, the default-prefix guidance, the Program Files/System32 refusals, or the `finally` cleanup fails validation. |
| `validation_rejects_elevation_prompts_and_machine_path_writes` | `Start-Process -Verb RunAs`, `Read-Host`, and `SetEnvironmentVariable(..., 'Machine')` are each refused with a typed `script_invalid`. |
| `install_command_builds_the_exact_argument_vector` | `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ... -Prefix ... -File ... -Sha256 ...`. |
| `install_command_refuses_an_invalid_checksum_or_path` | Empty, short, uppercase, and non-hex digests; empty prefix and file. |
| `an_error_names_its_kind_and_every_problem` | `zero.installer.script_invalid` plus every problem in the message. |
| `the_generator_does_not_execute_commands` | Production source has no `Command::new`, `std::process`, or inline `powershell -c`. |

## Limitations

- This task ships the manifest, naming, SBOM, and signing surface. It does not
  build archives, upload them, or run the six-target release matrix; those
  belong to T-TST-01 and the installer tasks.
- The embedded key is a placeholder until release tooling replaces it. A
  manifest signed by this test key proves the verification path, not a
  production release.
- SBOM licences are reported as `see package metadata`; licence resolution
  against package metadata is not implemented here.
- `save_signed` fsyncs the file before renaming. It does not fsync the parent
  directory, so on a power loss the new name may not be durable on every
  filesystem; the file contents are never partially visible.
- `channel` is stored and validated. The `ZERO_VERSION` and
  `ZERO_RELEASE_CHANNEL` overrides are installer/CLI behavior (INST-01) and are
  not implemented in this module.
- Update archive extraction is not implemented: `UpdatePayload` is the seam. A
  real `.tar.gz` or `.zip` decoder (and executable-bit handling) is installer
  work; until then an update can only be applied from an already-decoded tree.
- The swap is atomic per file, not for the whole tree. A process crash or power
  loss between two renames can leave a mixed tree. The snapshot is complete
  before the first rename, so a later start can restore it with `rollback` from
  the same `UpdateReport` (or by reading the snapshot manifest), but automatic
  crash recovery is not implemented.
- A running `zero` process holds its executable open. On Windows the rename over
  that file fails; the installer must stop the service or process before
  swapping. The module reports the I/O error and rolls back.
- Temporary files and renamed files are synced, but parent directories are not
  fsynced. Durable rename ordering after a power loss is therefore best-effort.
- The default `DiskProbe` cannot query the OS without a platform syscall and
  reports an unbounded disk. Installers must inject a real probe.
- The install tree must contain only regular files and directories; symlinks and
  special files are refused as `path_escape`. Snapshot directories named
  `.backup-*` are reserved and skipped on the next update.
- A rollback keeps the snapshot directory (for inspection) and can leave empty
  directories behind for files the update introduced; file contents are
  restored, directory emptiness is not tracked.
- The Unix installer installs one executable file. Downloading, archive
  decoding, manifest signature verification, and service registration stay in
  the release tooling and the `zero install` path; the script trusts the bytes
  only because the caller passes the artifact's SHA-256.
- macOS is covered by the hosted `installer (unix)` job, not by this host. The
  script uses only `sh`, `cut`, `dirname`, `grep`, `mkdir`, `mv`, `chmod`,
  `stty`, and `sha256sum`/`shasum`, all present on the supported macOS images.
- The script has no update protocol of its own. `--force` replaces a binary
  without the signed-manifest check, snapshot, health check, and rollback of
  T-INST-04; use `zero update` for that path.
- `--update-path` manages only `~/.profile` and `~/.zshrc`. It does not edit
  fish configuration, and uninstall does not remove a PATH entry the user added
  by hand.
- The terminal restore only corrects a state change that happened during the
  run; the installer itself never changes terminal modes.
- The Windows installer installs one executable. Archive decoding, signed
  manifest verification, service registration, and kernel bootstrap stay in the
  release tooling and the `zero install` path; the script trusts the bytes only
  because the caller passes the artifact's SHA-256.
- `-Uninstall` removes only the executable and the lock. It does not remove the
  user PATH entry and does not touch data or configuration; `zero uninstall`
  (T-INST-07) is the entry point for scoped data/config cleanup and exact PATH
  removal.
- The Windows lock records a PID and treats a live PID as an owner. PID reuse can
  therefore misclassify a stale lock as live, exactly as in the Unix installer;
  remove the lock manually after verifying that no install is running.
- The user PATH write goes through `[Environment]::SetEnvironmentVariable(...,
  'User')`, which updates the registry (HKCU). Already-running processes keep
  their old environment until restarted, and no environment-change broadcast is
  sent.
- `-WhatIf` is a script switch, not `SupportsShouldProcess`; it verifies the
  artifact and prints the plan but performs no lock or filesystem mutation.
- The Windows installer targets PowerShell 5.1 and later. The local run used
  5.1; the hosted CI job invokes the script through `powershell.exe`, so the 5.1
  path is the one exercised in CI.
- The install lock and terminal restoration required by INST-04 are installer
  behavior. This module cleans its staging directory but does not lock the
  install root.
- The `zero update` verb remains a stub; it is not wired to `apply_update` until
  the installer milestone supplies a signed package and channel.
- Kernel bootstrap components are modelled as one verified file each. Decoding
  a real `.tar.gz`/`.zip` and laying out a full Python environment (site
  packages, `python -m ipykernel`) is installer work; until then the bootstrap
  proves the plan, checksum, cache, offline, install, and probe rules.
- `default_plan` is a placeholder manifest: its digests are 64 zeros and its
  URLs are `example.invalid`. The executor refuses it, so a release must supply
  a plan with real digests. `default_plan` is a shape, not a downloadable
  bundle.
- The bootstrap returns the PATH entry instead of changing the user PATH.
  Applying it, and explaining manual steps when the change is refused, is
  installer behavior (INST-06).
- The cache has no eviction, locking, or concurrent-writer protocol beyond the
  atomic temp-file rename. Two bootstraps sharing one cache may both download
  the same component; the last writer wins with identical, verified bytes.
- Offline bootstrap requires the cache even when a component is already
  installed in `bin_dir`, because the requirement makes the cache the only
  offline source. A missing cache entry is reported with the exact path to
  seed.
- `BinDirProbe` checks that the installed files exist; it does not execute
  Python and cannot report real interpreter or package versions. A release
  probe must run the interpreter.
- Service units are rendered, not written. The module never stages a file under
  `/etc`, `/Library`, or `C:\ProgramData` and never raises its privileges; the
  host installer or manager writes the text at the default path and registers
  it.
- The Windows unit is a JSON wrapper config, not a service control manager
  call. Creating, configuring, or deleting the service (`sc.exe`/SCM) is host
  work; only the config shape and the lifecycle seam are implemented here.
- The launchd path is `/Library/LaunchDaemons`, which needs root. Loading,
  bootstrapping, and bootout (`launchctl`) are host work, not module calls.
- Service status is only as accurate as the injected `ServiceManager`. The
  module never polls the platform itself, so a manager that reports stale state
  is reported as stale state.
- The restart policy has no backoff tuning: systemd uses a fixed `RestartSec=5`,
  the Windows config records only the policy, and launchd expresses
  `on_failure` as `SuccessfulExit = false`.
- A service user is recorded, not created or checked. The host must create the
  account and grant it access to the working and log directories.
- Secret-looking environment names are refused by token, so a legitimate
  non-secret variable whose name contains `KEY`, `TOKEN`, `SECRET`, or a related
  token is also refused. The workaround is to rename the variable or move the
  value to the credential store, not to weaken the unit.
- `platform_for_current_os` supports Linux, macOS, and Windows only. A build on
  another OS gets a typed `unsupported` refusal; it does not guess a unit
  format.
- The module is non-interactive by construction, but a real manager still has
  to pass non-interactive flags to its host command so a missing unit cannot
  open a prompt (INST-05).
- Uninstall is not wired to a `zero uninstall` CLI verb or an installer script
  yet; the library surface, tests, and report are complete, but the host entry
  point must call `plan_uninstall`, `preview`, `request_confirmation`, and
  `uninstall` in that order.
- The injected `TrashService` owns the protected-path policy. A trash service
  built with the live data/config roots as protected (the default
  `ProtectedPaths::for_current`) refuses the roots an uninstall must move, so
  the uninstall entry point must supply a service whose protected set excludes
  the roots being removed, or a future whitelist for confirmed uninstalls. The
  module reports the refusal and leaves the roots in place; it never falls back
  to raw deletion.
- The PATH vector models one user PATH value. Applying it to the Windows
  registry, rewriting a shell profile, and broadcasting the environment change
  are host/installer work. Only exact-match removal and preservation of every
  other entry are implemented here.
- "Binaries" means the `zero` and `zero.exe` files in `binary_dir`. Other files
  in that directory are not deleted, and a non-empty install directory is left
  in place; it is not counted as orphaned.
- The service manager contract is that `stop` and `uninstall` succeed or report
  a typed error; the module does not inspect `status` first and does not retry.
  A manager that returns an error for an already-absent service will make the
  uninstall stop before the PATH and binary steps, so real managers should treat
  "not installed" as success.
- A partial failure reports `remaining` and `orphaned` but not the manager or
  trash error text (the `UninstallReport` has no message field). Callers can see
  which targets survive; a diagnostic reason must come from the injected
  manager's own logging.
