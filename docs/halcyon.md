# Halcyon discovery, trust, verification, keys, adapters, behaviour, flags, and todo sync

Seven slices live in `zero-halcyon`:

- **T-HAL-01 — discovery and trust** (`src/discovery.rs`): find the nearest
  `.halcyon-mode`, refuse linked paths, and keep the mode inert in an untrusted
  workspace (HAL-01, HAL-02, HAL-12).
- **T-HAL-02 — verification** (`src/verify.rs`): parse the document, verify an
  Ed25519 signature over a canonical encoding against a key pinned in user
  configuration, enforce the issuance/expiry window, and bind the file to the
  current project id (HAL-02, HAL-03, HAL-05).
- **T-HAL-03 — key tooling** (`src/keys.rs`): keygen, sign, pin, unpin, rotate,
  revoke, un-revoke, and sealed private-key storage behind a user-only actor
  gate (HAL-03, HAL-04).
- **T-HAL-04 — adapters** (`src/adapters.rs`): detect `tkb`, `joker`, and `epb`
  on `PATH`, negotiate their versions, and turn a missing or outdated tool into
  install or upgrade guidance with no installer, download, or vendor binding
  (HAL-04, HAL-07, HAL-13).
- **T-HAL-05 — behaviour rules** (`src/behaviour.rs`): record gaps, route gates
  only through `joker`, route endpoints only through `epb`, and refuse to finish
  without a `tkb check` record and a handover (HAL-05, HAL-08, HAL-09).
- **T-HAL-06 — flags** (`src/flags.rs`): exactly the four HAL-10 keys, parsed
  from a typed map and resolved so the untrusted project layer can only disable
  a flag, never enable one (HAL-06, HAL-10).
- **T-HAL-07 — todo sync** (`src/todo_sync.rs`): bidirectional, idempotent,
  version-checked todo sync with `tkb`, gated by `halcyon.todo_sync`, with an
  offline queue and conflicts surfaced as panel items (HAL-07, HAL-11, TODO-09,
  TSK-12).

## Discovery

`discover(start, home)` converts the start to an absolute path, verifies it is a
real directory, canonicalises it, and searches outward by distance:

| Distance | Directories inspected |
|---|---|
| 0 | the start directory itself |
| 1 | every immediate child directory (non-recursive) and the parent |
| 2..n | one ancestor per level, stopping at home or the filesystem root |

At each directory, `symlink_metadata` inspects `<dir>/.halcyon-mode`:

1. A regular file is a candidate; the containing directory is the workspace root
   used for trust.
2. A missing entry continues the scan.
3. A link, a non-regular entry such as a directory, or an unreadable entry is a
   typed error, never a silent skip.

**Nearest wins.** The scan stops at the first distance that has candidates:

- exactly one candidate → `Discovery::Found(ModeFile { path, root })`;
- two or more candidates → `Discovery::Conflict { candidates, reason }`; nothing
  is chosen and no contents are read;
- none through the boundary → `Discovery::Absent`.

`Discovery::candidate_paths()` returns the one found path or the sorted conflict
list; `is_found()`, `is_conflict()`, and `is_absent()` expose the state.

**Tie rule.** Distance 0 is unique and wins outright, so a working-directory file
beats both children and ancestors. At distance 1, immediate-child files and the
parent file are equally near; the requirement's same-distance rule applies and
more than one candidate is a conflict. There is no parent-first or lexicographic
fallback: a child file plus a parent file conflicts, and two child files conflict.
Distances 2..n hold one directory each, so ties cannot occur above distance 1.
Child scanning is non-recursive; a grandchild is only considered when it is the
working directory (or an immediate child of it).

The start and home boundaries are canonicalised before the boundary comparison.
When `home` is supplied, a start outside it is refused with
`zero.fnd.invalid_input`; the scan checks home itself and never ascends above it,
so a file in an ancestor of home cannot enable the mode.

## Symlink and reparse-point rejection

Discovery never follows a link, at any position:

- every existing ancestor of the start is checked with `symlink_metadata`
  before the scan begins, so a linked intermediate directory cannot redirect
  discovery;
- a `.halcyon-mode` that is a link is refused rather than skipped, at the start,
  in a child, or in an ancestor;
- a link-like immediate child directory is an inspection exclusion: it is never
  followed and never becomes a candidate, because it cannot own this
  workspace's mode file. Excluding it is not an error, so ordinary projects with
  linked dependency directories still work;
- on Windows, `FILE_ATTRIBUTE_REPARSE_POINT` is refused as well as
  `is_symlink()`, because junctions do not report as symlinks.

A refused link is a typed `zero.pol.denied` error naming the offending path. A
non-regular entry such as a directory named `.halcyon-mode` is
`zero.fnd.invalid_input`. An unreadable child (or unreadable mode file) is a
typed `zero.fnd.permission_denied` error rather than an ignored directory,
because a nearer candidate cannot otherwise be ruled out. Permission failures
while inspecting a path are never treated as "absent".

`ModeFile::read_bounded(max_bytes)` re-checks that the file is still a regular,
non-linked file, refuses a size above the cap with `zero.fnd.limit_exceeded`,
and reads through `take(max_bytes + 1)` so a file that grows between the metadata
check and the read is refused instead of partially accepted. The default
suggested cap is `DEFAULT_MAX_MODE_FILE_BYTES` (64 KiB).

## Trust gate

`activation(discovery, gate)` never reads file contents:

| Discovery | Gate | Activation |
|---|---|---|
| `Absent` | not consulted | `Disabled { reason: None }` — nothing is registered (HAL-02) |
| `Conflict` | not consulted | `Disabled { reason: Some(conflict reason) }` — no candidate is chosen |
| `Found` | trusted | `Enabled(file)` |
| `Found` | untrusted | `Inert { reason: "workspace is not trusted" }` |

`Activation::is_enabled()`, `is_inert()`, `is_disabled()`, `reason()`, and
`mode_file()` expose the decision; `reason()` carries either the conflict
explanation or the untrusted reason. `mode_file()` is `None` unless enabled.

`TrustGate` has one method, `trusted(root) -> bool`. `UntrustedWorkspace` is the
default and trusts nothing. `TrustedRoots` is the explicit helper used by tests
and hosts: it holds canonical roots and matches them **exactly**, with no
inheritance. Trusting a parent therefore does not trust a project inside it, so a
hostile repository cannot be enabled by a nearby trust decision or by a valid
looking file. Trust is evaluated against the discovered workspace root, never
against the start path or the process working directory.

## Hostile-workspace inertness

HAL-12 requires the mode to stay inert in an untrusted workspace even when the
file is signed. This slice enforces the structural precondition: a repository
that ships `.halcyon-mode` contributes `Inert` until its root is explicitly
trusted, and the gate runs before any content is opened. Because discovery
refuses links and treats same-distance candidates as a conflict, a hostile
repository also cannot point the mode file or the scan at a trusted location, nor
force a choice between candidates.

## Verification (T-HAL-02)

`verify.rs` turns a discovered file into a `VerifiedMode` only when the schema,
the signature, the project binding, and the time window all pass.

### Document schema

`.halcyon-mode` is JSON:

```json
{
  "version": 1,
  "project_id": "prj_0123456789abcdef",
  "issued_ms": 1700000000000,
  "expires_ms": 1700003600000,
  "flags": { "halcyon.mode": true, "halcyon.todo_sync": false },
  "nonce": "nonce-0001",
  "key_id": "user-halcyon-key",
  "signature": "<standard base64, 64 bytes decoded>"
}
```

| Field | Required | Rule |
|---|---|---|
| `version` | yes | must be `1`; an unknown version is refused, not guessed |
| `project_id` | yes | non-empty visible ASCII without spaces, ≤ 128 bytes |
| `issued_ms` | yes | i64 milliseconds since the Unix epoch |
| `expires_ms` | yes | i64, strictly greater than `issued_ms` |
| `flags` | no (default empty) | at most 64 entries; each key follows the identifier rule; values are booleans |
| `nonce` | yes | identifier rule; signed but not interpreted here |
| `key_id` | yes | identifier rule; must name a pinned key exactly |
| `signature` | yes for activation | standard padded base64 of a 64-byte Ed25519 signature; **not** part of the signed bytes |

Missing required fields, wrong types, non-ASCII or oversized identifiers, an
inverted time window, and an unsupported version are `zero.fnd.invalid_input`.
A document above 64 KiB (`MAX_MODE_DOCUMENT_BYTES`) is
`zero.fnd.limit_exceeded`. Unknown JSON fields are ignored for forward
compatibility. `ModeDocument::from_json` applies the same bounds the verifier
does.

### Canonical encoding

`canonical_bytes` is a fixed, length-prefixed layout — not JSON serialisation, so
parser map ordering cannot affect the signature. Measured byte for byte:

| Order | Bytes | Meaning |
|---|---|---|
| 1 | `zero.halcyon.mode.v1\0` (21 bytes) | domain separation |
| 2 | `u16le` | `version` |
| 3 | `u32le` length, then UTF-8 bytes | `project_id` |
| 4 | `i64le` | `issued_ms` |
| 5 | `i64le` | `expires_ms` |
| 6 | `u32le` | flag count |
| 7 | repeated, ascending flag key: `u32le` length, key bytes, `u8` value (`1` true, `0` false) | `flags` |
| 8 | `u32le` length, then UTF-8 bytes | `nonce` |
| 9 | `u32le` length, then UTF-8 bytes | `key_id` |

`signature` is excluded by construction: the signer signs these bytes and stores
the result beside them. Because every variable-width field carries its own
`u32le` byte count and the flag keys come from a sorted map, two different
documents cannot collide by re-splitting bytes across field boundaries, and
insertion order in the JSON object cannot change the bytes. The function
validates first, so it returns a typed error rather than encoding an
out-of-bounds field.

Limits: identifiers and flag names are at most `MAX_MODE_FIELD_BYTES` (128)
bytes; a document has at most `MAX_MODE_FLAGS` (64) flags; the canonical bytes
therefore stay small and bounded.

### Pin set

Keys come from a **user-scope** JSON file; there is deliberately no project
constructor, because a repository must not be able to pin a key for itself
(HAL-10: project config cannot enable Halcyon).

```json
{
  "keys": [
    {
      "key_id": "user-halcyon-key",
      "public_key_b64": "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
    }
  ]
}
```

`PinSet::load(path)` bounds the file at 64 KiB (`MAX_PIN_FILE_BYTES`), rejects
non-regular files, refuses more than 1024 keys (`MAX_PINS`), requires
`STANDARD` padded base64 that decodes to exactly 32 bytes and forms a valid
Ed25519 point, applies the identifier rule to `key_id`, and rejects duplicate
key ids with `zero.fnd.invalid_input`. An empty pin set is valid but verifies
nothing. Malformed pins are refused at load time, and the verifier also refuses
to choose when a set deserialised around `load` contains a duplicate. A pin
error never echoes the public key bytes.

### Verification order and errors

`verify(document, signature_b64, pins, expected_project_id, now_ms)` checks in
this order:

| Step | Check | Failure |
|---|---|---|
| 1 | schema, bounds, canonical encoding | `zero.fnd.invalid_input` / `zero.fnd.limit_exceeded` |
| 2 | exact `key_id` in the pin set; no fallback, no prefix match, no duplicate | `zero.pol.denied` |
| 3 | signature decodes as standard base64 to exactly 64 bytes | `zero.fnd.invalid_input` |
| 4 | Ed25519 `verify_strict` over `canonical_bytes` | `zero.pol.denied` |
| 5 | `project_id == expected_project_id` (HAL-05) | `zero.pol.denied` |
| 6 | `issued_ms <= now_ms + skew` and `expires_ms > now_ms - skew` | `zero.pol.denied` |

Verification never falls back to another pinned key when the named key fails or
is absent, and a failure does not distinguish a wrong signature from tampered
bytes in its message (both are "the Ed25519 signature does not verify for pinned
key `<key_id>`"). Messages never contain the public key or the signature bytes.
`verify_strict` rejects small-order public keys, non-canonical signatures, and
scalar malleability.

### Expiry and clock skew

The window is strict by default (`DEFAULT_CLOCK_SKEW_MS = 0`): `expires_ms` must
be strictly after `now_ms` and `issued_ms` at or before it. A host may opt into a
tolerance in either direction with `verify_with_skew` or
`Verifier::with_clock_skew_ms`; accepted values are `0..=3_600_000` ms
(`MAX_CLOCK_SKEW_MS`). With skew `s`, a document is expired when
`expires_ms <= now_ms - s` and not yet valid when `issued_ms > now_ms + s`.
Comparisons are done in `i128`, so hostile timestamp extremes cannot overflow.
A `VerifiedMode` exposes `expires_ms`, `issued_ms`, `is_expired_at(now)`,
`flags`, `nonce`, and `key_id` for later policy layers.

### Project binding and copied repositories

`project_id` is signed. A copied repository has a new project id, so the copied
file's still-valid signature fails step 5 and the copy stays disabled until it
has its own signed file. This is the T-HAL-02 Done criterion. Path is never part
of the binding, so moving a project keeps its identity (HAL-05).

### Activation order

`activation_verified(discovery, gate, verifier, expected_project_id, now_ms)`
composes trust and verification:

1. absent discovery → `Disabled` with no reason, nothing read;
2. same-distance conflict → `Disabled` with the tie reason, nothing read;
3. untrusted workspace → `Inert` after the metadata-only gate and before the
   file is opened (HAL-12); a non-JSON file in an untrusted repository still
   yields a clean `Inert`;
4. trusted workspace → `ModeFile::read_bounded` (64 KiB cap, links refused),
   strict parse, embedded signature required, then the verification steps;
5. `Enabled` only after every check passes. A trusted file that fails
   verification returns the typed error; it never becomes `Enabled`.

`discovery::activation` remains the structural path used by the T-HAL-01 tests.
It answers "is there a unique file in a trusted root?", not "is this file
authentic?", and hosts must not treat its `Enabled` as verification. The
authentic paths are `activation_verified`, which reaches `Enabled` only after
verification, and `verify_mode_file`, which returns a `VerifiedMode` that can
only be constructed inside `verify.rs`.

### Scope limits of this slice

- Expiry is mandatory in schema version 1; HAL-05's "optional expiry" needs a
  sentinel or a later schema version.
- `nonce` is signed and returned but no replay or rotation check is applied; the
  short-lived capability token is HAL-06.
- Only Ed25519 against pinned keys is implemented. The passkey fallback in
  HAL-03 is later work; the Argon2id option is the sealed private-key file in
  T-HAL-03 (`keys.rs`), not a second signature algorithm.
- Flag names are stored and returned by verification; `flags.rs` restricts
  configuration to the four HAL-10 keys and resolves them so a project file can
  only disable (T-HAL-06).
- The signature is over Zero's canonical encoding, not RFC 8785 JSON
  canonicalisation; interoperability with another producer would need to adopt
  this layout exactly.
- JSON is parsed before encoding, so duplicate object keys in the raw file are
  resolved by the parser (last value wins) and the signature covers the resolved
  document, not the original bytes.

## Key tooling (T-HAL-03)

`keys.rs` owns every operation that can mint, use, change, or distrust a key.
Verification stays in `verify.rs`; the key layer only decides who may act and
what the user has pinned, revoked, or rotated.

### Actor gate

`Actor` has exactly two values, `User` and `Agent`, and no `Default`, so no
call defaults to a user by omission. Every public mutating or signing entry
point takes an `Actor` first and calls `authorize(action, actor)` before doing
any work:

| `KeyAction` | `User` | `Agent` | Entry points |
|---|---|---|---|
| `Keygen` | allowed | `zero.pol.denied` | `keygen`, `KeyPair::keygen`, `KeyPair::with_label` |
| `Sign` | allowed | `zero.pol.denied` | `sign_mode`, `KeyPair::sign_mode`, `KeyPair::seal`, `SealedKey::unseal` |
| `Pin` | allowed | `zero.pol.denied` | `PinSet::pin`, `PinSet::unpin` |
| `Rotate` | allowed | `zero.pol.denied` | `PinSet::rotate` |
| `Revoke` | allowed | `zero.pol.denied` | `PinSet::revoke`, `PinSet::unrevoke` |
| `Verify` | allowed | allowed | `PinSet::verify`, `PinSet::verify_with_skew` |

`authorize` is also public so a host can ask the same question before it builds
a surface. The denial message names the action and never includes key bytes.
This is the T-HAL-03 Done criterion: the agent cannot sign or rotate; a test
drives every action as `Agent`, asserts refusal for the five mutating actions,
and asserts that verification still succeeds.

Sealing and unsealing are gated as `Sign`: unsealing yields a private key that
can sign, so it is not a verification-only operation.

### Key ids

A key minted by `keygen` derives its id from the public key:

```text
key_id = "halcyon-" || first 32 hex characters of blake3(public_key_bytes)
```

32 hex characters carry 128 bits, which makes an accidental collision
negligible while keeping ids readable. `KeyPair::with_label` keeps a
caller-supplied label instead; the label follows the mode-document identifier
rule (visible ASCII without spaces or control characters, at most 128 bytes).
The key id is the only key material that appears in logs, errors, and the pin
file, and it is the exact string a mode document must name.

`KeyPair` wraps `ed25519_dalek::SigningKey`. Its `Debug` implementation prints
only the key id; the private scalar is never printed, formatted, serialised, or
written by this module. A test scans the `Debug` output of every type, every
error message, and every file written into a temporary directory for the raw
private bytes, their hex form, and their base64 form.

### Signing

`sign_mode(actor, keypair, document)` clones the document, replaces `key_id`
with the signing key's id, clears any stale signature, signs
[`canonical_bytes`], and returns a `SignedMode` carrying both the signed
document and the detached standard-base64 signature. The returned document also
has the signature embedded under `signature`, so writing it to
`.halcyon-mode` is one JSON serialisation.

Overriding `key_id` is deliberate: a caller cannot produce a signature that
claims a different key id than the one that made it. Canonical bytes exclude
`signature`, so signing does not change the bytes being signed; a test asserts
the bytes are identical before and after.

### Pin, unpin, rotate, revoke

Pin state lives in a user-scope `PinFile`; nothing here accepts a project path,
so a repository cannot pin a key for itself.

```json
{
  "schema": 1,
  "pins": [
    {
      "key_id": "halcyon-2f9c0f0d7c0a4f0e9c3d2b1a88776655",
      "public_key_b64": "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
    }
  ],
  "revoked": [{ "key_id": "old-key", "at_ms": 1700000000000, "reason": "lost laptop" }],
  "rotations": [{ "from_key_id": "old-key", "to_key_id": "halcyon-2f9c0f0d7c0a4f0e9c3d2b1a88776655" }]
}
```

| Operation | Behaviour |
|---|---|
| `pin(actor, key)` | User-only. Validates the id and Ed25519 point, refuses a duplicate id (`zero.fnd.already_exists`), and refuses a revoked id (`zero.pol.denied`) until `unrevoke` runs. |
| `unpin(actor, key_id)` | User-only. Refuses a missing pin (`zero.fnd.not_found`). |
| `rotate(actor, old_key_id, new_keypair)` | User-only. Requires the old pin, a different new id, a new id that is not revoked, and a new id that is not already pinned. Pin-new, unpin-old, and the rotation record are applied as one assignment; any failure leaves the set unchanged. |
| `revoke(actor, key_id, now_ms)` | User-only. Adds a `{key_id, at_ms, reason}` record; repeating it is idempotent. The pin record is deliberately kept so verification refuses the key by revocation, not by absence. |
| `unrevoke(actor, key_id)` | User-only and explicit. Removes the revocation so the id can be pinned and verified again; nothing clears a revocation implicitly. |

`PinFile` is bounded at 64 KiB, validated on load and before save, and written
through a temporary file plus `sync_all` and a rename. It never contains a
private key. `PinSet::load_file` and `PinSet::save_atomic` are the file pair;
`PinSet::load` remains the legacy `{"keys":[...]}` reader from T-HAL-02, and its
serialised form is unchanged while no revocations or rotations exist.

### Sealed private keys

`KeyPair::seal(actor, passphrase)` encrypts the 32-byte Ed25519 seed at rest:

| Property | Value |
|---|---|
| Derivation | `Argon2::default()` (Argon2id, version 19) over the passphrase with a random 16-byte salt |
| Cipher | AES-256-GCM with a random 12-byte nonce |
| Associated data | `zero.halcyon.sealed-key.v1\0` followed by the key id, so editing the id also fails decryption |
| Envelope | `{ version, kdf: "argon2id", key_id, salt_b64, nonce_b64, ciphertext_b64 }`, bounded at 16 KiB |
| Failure | A wrong passphrase, tampered ciphertext, tampered key id, or malformed base64 is `zero.tru.tamper` (`TamperDetected`); the message never echoes key material |

An empty passphrase is `zero.fnd.invalid_input`; one above 1024 bytes is
`zero.fnd.limit_exceeded`. `SealedKey::save_atomic` and `SealedKey::load` use the
same temporary-and-rename pattern. `SealedKey::unseal(actor, passphrase)` and
`KeyPair::unseal(actor, passphrase, sealed)` are user-only and restore a pair
with the envelope's key id, including custom labels. A key that is not sealed
to disk exists only in memory for the life of the `KeyPair`; there is no
plaintext export path.

### Verification integration

`PinSet::verify(actor, document, signature_b64, expected_project_id, now_ms)`
takes the actor, authorizes `Verify` (allowed to both), and delegates to
`verify::verify`, so schema, pin lookup, signature, project binding, and the
issuance/expiry window all behave exactly as documented above. The reverse
direction is also wired: `verify_with_skew` consults `PinSet::is_revoked`
immediately after canonical encoding and before the pin lookup, so a revoked key
id is refused even while its pin record is still present. That check applies to
the raw free function too, not only the actor-gated wrapper.

Rotation semantics are forward-only: `rotate` unpins the old key, so a document
signed by the old key no longer verifies (it fails with "no pinned key") and a
document signed by the new key verifies immediately. Keeping the old key valid
alongside the new one is a policy decision a host can make by pinning the old
key again; this crate does not keep it implicitly. Revocation is permanent for
the id until the user explicitly un-revokes it.

### Scope limits of the key slice

- HAL-03's passkey fallback and HAL-04's OS-store or hardware key storage are
  not implemented; the sealed file is the file-based Argon2id option, and an
  in-memory `KeyPair` is the only other form.
- Sealed storage is a user-scope file format, not a substitute for a platform
  keychain. T-CRT-01/T-CRT-02 cover the OS store and the credential fallback.
- Rotation has no timestamp field (the operation takes no clock); the audit
  record is the ordered `rotations` list.
- Key export/import and cross-device key mesh are out of scope here
  (T-PRJ-06, T-MESH-01).

## Adapters (T-HAL-04)

`adapters.rs` answers two questions about the tools Halcyon drives — `tkb`, the
task backend; `joker`, the gate runner; and `epb`, the endpoint bridge — without
trusting them:

1. is the binary on `PATH`;
2. does it report a version this build supports.

Detection is side-effect free. It never runs the candidate, installs anything,
downloads anything, or binds to a vendor distribution. A missing or outdated
tool becomes a typed [`Adapter`] carrying guidance, not an error that hides the
remedy (HAL-07, HAL-13).

### Adapter model

`AdapterKind::{Tkb, Joker, Epb}` exposes `binary_name()` (`tkb`, `joker`,
`epb`), `display_name()` (for guidance), `package_name()` (the install package
text), `minimum_version()`, and `requirement()`.

| Adapter | Binary | Package | Minimum |
|---|---|---|---|
| tkb task backend | `tkb` | `tkb` | `1.0.0` (`TKB_MINIMUM_VERSION`) |
| joker gate runner | `joker` | `joker` | `1.0.0` (`JOKER_MINIMUM_VERSION`) |
| epb endpoint bridge | `epb` | `epb` | `1.0.0` (`EPB_MINIMUM_VERSION`) |

Each floor is a separate constant, so raising one adapter's minimum does not
change the others. Guidance names the package and points at
`docs/halcyon.md#adapters`; it deliberately does not invent an external download
URL for a project-specific tool.

`Version { major, minor, patch }` compares numerically. `Version::parse` accepts
one `MAJOR.MINOR.PATCH` token: a leading `v`/`V` is allowed, and everything from
the first `-` or `+` is ignored, so `v1.2.3-rc.1+build.5` parses as `1.2.3`.
Exactly three dot-separated numbers are required; `1.2`, `1.2.3.4`, and `1.x.3`
are refused.

`Version::parse_reported` reads `--version` output by tokenising on whitespace
and punctuation and taking the first token that parses. This accepts
`tkb 1.2.3`, `joker version: 2.0.1`, `v0.9.0`, and `epb/1.4.0 (release)`. The
first-match rule means output that prints a date such as `2026.11.25` before the
real version is read as that date.

`Requirement { min }` is the floor; `Requirement::at_least(version)` builds one.
`Compatibility` is the negotiation result:

| Value | Meaning |
|---|---|
| `Compatible` | the reported version is at or above the requirement |
| `TooOld { found, min }` | the reported version is below the requirement |
| `Unparseable { raw }` | the probe ran but its output held no version token |

`Adapter` carries `kind`, `executable`, `version`, `raw_version` (the exact probe
output, retained even when parsing failed), `compatibility` (an `Option`, since
`detect` alone does not negotiate), and `guidance`. `is_present()` answers
"found"; `is_compatible()` answers "found and at or above the requirement".

### Detection

`Env` is the search environment. `Env::from_process()` reads `PATH` with
`std::env::split_paths` and, on Windows, `PATHEXT` (falling back to
`.COM;.EXE;.BAT;.CMD`). `Env::new(path, extensions)` is the test seam, so no test
depends on the host's real `PATH`.

`detect(kind, &env)` walks `PATH` entries in order:

- On Windows, each directory tries every `PATHEXT` extension in order, so the
  environment's extension order decides between `tkb.CMD` and `tkb.EXE` in the
  same directory.
- On Unix, the exact name is tried and must be a regular file with an execute
  bit (mode `0o111`); a readable data file named `tkb` is ignored.
- The first existing executable wins. It is not canonicalised and it is not
  run.

A found adapter has `executable: Some(path)` and `compatibility: None`. A
missing adapter has `executable: None`, `version: None`, and `guidance:
Some(...)`; that is the Done criterion for T-HAL-04: a missing binary shows
install guidance.

Limitations: a relative `PATH` entry is resolved against the process working
directory. On Windows, while `PATHEXT` is non-empty, a bare extensionless
executable is not a candidate, and `PATHEXT` matching relies on filesystem
case-insensitivity. `CommandProbe` spawns directly rather than through a shell,
so a `.cmd`/`.bat` launcher found by `PATHEXT` fails its probe and produces
guidance; a host that needs those can supply its own `VersionProbe`.

### Negotiation and guidance

`negotiate(adapter, requirement)` recomputes `compatibility` and `guidance` from
the adapter's parsed version. It is repeatable: applying a stricter requirement
replaces the earlier result instead of accumulating one, and relaxing it can
return `Compatible` with no guidance.

`detect_and_negotiate(kind, &env, &probe)` is the common path: detect, call the
probe at most once for a found executable, parse `Version::parse_reported`, then
negotiate against `kind.requirement()`.

| State | `compatibility` | Guidance |
|---|---|---|
| missing | `None` | name, package, `PATH`, minimum, docs anchor, `--version` to confirm |
| too old | `TooOld { found, min }` | found and minimum versions, upgrade the package |
| unparseable | `Unparseable { raw }` | the raw output, the `MAJOR.MINOR.PATCH` rule, the minimum |
| probe error | `None` (version unknown) | the reason, the executable path, the minimum, manual `--version` |
| compatible | `Compatible` | `None` |

A probe error is a typed `ZeroError` (`Timeout`, `LimitExceeded`, `NotFound`,
`PermissionDenied`, `Io`, or `Internal` for a reader failure or empty output) at
the seam, but `detect_and_negotiate` converts it into guidance so a broken tool
disables only its capability. Nothing in the module writes files, installs a
package, or downloads one.

### Probe seam

`VersionProbe::version(&Path) -> Result<String, ZeroError>` is the only way a
version enters the model.

- `CommandProbe` (production) runs `<executable> --version` with no stdin,
  captures stdout and stderr on reader threads so a chatty binary cannot fill a
  pipe and deadlock, caps each stream at
  `DEFAULT_PROBE_OUTPUT_BYTES` (4 KiB), kills the child after
  `DEFAULT_PROBE_TIMEOUT` (2 s), and prefers stdout when both streams are
  non-empty. `CommandProbe::new(timeout, max_output_bytes)` overrides both. It
  runs `--version` and nothing else; it is never an installer.
- `ScriptedProbe` (test double) keys outputs or errors by path, with
  `with_any_output`/`with_any_error` fallbacks. `calls()` and `requested()` let a
  test prove the probe ran once, on the path detection chose, so no fixture
  binary was executed.

## Behaviour (T-HAL-05)

`behaviour.rs` encodes the mode's workflow natively (HAL-08). Nothing here reads
Halcyon's own instructions: the rules below are code, and every refusal names the
rule and points at this section.

### Run state and evidence

`HalcyonRun` is the evidence a host collects while the mode is active:

| Field | Meaning |
|---|---|
| `run_id`, `started_ms` | caller-supplied identifier (visible ASCII without spaces, ≤ 128 bytes) and start time |
| `check: Option<CheckRecord>` | the latest `tkb check` result: `{ at_ms, ok, summary }` |
| `gaps: Vec<Gap>` | every gap: `{ id, at_ms, description, severity, resolved, waived }` |
| `handover: Option<Handover>` | `{ at_ms, summary, evidence }` from `tkb handover write` |
| `gates: Vec<GateRecord>` | every gate request: `{ gate, via }`, refused ones included |
| `endpoints: Vec<EndpointRecord>` | every endpoint request: `{ endpoint, via }`, refused ones included |
| `finished_ms: Option<i64>` | set only by a successful `finish` |

| Function | Behaviour |
|---|---|
| `HalcyonRun::new(run_id, started_ms)` | Empty evidence. An empty or oversized id, or one with a space or a non-visible character, is a typed error. |
| `record_check(run, ok, summary, now_ms)` | Replaces `check`. The summary is non-empty, ≤ 1024 bytes, and has no control characters other than newline and tab. A later call replaces the earlier record, which is how a failed check is cleared. |
| `record_gap(run, description, severity, now_ms)` | Appends a gap numbered `gap-1`, `gap-2`, … in discovery order and returns the id. The description is non-empty, ≤ 1024 bytes, and free of control characters other than newline and tab. |
| `resolve_gap(run, gap_id)` | Marks the gap resolved. Resolving twice is a no-op; an unknown id is `zero.fnd.not_found`. |
| `waive_gap(run, gap_id)` | Explicitly waives an info gap. A warn or high gap is `zero.pol.denied`; an unknown id is `zero.fnd.not_found`. |
| `handover(run, summary, evidence, now_ms)` | Stores and returns the handover. The summary is non-empty, ≤ 4096 bytes, with no control characters other than newline and tab. At most 64 evidence lines, each non-empty, ≤ 512 bytes, and single-line (no control characters at all). |
| `can_finish(run)` | Read-only completion gate; returns a `FinishReport` or the refusal. |
| `finish(run, now_ms)` | Runs the gate, then stamps `finished_ms` and returns the report. |

Evidence is a closed record: once a run has finished, `record_check`,
`record_gap`, `resolve_gap`, `waive_gap`, `handover`, `request_gate`, and
`request_endpoint` all refuse with `zero.pol.denied` naming the finish time, so a
handover cannot be back-dated or amended after the fact. `can_finish` and
`finish` still answer for a finished run.

### Routing rules (HAL-08, HAL-09)

`Route::{Joker, Epb, Direct}` is the route a request took. `Direct` exists so a
refused direct call leaves evidence behind; it is never an accepted route.

| Function | Accepted route | Any other route |
|---|---|---|
| `request_gate(run, gate, route)` | `Route::Joker` | `zero.pol.denied`: "gates run only through joker" |
| `request_endpoint(run, endpoint, route)` | `Route::Epb` | `zero.pol.denied`: "endpoints route only through epb" |

A refused request is **appended to `gates`/`endpoints` before the error is
returned**, so a caller that ignores the error does not erase the attempt:
`can_finish` fails on any recorded gate that did not go through `joker` or any
recorded endpoint that did not go through `epb`. A cross-route mistake (a gate
through `epb`, an endpoint through `joker`) is refused the same way as `Direct`.

There is no direct-test shortcut and no mock endpoint. Falling back to a bare
`cargo test` or building a stand-in backend is a violation (HAL-08, HAL-09), and
this module gives it no path that succeeds. Names are validated before
recording: empty, oversized, or non-visible-ASCII gate and endpoint names are
`zero.fnd.invalid_input` and leave no record.

`JokerAdapter` and `EpbAdapter` are the host seams: an implementation wraps the
real binary and records the request through the matching route. The default
implementations, `JokerRoute` and `EpbRoute`, cannot pass `Route::Direct`, so a
caller using the seam cannot request a direct run by accident.

### Gap policy

Every skipped item, discovered bug, scope addition, or missing endpoint is
recorded with `record_gap` at the moment it is found; a gap named only in prose
is not recorded (HAL-08). `GapSeverity` is `Info`, `Warn`, or `High`.

- `Gap::is_blocking()` is `!resolved && !(severity is info && waived)`.
- A resolved gap never blocks.
- Only an **info** gap may be waived, and only explicitly through `waive_gap`.
  A waiver stored on a warn or high gap is ignored by `is_blocking`, so editing
  the field cannot bypass the gate.
- Ids are run-local and assigned in order; the refusal names up to three
  blocking ids and a count of the rest.

### Completion and handover gate

`can_finish` checks in this order and refuses with `zero.pol.denied`:

| Order | Refused when | Message names |
|---|---|---|
| 1 | no `tkb check` record exists | "tkb check required" |
| 2 | the latest check failed | the failed check's time and summary; fix and run `tkb check` again |
| 3 | an unresolved gap is not an explicitly waived info gap | the blocking ids and the count |
| 4 | no handover exists | "handover required"; write one with `tkb handover write` |
| 5 | a gate was recorded through a route other than `joker` | the gate and its route |
| 6 | an endpoint was recorded through a route other than `epb` | the endpoint and its route |

The task text allows `zero.pol.asked`/`zero.pol.denied` for the missing-check
refusal. This slice uses `zero.pol.denied` for every completion refusal: a
missing check is not an action a user can approve, and offering
`zero.pol.ask` would let an approval bypass the evidence bar. A failed check is
cleared only by a later successful `record_check`, which replaces the record and
keeps its own `at_ms`.

On success the `FinishReport` carries `run_id`, the satisfying `check`, the
`handover` (with `evidence()`), every gap, every gate, and every endpoint, so a
reviewer can reconstruct the run without the live state.

`finish` stamps `finished_ms` only after the gate passes. A second `finish` is
idempotent: it re-evaluates the unchanged evidence, returns an equal report, and
leaves the first timestamp in place. A failed gate never stamps the run, so the
caller can fix the evidence and call again.

### Scope limits of the behaviour slice

- The run keeps one check record. Re-check history is not retained; the record's
  `at_ms` says when the current result was taken.
- Nothing here executes `tkb`, `joker`, or `epb`. Recording is the seam;
  `adapters.rs` owns detection and a host owns execution. A gate recorded as
  `Route::Joker` is evidence that the host says it used joker, not proof that a
  process ran.
- Evidence lives in memory. Durable storage and todo sync are T-HAL-07 and the
  session log.
- Handover validation is shape-only (bounds and control characters). The text is
  not checked against the tests that actually ran.

## Flags (T-HAL-06)

`flags.rs` owns the HAL-10 flag surface. There are exactly four keys, no
wildcard, and no generic `halcyon.*` namespace.

| `Flag` | `key()` | Capability |
|---|---|---|
| `Mode` | `halcyon.mode` | the mode itself |
| `TodoSync` | `halcyon.todo_sync` | two-way todo sync with `tkb` (T-HAL-07) |
| `Joker` | `halcyon.joker` | gates through `joker` |
| `Epb` | `halcyon.epb` | endpoints through `epb` |

`Flag::key` returns the exact key, `Flag::parse_key` matches exactly and
case-sensitively (`Halcyon.Mode` and `halcyon.mode ` are unknown), and
`Flag::ALL` has four entries. `FlagValues` stores four booleans and defaults to
all false; `enabled(flag)`, `set(flag, bool)`, `is_empty()`, and
`enabled_flags()` are the accessors.

### Parsing

`parse_report(&BTreeMap<String, serde_json::Value>) -> Result<FlagReport>` reads
only the four keys:

1. A known key must hold a JSON boolean. Any other type (`"true"`, `1`, `null`,
   an array, an object) is `zero.fnd.config_invalid` and the message names the
   key.
2. An unknown key is ignored for forward compatibility and listed in
   `FlagReport::ignored`, sorted with the map.
3. A missing known key is false.

`parse_values(map)` returns the same `FlagValues` without the ignored-key list.
A malformed known key fails in both forms; unknown keys never fail.

### Resolution

`resolve(FlagSources { global, project })` returns a `FlagResolution`:

| global | project | effective | record |
|---|---|---|---|
| false | absent | false | — |
| false | false | false | — |
| false | true | **false** | `rejected` with `PROJECT_CANNOT_ENABLE_REASON` |
| true | absent | true | — |
| true | false | **false** | `disabled_by_project` |
| true | true | true | — |

Only the global (user-owned) layer may enable a flag. The project layer is
untrusted, so it has exactly one direction: it may subtract. A project `true`
where the global layer is `false` never becomes effective and is recorded in
`FlagResolution::rejected`. A project `false` turns off a globally enabled flag
and is recorded in `FlagResolution::disabled_by_project`. A project `true` where
the global layer is also `true` stays true. When the global layer has no value,
every flag is false even if the project layer says true.

This is the T-HAL-06 Done criterion: **project config cannot enable a flag**.
`FlagResolution::effective` starts from the global values and the loop only ever
calls `set(flag, false)`, so no project input can raise a flag.

A project layer is a complete snapshot, not a sparse overlay. `FlagValues`
defaults every missing key to false, so a key the project map omits is a project
`false` and disables that globally enabled flag. A project that wants to keep
other flags on states them `true`; those that are globally off are still
rejected, never enabled.

### Diagnostics

- `FlagResolution::reason(flag)` returns the rejection reason for a project
  attempt to enable, `PROJECT_DISABLED_REASON` for a project disable, and `None`
  when the global layer decided the value.
- `FlagResolution::rejected` lists `(Flag, reason)` pairs; it is the audit trail
  for an override that was refused.
- `FlagResolution::disabled_by_project` lists the flags a project file turned
  off, in `Flag::ALL` order.
- `FlagResolution::is_enabled(flag)` and `enabled_flags()` are convenience
  readers over `effective`.
- `FlagReport::ignored` explains why an unfamiliar key had no effect.

### Flags do not grant the mode

A flag permits a capability; it never substitutes for the activation gates.
`halcyon.mode = true` does not start Halcyon: `discovery` must find a
`.halcyon-mode` file in a trusted workspace, and `verify` must accept its
Ed25519 signature, pinned key, project binding, and time window. Resolving a
flag set early, or storing it in project config, cannot skip either gate. The
`flags_do_not_bypass_discovery_or_verification` test proves the mode flag alone
leaves `Discovery::Absent` disabled and an unverifiable document denied.

### Test evidence

`cargo test -p zero-halcyon flags::tests` — 15 tests:

| Test | Covers |
|---|---|
| `flag_set_has_exactly_four_keys` | Exactly the four HAL-10 keys, in order, unique. |
| `there_is_no_fifth_flag` | Plausible non-HAL-10 keys do not parse; storage is four slots. |
| `flag_keys_are_case_sensitive` | Exact keys parse; case and whitespace near-misses do not. |
| `parse_reads_every_boolean_and_defaults_missing_to_false` | Four true/false values; empty map is all false. |
| `unknown_keys_are_ignored_and_reported` | Unknown keys are inert and listed in `FlagReport::ignored`. |
| `wrong_typed_known_flag_is_invalid` | String, number, null, array, and object values are `zero.fnd.config_invalid`. |
| `global_config_enables_a_flag` | Global values are effective with no project layer. |
| `absent_global_keeps_every_flag_false` | No global layer → all false, even with a project `true`. |
| `project_config_cannot_enable_a_flag` | Done criterion: each of the four project `true` values stays false and is rejected. |
| `project_true_with_global_false_is_rejected` | True/false mix keeps global true, rejects project-only enables. |
| `project_can_disable_a_global_flag` | Project `false` turns a global `true` off and records it. |
| `project_layer_is_a_complete_snapshot` | Unmentioned project keys are false and disable the corresponding global flags. |
| `project_true_with_global_true_stays_enabled` | Both layers true stays true with no record. |
| `project_false_with_global_false_is_inert` | Both layers false stays false with no record. |
| `flags_do_not_bypass_discovery_or_verification` | Mode flag alone cannot enable absent or unverifiable discovery. |

## Todo sync (T-HAL-07)

`todo_sync.rs` mirrors todos between the local store and the `tkb` task backend.
It is the HAL-11/TODO-09 path: bidirectional, idempotent, version-checked,
offline-tolerant, and conflict-visible, and it runs only when
`halcyon.todo_sync` is effective (T-HAL-06).

### Model

| Type | Fields | Meaning |
|---|---|---|
| `HalcyonTodo` | `id`, `title`, `status`, `updated_ms`, `version` | a todo both sides store; a local create starts at version 1 |
| `TodoStatus` | `open`, `done`, `blocked` | the subset of TODO-02 that `tkb` mirrors |
| `TodoOp` | `op_id`, `todo_id`, `kind`, `payload`, `base_version`, `at_ms` | one idempotent, version-checked change |
| `TodoOpKind` | `create`, `update`, `complete`, `block` | what the op asks for |
| `TodoPayload` | `title`, `status` | the values the op carries |
| `SyncState` | `schema_version`, `last_sync_ms`, `pending`, `applied`, `conflicts`, `todos` | durable sync state |
| `SyncReport` | `Disabled`, `Offline { queued }`, `Synced { .. }`, `Failed` | one sync's outcome |

`SyncState::create_todo`, `update_todo`, `complete_todo`, and `block_todo`
change the local todo and queue the matching op with `base_version` set to the
version the change was made against. `queue_op` accepts a hand-built op;
queueing an `op_id` that is already pending or applied is a no-op, and a full
queue is `zero.fnd.limit_exceeded` rather than a silent drop.

`TkbTodo` is the only backend surface: `pull(since_ms)` returns changed remote
todos and `push(&[TodoOp])` returns `PushOutcome { applied, rejected }`, where a
rejection carries the remote todo that made the op stale. `unavailable_error`
builds the typed `zero.fnd.unavailable` error an offline backend returns. The
trait is the seam; nothing here starts a `tkb` process.

### Version and idempotency rules

- An edit advances the local version to `base_version + 1`, and an accepted op
  advances the remote version to the same value. A `create` has `base_version`
  0 and lands at version 1.
- `sync` filters the pending batch through `applied`. An op id that is already
  applied is skipped, and an empty batch is **not sent**, so a repeated sync
  after success makes no push call and sends no duplicate.
- `tkb` also dedupes by `op_id`, so a retry after a partially observed success
  is safe even when this side has forgotten the id.
- A later edit's `base_version` is the version the user saw, not the newest
  remote version. Push is version-checked: a stale `base_version` is rejected
  with the remote todo and becomes a conflict, never an overwrite.
- `applied` is bounded (`MAX_APPLIED_OPS`, 1024) by dropping the
  lexicographically smallest ids; the backend's dedupe keeps that safe.

### Sync order and the offline queue

`sync(state, backend, flags, now_ms)` checks the flag first. When
`halcyon.todo_sync` is off it returns `SyncReport::Disabled` without calling the
backend. Otherwise:

1. pull remote todos since `last_sync_ms`;
2. merge by id and version — a newer remote todo is adopted unless a queued op
   is based on an older version and title or status diverged, which records a
   conflict and holds the queued change;
3. push pending ops in queue order, skipping applied ids;
4. advance `last_sync_ms` to `now_ms` only after all three succeed.

`zero.fnd.unavailable` or `zero.fnd.offline` from the backend returns
`SyncReport::Offline { queued }`, keeps every op in `pending`, and leaves
`last_sync_ms` alone, so the next sync re-reads the same window and flushes the
queue in order. `SyncState::save_atomic`/`load` keep the queue across restarts.
Any other backend error returns `SyncReport::Failed`; it also keeps the queue,
because the op is removed only after a successful push reports it accepted or
rejected.

### Conflicts and resolution

A conflict is `TodoConflict { todo_id, local, remote, detected_ms }` and is the
T-HAL-07 Done criterion: it is an **item**, not a log line and not a
last-writer-wins overwrite. It is recorded when both sides changed title or
status while the local op was based on an older version, either during the pull
merge or when the backend rejects a stale push. `state.conflicts` is bounded
(`MAX_CONFLICTS`, 64); at the cap the oldest is replaced, and a second detection
for the same todo replaces the stored snapshot instead of duplicating it. A
visible conflict freezes the local side, so re-pulling the same remote change
cannot silently adopt it.

`conflict_items(state)` maps conflicts to panel items sorted by todo id:
`ConflictItem { todo_id, title, status, reference }`, where `title` and `status`
are the local side and `reference` is this anchor plus the todo id.

`resolve_conflict(state, todo_id, choice, now_ms)` removes the conflict and
settles it in one step:

| Choice | Local result | Queued op |
|---|---|---|
| `KeepLocal` | local title and status kept, version `remote.version + 1` | `Update` with `base_version = remote.version` |
| `TakeRemote` | remote todo adopted verbatim | none |
| `Merge` | local title kept, status is the furthest of the two (`done` > `blocked` > `open`), version `remote.version + 1` | `Update` with `base_version = remote.version` |

Resolution is all-or-nothing: it works on a copy and commits only after the new
op is queued and the state validates. An unknown todo id is
`zero.fnd.not_found`. After `KeepLocal` or `Merge` the next sync pushes the new
op, and the backend accepts it because its base is the remote version.

### State file

`SyncState` is JSON at `schema_version: 1`; unknown fields are ignored for
forward compatibility. `validate` enforces the schema
(`zero.fnd.schema_version`), the bounds (`MAX_TODOS` 4096, `MAX_PENDING_OPS`
256, `MAX_CONFLICTS` 64, `MAX_APPLIED_OPS` 1024), the identifier and title
rules, unique pending op ids, and that no op is both queued and applied. `load`
bounds the file at 256 KiB (`MAX_STATE_BYTES`) and re-reads through
`take(cap + 1)`, so a file that grows mid-read is refused. A parse failure or a
shape violation is `zero.fnd.corrupt`; an unsupported schema is
`zero.fnd.schema_version`; an oversized file is `zero.fnd.limit_exceeded`.
`save_atomic` validates, writes a temporary file, calls `sync_all`, and renames.

### Test evidence

`cargo test -p zero-halcyon todo_sync::tests` — 16 tests:

| Test | Covers |
|---|---|
| `two_way_create_update_and_complete_sync` | Local create, update, and complete reach `tkb` at versions 1, 2, 3; a remote-only create is pulled with no push. |
| `repeated_sync_is_idempotent_and_sends_nothing` | A second sync pushes nothing, sends no duplicate op, and leaves the remote version unchanged. |
| `offline_queues_then_flushes_in_order_and_keeps_the_window` | An offline sync keeps both ops queued and leaves `last_sync_ms` at 0; the next sync pushes them in queue order. |
| `both_sides_editing_the_same_todo_surfaces_a_conflict_item` | Both sides edit one todo → one `ConflictItem` with the local title/status and a reference; the pull does not overwrite local; a repeat sync neither duplicates nor pushes. |
| `a_stale_base_version_creates_a_conflict_not_an_overwrite` | A backend rejection of a stale base version records a conflict and leaves the remote todo untouched. |
| `resolving_keep_local_pushes_the_local_side_at_the_remote_version` | `KeepLocal` removes the conflict, bumps to `remote + 1`, and the sync pushes the local side. |
| `resolving_take_remote_adopts_the_remote_side_and_drops_the_change` | `TakeRemote` adopts the remote todo, drops the queued change, and pushes nothing. |
| `resolving_merge_keeps_the_local_title_and_the_furthest_status` | `Merge` keeps the local title and the furthest status (`done`), then pushes it. |
| `a_disabled_flag_never_calls_the_backend` | `halcyon.todo_sync` off → `Disabled`, zero pull/push calls, queue and cursor untouched. |
| `corrupt_and_malformed_state_is_typed_and_state_round_trips` | Bad JSON → `Corrupt`, schema 99 → `SchemaVersion`, oversized → `LimitExceeded`, mismatched id → `Corrupt`; save/load round-trips atomically. |
| `the_queue_and_the_conflict_list_are_bounded` | The queue refuses op 257 with `LimitExceeded`; the conflict list caps at 64 and keeps the newest. |
| `versions_increment_with_every_accepted_op` | Create, update, complete, block leave both sides at version 4 with the last timestamp. |
| `an_offline_pull_does_not_advance_the_window` | A failed pull leaves the cursor at 0; the successful sync re-reads from 0 and records the new cursor. |
| `resolving_an_unknown_conflict_is_not_found` | Unknown todo id → `zero.fnd.not_found`. |
| `queueing_a_duplicate_op_id_is_a_no_op` | Queueing an already-pending op id does not duplicate it. |
| `a_backend_failure_other_than_offline_is_reported_and_keeps_the_queue` | A non-offline backend error returns `Failed` and keeps the queued op. |

## Tests

`cargo test -p zero-halcyon` — Windows run: 114 passed, 0 failed (2026-11-25),
of which 24 are discovery tests, 20 are verification tests, 11 are key tooling
tests, 13 are adapter tests, 15 are behaviour tests, 15 are flag tests (listed in
[Flags](#flags-t-hal-06)), and 16 are todo sync tests (listed in
[Todo sync](#todo-sync-t-hal-07)). The suite contains three Unix-only
discovery tests (unreadable child, unreadable mode file, gate-before-read) and
one Windows-only adapter test (`PATHEXT` ordering), so a Unix build compiles the
same total with 25 discovery and 12 adapter tests.

| Test | Covers |
|---|---|
| `nearest_mode_file_wins_over_an_ancestor` | Parent file at distance 1 beats a grandparent file at distance 2. |
| `an_immediate_child_is_found_and_enabled_when_trusted` | Child candidate is found; its root is trusted and enables. |
| `the_working_directory_beats_a_child_and_an_ancestor` | Distance 0 wins outright over child and ancestor files. |
| `two_immediate_children_are_a_conflict_without_reading_content` | Two child candidates → `Conflict`, `Disabled` with the tie reason; files are metadata-only (Unix makes them unreadable). |
| `a_child_and_the_parent_at_distance_one_conflict` | The chosen tie rule: same-distance child vs parent is a conflict, not a parent-first pick. |
| `a_symlinked_child_is_not_followed` | A linked child does not contribute a candidate (skips when directory symlinks cannot be created). |
| `a_junction_child_is_not_followed` | Windows junction child is excluded via the reparse-point check. |
| `an_untrusted_child_stays_inert` | Child found but only the parent is trusted → `Inert`, not `Enabled`. |
| `absent_everywhere_stays_disabled` | `Disabled` with no reason and no candidates. |
| `a_missing_mode_file_is_absent_not_an_error` | `Absent`, no error. |
| `a_symlinked_mode_file_is_rejected_and_reported` | Link refused with `zero.pol.denied` (skips when file symlinks cannot be created). |
| `a_symlinked_directory_in_the_walk_is_rejected` | Linked ancestor refused (skips when directory symlinks cannot be created). |
| `a_junction_directory_in_the_walk_is_rejected` | Windows junction refused via the reparse-point check. |
| `the_home_boundary_stops_the_walk` | A file above home is never consulted. |
| `a_start_outside_home_is_refused` | Outside-home start is `zero.fnd.invalid_input`. |
| `an_untrusted_workspace_is_inert_even_with_a_valid_file` | Found + untrusted → `Inert`, reason reported. |
| `a_trusted_workspace_with_a_file_enables_the_mode` | Found + trusted → `Enabled`. |
| `a_hostile_repo_cannot_flip_the_gate` | Exact-root trust and the default gate both refuse the hostile repo. |
| `an_oversized_mode_file_is_refused` | `zero.fnd.limit_exceeded`. |
| `a_mode_file_exactly_at_the_limit_is_read` | Boundary is inclusive; zero cap refuses non-empty content. |
| `a_directory_named_like_a_mode_file_is_refused` | Non-regular entry at distance 0 is invalid input. |
| `a_directory_named_like_a_mode_file_in_a_child_is_refused` | Non-regular entry in a child is invalid input. |
| `an_unreadable_child_is_a_typed_error` | Unreadable child is not ignored; `zero.fnd.permission_denied` (Unix). |
| `an_unreadable_mode_file_is_refused` | Permission denied is typed (Unix). |
| `an_untrusted_file_is_never_opened` | Gate precedes reads: unreadable file still yields a clean `Inert`. |
| `a_missing_start_directory_is_a_typed_error` | `zero.fnd.not_found`. |
| `trusted_roots_match_exactly_and_do_not_inherit` | Parent and child do not inherit trust. |
| `a_valid_document_and_pinned_key_verify` | Valid signature, pin, binding, and window produce a `VerifiedMode` with flags, expiry, nonce, and key id. |
| `a_tampered_field_fails` | Changing a flag, project id, expiry, or nonce after signing is denied. |
| `an_unknown_or_wrong_key_id_fails` | Unknown key id is denied; a pinned id pointing at a different key fails the signature. |
| `an_expired_document_is_denied` | `expires_ms <= now_ms` is denied. |
| `a_future_issued_document_is_denied` | `issued_ms > now_ms` (outside skew) is denied. |
| `clock_skew_is_configurable_and_bounded` | 60 s skew accepts 30 s of drift in both directions; 61 s fails; negative and above-limit skew are invalid input. |
| `a_copied_repository_needs_its_own_signed_file` | The original project id verifies; a copied project id is denied by binding (Done criterion). |
| `duplicate_pins_are_rejected` | Two pins with one key id are invalid input. |
| `malformed_pins_are_rejected` | Bad base64, short keys, and non-ASCII key ids are refused; a valid set round-trips through JSON. |
| `a_pin_set_loads_from_a_user_config_file` | `PinSet::load` round-trips a user file, reports `not_found`, and refuses an oversized file. |
| `malformed_signatures_are_rejected` | Bad base64, 63-byte, 65-byte, oversized, and 64-byte non-signatures are refused with the right code. |
| `malformed_documents_are_rejected` | Missing/wrong-typed fields, non-ASCII ids, inverted windows, bad versions, and oversized documents are refused; unknown fields are ignored. |
| `canonical_bytes_match_the_documented_layout` | Byte-for-byte check of the domain prefix, field order, widths, and sorted flags. |
| `canonical_bytes_ignore_flag_order_and_the_signature` | Flag insertion order and the signature field do not change the bytes; length framing distinguishes shifted fields. |
| `an_untrusted_workspace_never_reads_the_mode_file` | A non-JSON file in an untrusted root yields `Inert`, not a parse error: trust precedes reading. |
| `activation_enables_only_after_signature_binding_and_expiry_pass` | `Enabled` for the valid file; tampered, copied-project, and expired files are denied even in a trusted root. |
| `absent_or_conflicting_discovery_stays_disabled_without_verification` | `Disabled` with no read for absent and conflicting discovery. |
| `a_mode_file_without_a_signature_cannot_enable` | Missing embedded signature is invalid input, never `Enabled`. |
| `an_empty_pin_set_verifies_nothing` | Empty pins deny with "no pinned key". |
| `a_pin_set_deserialised_with_duplicates_is_refused_at_use` | Verification refuses to choose when a duplicate id bypassed `PinSet::load`. |
| `keygen_sign_and_verify_round_trip` | Keygen → pin → sign → verify; the signed JSON re-parses and verifies; a tampered signed document is denied. |
| `the_agent_is_denied_every_mutating_action_and_may_verify` | Every `KeyAction` as `Agent`: keygen, sign, pin, rotate, revoke, seal, and unseal are `zero.pol.denied`; verify succeeds. |
| `a_wrong_passphrase_or_a_tampered_seal_is_typed` | Correct passphrase round-trips; wrong passphrase, tampered key id, and tampered ciphertext are `TamperDetected`; empty and oversized passphrases are typed. |
| `a_sealed_key_survives_a_file_round_trip` | Sealed envelope save/load preserves the key id and unseals; an oversized file is refused. |
| `pin_unpin_rotate_and_revoke_persist` | Pin, rotation, revocation, un-revoke, and unpin round-trip through the pin file; the new key verifies, the old one does not; a revoked id cannot be re-pinned until un-revoked. |
| `a_revoked_key_is_rejected_even_while_pinned_and_the_pin_file_holds_no_secret` | Revocation wins over a still-present pin, is idempotent, persists, and no private bytes reach the pin file. |
| `a_copied_repository_and_a_wrong_project_still_fail` | A valid signature bound to another project id is denied as a copied repository. |
| `signing_does_not_change_the_canonical_bytes` | `canonical_bytes` is identical before and after signing; the signature stays outside the signed bytes. |
| `key_ids_are_stable_and_labels_are_honoured` | Derived ids are deterministic per public key and differ across keys; labels are exact and validated; unsealing preserves the id. |
| `private_key_bytes_never_appear_in_debug_or_errors` | `KeyPair`/`SealedKey`/`SignedMode` `Debug`, error messages, the pinned public key, the pin file, the sealed envelope, and the signed mode document contain no private scalar. |
| `a_bad_schema_or_malformed_pin_file_is_refused` | Unknown pin-file schema is `zero.fnd.schema_version`; duplicate revocations and duplicate pins are refused. |
| `a_missing_binary_shows_install_guidance` | Missing `tkb` yields `executable: None` and guidance naming the binary, minimum, `PATH`, and docs; the probe is not called (T-HAL-04 Done). |
| `every_adapter_guidance_names_the_binary_and_minimum` | All three adapters produce guidance containing the binary, package, display name, minimum version, install text, and docs anchor. |
| `a_found_compatible_binary_has_no_guidance` | Found `tkb 1.2.3` parses, probes once on the detected path, reports `Compatible`, and has no guidance. |
| `a_too_old_binary_explains_the_minimum` | `joker 0.9.0` reports `TooOld`, keeps the found/min pair, and guidance says to upgrade. |
| `an_unparseable_version_is_reported_with_guidance` | Non-version output is `Unparseable` with the raw string, the format rule, and the minimum. |
| `versions_parse_with_a_prefix_and_suffixes` | `v` prefixes, prerelease/build suffixes, and malformed two- or four-part versions behave as documented. |
| `reported_output_is_searched_for_a_version` | `tkb 1.2.3`, `joker version: 2.0.1`, `v0.9.0`, and `epb/1.4.0` are found in probe output; text with no version is refused. |
| `path_order_decides_which_executable_is_used` | Two `PATH` entries with the same binary: the first wins and is the only probed path. |
| `a_non_executable_file_is_ignored` | Unix ignores a non-executable `tkb`; Windows ignores `tkb.txt` and a bare `tkb`. |
| `windows_pathext_decides_which_extension_is_used` | `PATHEXT` order picks `.CMD` or `.EXE`; removing the first falls through to the next (Windows). |
| `a_probe_error_shows_guidance_instead_of_failing_detection` | A timed-out probe keeps the adapter present with unknown version and guidance containing the reason and minimum. |
| `negotiation_uses_an_explicit_requirement` | A stricter explicit requirement turns `Compatible` into `TooOld`; relaxing it restores `Compatible` and clears guidance. |
| `detection_does_not_execute_the_binary` | The scripted probe is the only version run; the fixture (a marker-writing script on Unix) is never executed. |
| `a_run_without_a_tkb_check_is_refused` | A handover with no check record is `zero.pol.denied` with "tkb check required"; `finish` refuses and does not stamp the run (T-HAL-05 Done criterion). |
| `a_passing_check_and_a_handover_finish` | A green check plus a handover finishes; the report carries the evidence and the run records `finished_ms`. |
| `a_failed_check_then_a_success_is_allowed` | A failed check refuses; a later successful check replaces it and finishes. |
| `a_failed_check_with_no_retry_is_refused` | A failed check with no retry refuses and leaves the run unfinished. |
| `an_unresolved_high_gap_is_refused` | An unresolved high gap refuses and the message names the gap id. |
| `only_info_gaps_can_be_waived` | Warn and high gaps refuse a waiver; resolving them and waiving an info gap finishes. |
| `a_resolved_gap_and_an_info_waiver_are_allowed` | Resolved and info-waived gaps are not blocking; a second resolve is a no-op. |
| `a_direct_gate_is_refused_and_recorded` | `Route::Direct` and `Route::Epb` gate calls are denied, appended to `gates`, and block `can_finish`. |
| `a_gate_through_joker_is_allowed` | Gates through `Route::Joker` and the `JokerRoute` seam are accepted and finish. |
| `a_direct_endpoint_is_refused_and_recorded` | A direct endpoint call is denied, recorded, and blocks `can_finish`. |
| `an_endpoint_through_epb_is_allowed` | Endpoints through `Route::Epb` and the `EpbRoute` seam are accepted and finish. |
| `a_missing_handover_is_refused` | A green check with no handover refuses and does not finish. |
| `a_malformed_handover_is_refused` | Empty or control-character summaries and evidence lines are `zero.fnd.invalid_input`; an oversized summary is `zero.fnd.limit_exceeded`; nothing is stored. |
| `finish_is_idempotent` | A second `finish` returns an equal report and keeps the first `finished_ms`. |
| `a_finished_run_refuses_new_evidence` | Check, gap, resolve, gate, endpoint, and handover writes after finishing are denied; the evidence and gate verdict are unchanged. |

`cargo clippy -p zero-halcyon --all-targets -- -D warnings` — clean.

### Windows caveat

Creating file or directory symlinks on Windows needs developer mode or elevation.
On a host without it, the three symlink tests (file, walk directory, child
directory) print a skip line and return. The two junction tests still exercise
reparse-point rejection because `mklink /J` needs no elevation. Unix CI runs every
refusal path with real symlinks.

## Scope boundary

HAL-01's structural model, HAL-02/HAL-03/HAL-05's verification path, the
HAL-03/HAL-04 user-facing key tooling, HAL-07/HAL-13 adapter detection and
version negotiation, and HAL-08/HAL-09's behaviour rules are complete:
nearest-wins discovery, symlink refusal, trust before any read, canonical-byte
Ed25519 verification against user-pinned keys, strict or skew-tolerant
issuance/expiry, binding to `projectId` with no path binding, a user-only
keygen/sign/pin/rotate/revoke surface with Argon2id + AES-256-GCM sealed private
keys, `PATH` detection plus a per-adapter minimum with typed guidance instead of
an error, a native workflow that records gaps, accepts gates only through
`joker` and endpoints only through `epb`, and refuses to finish without
`tkb check` and a handover, the four HAL-10 flags with global-only enabling
and project-only disabling, and two-way todo sync with `tkb` that is
version-checked and idempotent, queues while offline, and surfaces conflicts as
panel items. The agent can verify but cannot sign or rotate.
