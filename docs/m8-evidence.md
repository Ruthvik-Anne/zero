# M8 evidence

M8 covers the mesh, teleport, and self-improvement. The identity slice is
implemented; the rest of the milestone is open.

## Performance budgets — T-PERF-01 (done)

The benchmark harness now covers five dimensions (T-PERF-01, TST-07):
`startup_ms`, `frame_us`, `attach_ms`, `memory_mb`, and `session_bytes_1k`.
Startup/frame/attach keep the existing warm-up + median method; memory is a
process-wide counting-allocator peak over a 20k-entry session scan (portable
Windows/Linux, median of 3); session size is exact serialized JSONL bytes per
1,000 `Event` records. `bench/baselines.json` records all five under one
tolerance; `--check` fails when measured > baseline × tolerance, and `--record`
writes all five. Synthetic over-budget and boundary tests cover the gate logic.

| Test area | Evidence |
|---|---|
| Done criterion | Budgets recorded and enforced; `cargo run -p xtask -- bench --check` is green. |
| Coverage | 9 xtask tests: all five dimensions, over/within/exclusive boundary, schema. |
| Method | Memory is a Rust-heap proxy, not OS RSS; session bytes exclude disk overhead. |

Baselines: startup 296.52 ms, frame 3891.28 µs, attach 629.65 ms, memory
16.39 MiB, session 184,890 B/1k (×4 gate). Commands: `cargo test -p xtask`,
`cargo clippy -p xtask --all-targets -- -D warnings`, `bench --check`.

## Network impairment — T-TST-05 (done)

`zero-web` now has a deterministic network impairment suite (TST-05). A seeded
`NetworkModel` (loss bps, latency, jitter, partition) produces
Delivered/Lost/Partitioned outcomes per request. `SimulatedEngine` implements the
real search-engine trait, mapping loss/partition to `unavailable` and latency
over timeout to `timeout`, and drives `ResilientSearch`/`EnginePolicy` with an
explicit clock. Six scenarios cover baseline, 10% loss with retry recovery,
sustained loss opening the breaker, latency within/over timeout, and full
partition; one failing engine never removes a healthy engine's results or fails
the search. The 25-cell NAT matrix is recorded as an external `zero-mesh`
traversal gate rather than re-implemented, and a report without it is not green.

| Test area | Evidence |
|---|---|
| Done criterion | 15 impairment tests + 1 doc test; suite report is green. |
| Scenarios | Retry recovery, breaker open/threshold/no-further-calls, latency, partition. |
| Determinism | Same seed replays identical outcome sequences; external NAT gate recorded. |

Commands: `cargo test -p zero-web impairment` (15 tests), `cargo clippy
-p zero-web --all-targets -- -D warnings`. Request-granularity only (no burst
correlation/bandwidth/reordering); the NAT gate is a recorded test name, not a
compile-time link.

## Conformance gate — T-TST-08 (done)

`zero-mcp` now has a release conformance gate (TST-08, TST-10). It loads every
MCP conformance fixture, runs the existing runner, requires both revisions, and
fails on any exchange failure; on the protocol side it parses every
`protocol/golden/*.json` projection into a `zero_types::proto::Frame`, checks the
canonical projection round-trips, per-frame encode/decode, `decode_all` over the
stream, and the `.bin` sibling when present. `GateReport` records
mcp_fixtures/mcp_revisions/protocol_fixtures/ok/failures, and `assert_gate`
returns a typed error listing missing classes or failures. Negative tests cover
empty inputs, one revision, unknown revision, malformed/failing MCP fixtures,
corrupt protocol frames, and a missing protocol class.

| Test area | Evidence |
|---|---|
| Done criterion | `tests/release_gate.rs` runs under `cargo test -p zero-mcp` (CI gate) and asserts ok. |
| Coverage | 13 MCP exchanges across both revisions; 8 protocol frames incl. `.bin` siblings. |
| Negatives | 8 gate tests: every missing/malformed class flips ok with a reason. |

Commands: `cargo test -p zero-mcp` (232 tests), `cargo clippy -p zero-mcp
--all-targets -- -D warnings`. The protocol gate needs the workspace checkout;
the TypeScript reader remains gated by `protocol/ts/check.mjs`.

## Security suites — T-TST-07 (done)

`zero-agent` now has a consolidated agent-side security suite (TST-07). Seven
prompt-injection fixtures cover ignore-previous, destructive calls,
system-prompt disclosure, role-play, fake tool schemas, envelope breakout, and
`<system>` tags; untrusted sources (tool output, fetched web, MCP results,
memory, file content) are wrapped as data, and a scripted policy decision is
unchanged before/after wrapping. Secret leakage seeds `sk-`, `ghp_`, `oc_sk_`,
and PEM values through five sink framings (transcript, log, audit, telemetry,
kernel) and asserts the shared redaction engine removes them. SSRF and zip-slip
are recorded as external `zero-web` suite names rather than duplicated.
`run_security_suites`/`assert_release_secure` produce a typed gate report.

| Test area | Evidence |
|---|---|
| Injection | 7 fixtures wrapped/labelled; policy decision unchanged; fake schema/breakout rejected. |
| Leakage | 20 cases (5 sinks × 4 secret classes) redacted. |
| Release gate | External SSRF/zip-slip recorded; any local failure flips `ok`. |

Commands: `cargo test -p zero-agent security_suite` (12 tests), `cargo clippy
-p zero-agent --all-targets -- -D warnings`. Sink checks use the shared redactor
and framing seam; concrete writers keep their own tests; SSRF/zip-slip are
gated by the workspace CI run.

## Fault injection — T-TST-06 (done)

`zero-doctor` now has a fault catalogue that exercises every stable error code
(TST-06). `fault_for` is exhaustive over `ErrorCode::ALL` (75 faults), each with
a deterministic injector and a fixture class; eight faults drive real doctor
checks (messy config, missing key, stale lock, corrupt journal, low disk, busy
port, broken workers, expired auth), and the rest are generic inject/report
faults. `run_faults`/`diagnose_faults` inject every code, assert the produced
code matches, run triage/playbook checks, and report exercised/missing/
mismatched; `assert_all_codes_exercised` returns a typed failure otherwise.
`diagnose_faults` writes fixtures only under a unique temp scratch and leaves the
caller's root untouched.

| Test area | Evidence |
|---|---|
| Done criterion | `run_all` exercises 75/75 codes with empty missing/mismatched/failures. |
| Fixtures | 8 check-bound faults drive their real checks; generic faults still code/triage/playbook-checked. |
| Safety | Scratch-only fixtures; deterministic injection; caller root untouched. |

Commands: `cargo test -p zero-doctor faults` (5 tests), `cargo clippy
-p zero-doctor --all-targets -- -D warnings`. Most codes are necessarily
generic; workers-serialization intentionally asserts check failure rather than a
code mapping.

## Mesh transport — T-MESH-07 (done)

`zero-mesh` now has the datagram session-stream prototype and a recorded
decision (MESH-07, MESH-01). `DatagramIo` is the carrier seam; a deterministic
simulated network drops/reorders/duplicates; `SessionStream` fragments with
sequence headers, bounded windows, acks, retransmission, and per-fragment
BLAKE3 hashes, while the reassembler suppresses duplicates, buffers
out-of-order fragments within bounds, and delivers a contiguous prefix. The
prototype moves 160 representative session JSONL events over a lossy/reordering
carrier byte-identically and still parses as 160 lines. ADR 0002 chooses
datagram streams plus a small reliable session layer over a userspace TCP/IP
stack, because MESH-01 forbids TUN/admin/VpnService; a userspace stack is
reconsidered only if arbitrary IP traffic becomes a requirement.

| Test area | Evidence |
|---|---|
| Done criterion | `a_session_jsonl_stream_moves_byte_identically` with loss, reorder, duplicates. |
| Robustness | 16 transport tests: corruption, oversize, timeout, window bound, duplicate suppression. |
| Decision | `docs/decisions/0002-mesh-transport.md` linked from `docs/mesh.md`. |

Commands: `cargo test -p zero-mesh` (246 tests), `cargo clippy -p zero-mesh
--all-targets -- -D warnings`. Prototype is in-process; no congestion control,
pacing, RTT, multiplexing, or crypto (carrier supplies it); corruption ends the
stream; fragment size is configured.

## Android pairing — T-AND-01 (done)

`zero-daemon-app` now models Android pairing (AND-01, AND-02). An offer carries
a 32-byte entropy secret, deterministic QR/short code, bounded TTL, and no
account/service/endpoint fields; Debug and the public view redact secrets.
Pairing requires the exact offer id, full secret, matching code, live window,
single use, one device id, and a biometric gate. A copied/replayed code, another
device, a wrong/expired code, or biometric denial all fail with
`zero.pol.denied` without consuming the offer — a stolen **short code** cannot
pair. The host-only `allow_without_biometric` flag is the sole bypass. Paired
tokens and previews are redacted; lock-screen previews show name/status only.
No socket/account code exists in the module.

| Test area | Evidence |
|---|---|
| Done criterion | 14 pairing tests: stolen code/second device refused; replay refused; valid code pairs once. |
| Biometrics | Denial aborts without consuming; host-only bypass tested. |
| Exposure | No public endpoint/account fields; previews/Debug redact secrets. |

Commands: `cargo test -p zero-daemon-app` (52 tests), `cargo clippy
-p zero-daemon-app --all-targets -- -D warnings`. A full QR payload is a bearer
credential until first use (single-use/TTL/binding mitigate); typed pairing needs
the full grouped secret.

## Parity audit — T-PAR-03 (done)

`zero-arch` now audits every Part 1, Part 2, and Part 8 item (PAR-03,
PAR-01..04). A tolerant parser extracts 133 items (49/42/42) and
`data/parity.json` maps each to a state (Implemented/Partial/Deferred/
OutOfScope) with a non-empty reason and refs. `parity::check` rejects missing
rows, `Unassessed`, unknown or duplicate ids, empty reasons, and Implemented
rows without refs. The distribution is 31 Implemented, 61 Partial, 40 Deferred,
1 OutOfScope, **0 Unassessed**. `docs/parity.md` is generated from the data, and
CI's docs job runs `xtask check-parity`; `parity-doc --write` regenerates it.
Negative tests cover every failure class; the real data passes.

| Test area | Evidence |
|---|---|
| Done criterion | 133/133 items assessed; `check-parity` OK. |
| Integrity | 10 parity tests + 2 integration: missing/unassessed/unknown/duplicate/empty/no-refs. |
| Generated doc | `docs/parity.md` freshness test; docs index row. |

Commands: `cargo test -p zero-arch` (28 tests), `cargo clippy -p zero-arch
--all-targets -- -D warnings`, `xtask check-parity`. Part 2 "Implemented" means
the doctrine is adopted, not a runtime feature; one broad old CLI item is
deliberately OutOfScope.

## Android session control — T-AND-02 (done)

`zero-daemon-app` now has the Android session controller (AND-02, AND-03). A
`MeshSessionClient` seam exposes list/transcript/prompt/steer/queue/cancel/diff
with no sockets. `AndroidSessionController` opens a session only after list
validation, pages transcripts with per-entry cursors, and sends prompts (default
Queue) or steering with strict bounds, returning deterministic views. A full
flow test asserts the exact call order list → open → transcript → prompt →
steer → queue → diff → cancel (the Done criterion). Offline/timeout keep their
codes with retry guidance; a stale cursor maps to `zero.ses.cursor_expired` and
forces a snapshot retry; unknown sessions are `not_found`; diffs/queue/pages are
bounded and ordered.

| Test area | Evidence |
|---|---|
| Done criterion | `android_session_a_full_flow_drives_every_action_in_order`. |
| Errors/paging | 12 tests: cursor expiry, unknown session, offline mapping, per-entry cursors. |
| Bounds | Prompt/steer/id/page/queue/diff caps; deterministic ordering. |

Commands: `cargo test -p zero-daemon-app` (64 tests), `cargo clippy
-p zero-daemon-app --all-targets -- -D warnings`. The mesh client is a contract
(zero-mesh must implement it); the prompt frame lacks a delivery-mode field, so
FollowUp/Queue are distinguished only in the phone's ack; offline input is not
persisted here (T-AND-04).

## Windows installer — T-INST-02 (done)

`installer/windows.ps1` is a PowerShell 5.1+ non-admin installer (INST-02..06).
It defaults to `%LOCALAPPDATA%\Zero`, refuses Program Files/System32/relative
prefixes without elevation, verifies the required SHA-256 before writing, takes
an exclusive lock with stale-PID recovery, treats identical binaries as
idempotent and refuses different ones without `-Force`, stages and atomically
renames (re-hash before move), and updates only the **user** PATH with
`-UpdatePath` (exactly once, never machine PATH). `-NoPath`, `-WhatIf`,
`-Uninstall` (binary+lock only, keeps data) and clean `finally` cleanup are
implemented; exit codes are 0/2/3. `crates/zero-cli` validates the script and
builds the command (9 tests). A new `installer (windows)` CI job installs into a
temp prefix, executes, and asserts idempotence, checksum/conflict/lock refusals,
force, PATH rules, and uninstall.

| Test area | Evidence |
|---|---|
| Done criterion | New Windows CI job performs a clean install; the exact job body passed locally (39 assertions). |
| Safety | Checksum-first, exclusive lock/stale recovery, staged rename, no elevation, user PATH only. |
| Uninstall | Binary+lock removed, data kept, rerun safe. |

Commands: `cargo test -p zero-cli windows_install` (9 tests), `cargo clippy
-p zero-cli --all-targets -- -D warnings`, local PowerShell end-to-end. Installs
one downloaded executable; archive/signature/service wiring remains release
tooling; PID reuse can look like a live lock.

## Unix installer — T-INST-03 (done)

`installer/unix.sh` is a POSIX `sh` installer for Linux/macOS (INST-03..06).
It defaults to `$HOME/.local`, refuses unwritable/root/relative prefixes without
elevation, verifies the required SHA-256 before any write (sha256sum or
`shasum -a 256`), takes a PID lock with stale-lock recovery, treats an identical
binary as idempotent and refuses a different one without `--force`, installs
atomically (temp + chmod 755 + re-hash + mv), and cleans up via EXIT/INT/TERM
traps. `--update-path` appends the PATH line once (`.profile`), `--no-path`
prints nothing, `--uninstall` removes only the binary+lock and keeps data. No
prompts; TTY state is restored only if changed. `crates/zero-cli` validates the
script and builds the command (9 tests). A new CI job runs the real install,
idempotence, checksum/conflict/lock refusals, force, PATH/no-path, and uninstall
on ubuntu-latest and macos-15.

| Test area | Evidence |
|---|---|
| Done criterion | CI `installer (unix)` job performs clean container/macOS installs; WSL dash run passed locally. |
| Safety | Checksum before write, lock/stale handling, atomic mv, traps, non-admin refusal. |
| Uninstall | Binary+lock removed, data kept. |

Commands: `cargo test -p zero-cli unix_install` (9 tests), `cargo clippy
-p zero-cli --all-targets -- -D warnings`, WSL end-to-end. macOS is CI-only;
archive download/decode and manifest verification remain release tooling.

## Documentation set — T-DOCS-01 (done)

A task-oriented docs set now covers install, configuration, and troubleshooting
(PAR-04, DEL-11/12, KRN-08, WEB-20). `docs/install.md` covers prerequisites,
OS notes, source build, first run, doctor, projects, login, services, update/
uninstall, offline notes, and a verification checklist — with unwired verbs
explicitly marked planned. `docs/configure.md` documents file locations,
precedence, providers/models, modes/approvals, MCP/tools, credentials/secrets,
projects, mesh, teleport, monitors, budgets, telemetry, and review, plus a
topic→page index. `docs/troubleshooting.md` is symptom→diagnosis→fix, doctor
first, linking errors/playbooks for provider, kernel, locks/journals, mesh, MCP,
secrets, and update failures. `docs/README.md` now indexes all three and the
reference set (corrupted rows fixed, missing pages added).

| Test area | Evidence |
|---|---|
| Checks | `check-docs` OK (479/277/38; 24 crates/23 edges); relative-link/anchor check OK. |
| Docs tests | `cargo test -p zero-arch --test docs` 3 passed; CLI suites 9+2 passed. |
| Honesty | Stub verbs (install/update/uninstall/login/service/repair) marked planned; config filename discrepancy documented. |

Known follow-up: `zero-cli`'s `unix_install` test was failing due to concurrent
work at the time; the install checklist uses the passing CLI suites. The config
path discrepancy (`.zero/config` written vs `config.toml` documented) is called
out for the loader task.

## Teleport failure matrix — T-TEL-08 (done)

`zero-mesh` now exercises the four teleport failure fixtures (TEL-08, TEL-10,
TEL-13, TEL-14). **Interrupted**: a real bundle checkpoint resumes and restores
byte-identically, with a second restore a no-op. **Unreachable source**: an
injected probe refuses with `unavailable`, writes nothing, and the local
snapshot still verifies with unchanged hash/bytes. **Forced takeover**: an
expired source lease hands off (generation 1→2), the new holder writes/restores,
stale write/restore/release are refused, and a stale cursor forces a snapshot.
**Return trip**: A→B→A path remap + re-sign with two device keys restores
byte-identically, and the first-leg generation is refused. `TripMatrixReport`
and `assert_all_four` are green.

| Test area | Evidence |
|---|---|
| Done criterion | 7 trip-matrix tests, one per fixture behavior; all four present and passing. |
| Interrupted | Checkpoint resume + verify + restore byte-identical; idempotent second restore. |
| Takeover/return | Stale holder refused; A→B→A restores identity/bytes; old generation refused. |

Commands: `cargo test -p zero-mesh trip` (16 matches; 7 trip tests), `cargo
clippy -p zero-mesh --all-targets -- -D warnings`. No sockets/latency/partial
streams; the unreachable fixture refuses rather than waits; lease store is
in-memory.

## Vault transfer — T-TEL-07 (done)

`zero-mesh` now moves a vault as ciphertext with exactly one target unlock
(TEL-07, SEC-11, TEL-05). `VaultEnvelope` carries opaque AES-256-GCM ciphertext,
Argon2id KDF params, nonce/AAD, and no plaintext/key fields (Debug shows
ids/lengths only). `seal_vault` uses a random salt/nonce and zeroizes secrets;
`unlock_vault` allows **one successful unlock per envelope**, refuses a second
even with the right passphrase, prompts (`zero.pol.ask`) on a wrong/missing
passphrase without returning plaintext, and reports tamper on damaged
ciphertext. An approved-transfer capability is bound to one envelope id with
expiry; mismatch/expiry are typed. `wrap_for_transfer`/`receive` move the
envelope through the encrypted transfer; the relay sees ciphertext only and the
passphrase never crosses it.

| Test area | Evidence |
|---|---|
| Done criterion | 11 vault tests: second unlock refused; target prompts once; no silent decrypt. |
| Crypto | Wrong passphrase prompts, tamper fails, approval binding/expiry enforced. |
| Transfer | Ciphertext-only through sealed bundle; Debug/errors redacted; new envelope resets unlock. |

Commands: `cargo test -p zero-mesh` (223 tests; 226 Unix), `cargo clippy
-p zero-mesh --all-targets -- -D warnings`. Dependencies reuse workspace
aes-gcm/argon2. Approval is an in-memory bearer capability; one-unlock state is
in-memory; zeroization is best-effort.

## Portability — T-TEL-06 (done)

`zero-mesh` now remaps teleported state across operating systems (TEL-06,
TEL-12/13/14). `PathMap` rewrites Windows drive/UNC ↔ POSIX roots with separator
and case-only source handling, refuses paths outside the source root or with
`..` escapes, and handles spaces/non-ASCII. `remap_text` rewrites only absolute
path tokens inside a transcript/config and reports substitutions/skips.
`remap_snapshot` remaps Session/Kernel/Manifest, passes binary artifacts through
unchanged, and re-signs with the target device key (invalidating the source
signature intentionally). Kernel rebuild plans are OS-specific and never
contain Windows paths; tool preflight reports missing tools with guidance, and a
no-git directory passes when git is not required — Windows→Linux and no-git runs
pass (the Done criterion).

| Test area | Evidence |
|---|---|
| Done criterion | 19 portability tests: drive/UNC/backslash/case remaps both ways; no-git pass/refuse. |
| Snapshot | Re-sign with target key; source key refused; binary blobs unchanged. |
| Preflight | Missing-tool guidance; `can_run` refuses when Python is not probed. |

Commands: `cargo test -p zero-mesh` (212 tests; 215 Unix), `cargo clippy
-p zero-mesh --all-targets -- -D warnings`. Text matching is heuristic; no
case-collision merge or line-ending conversion; live processes/PTYs/sockets do
not move.

## Lease fence and resume — T-TEL-05 (done)

`zero-mesh` now fences writes with leases and generations (TEL-05, TEL-10/11,
FS-10). A lease names the resource, holder, generation, and expiry; `fence` and
`assert_can_write` refuse a stale generation, `handoff` increments the generation
and changes holder, and `handoff_if` is a compare-and-set with a single winner.
`renew` is holder-only, `release` refuses a stale holder, and expired leases are
invalid. Resume uses `ResumeCursor { generation, sequence }`: an older generation
forces a snapshot (no events across a fence), the current generation resumes
events after the cursor, sequences stay monotonic, and effects are never
replayed. After handoff the source cannot write (the Done criterion).

| Test area | Evidence |
|---|---|
| Done criterion | `a_stale_holder_cannot_write_after_handoff`; both fence and assert_can_write refuse. |
| Handoff | 12 fence tests: CAS single winner, renew/release rules, expiry. |
| Resume | Older generation -> snapshot; current -> events; monotonic/no effect replay. |

Commands: `cargo test -p zero-mesh` (193 tests), `cargo clippy -p zero-mesh
--all-targets -- -D warnings`. This is a value model: the store must serialize
and commit the CAS winner; `restore`/`transfer` are not yet wired to leases.

## Conflict-safe restore — T-TEL-04 (done)

`zero-mesh` now restores a verified bundle without clobbering conflicts (TEL-04,
TEL-07, TEL-08). A `RestorePlan` is validated fully before writing (safe relative
paths, no `.zero` entries, no duplicate/nested paths, hash/size consistency,
contained symlink targets, modes, caps). Identical paths are skipped; a
conflicting file is **staged under `.zero/restore-staging/<bundle>/` and not
overwritten** (the Done criterion); type conflicts are staged/refused; even the
explicit `overwrite_existing` opt-in records the conflict. Unix modes and
recorded symlinks are applied, unrecorded destination symlinks are never
followed, and transcript/kernel/schedules/children components are written
atomically. A failed apply rolls back paths it created without touching
pre-existing conflicts; `adopt` is the explicit reviewed replacement.

| Test area | Evidence |
|---|---|
| Done criterion | `a_conflicting_file_is_staged_and_not_overwritten`; identical skipped; type conflict staged. |
| Preflight | 15 restore tests: escapes, duplicates, mode bounds, symlink containment, caps. |
| Components/adopt | Components restored; adopt re-checks the existing hash; rollback on failure. |

Commands: `cargo test -p zero-mesh` (181 tests; 184 Unix), `cargo clippy
-p zero-mesh --all-targets -- -D warnings`. `overwrite_existing` is not
reversible; Windows refuses recorded symlinks; no lease/fence yet.

## Encrypted transfer — T-TEL-03 (done)

`zero-mesh` now transfers bundles end-to-end encrypted (TEL-03, TEL-06, TEL-09).
Sealing uses an ephemeral X25519 key, HKDF-SHA256 over the ephemeral+recipient
public keys and bundle id, ChaCha20-Poly1305 per chunk with HKDF-derived unique
nonces, and AAD binding bundle id, chunk index, and plaintext BLAKE3 hash; the
manifest is encrypted with its own AAD. Opening checks the recipient id, derives
the same key, decrypts/authenticates the manifest and each chunk, verifies every
plaintext hash, and only then reassembles via bundle verification — a corrupted
chunk fails verification (the Done criterion) and nothing is materialized.
`retain_until_verified` never deletes on failure; cleanup is explicit, guarded,
and only after a verified transfer. Secrets and sealed envelopes have redacted
Debug; errors carry no key material.

| Test area | Evidence |
|---|---|
| Done criterion | `a_corrupted_chunk_fails_verification`; tampered tag/order/truncation fail. |
| Crypto | 17 transfer tests: wrong recipient, nonce uniqueness, AAD binding, manifest/id checks. |
| Retention | Failure keeps source+staging; cleanup only after verify, with guards. |

Commands: `cargo test -p zero-mesh` (169 tests), `cargo clippy -p zero-mesh
--all-targets -- -D warnings`. Dependencies: x25519-dalek 2.0.1,
chacha20poly1305 0.10.1, hkdf 0.12.4 (reuse curve25519/aead/sha2 stacks).
Metadata (hashes/sizes/ids) is visible to a relay; no sender authentication,
replay protection, or streaming yet.

## Teleport bundle — T-TEL-02 (done)

`zero-mesh` now builds content-addressed, resumable bundles (TEL-02, TEL-04,
TEL-05). Files are split into fixed-size chunks named by BLAKE3, globally
deduped, and recorded in a canonical manifest with safe relative paths,
sums/caps, exclusions, and a content-derived bundle id. `BundleWriter` writes
chunks as `<hash>`/`<hash>.part` and fsyncs an atomic `checkpoint.json` after
each chunk; `resume` reconciles the checkpoint with disk, rewrites missing or
corrupt chunks, and writes only the remainder — an interrupted bundle resumes
(the Done criterion). `BundleReader::verify` checks every chunk hash/length and
per-file reassembly; `materialize` verifies first, refuses unrecorded symlinks
and differing overwrites, skips identical files, and applies Unix modes.
Exclusions are sorted/deduped and always reported; secret-like paths are
refused.

| Test area | Evidence |
|---|---|
| Done criterion | Interrupted after two chunks, reload checkpoint, write only the rest, verify + materialize byte-identical. |
| Chunking | 16 bundle tests: split/reassemble, global dedupe, manifest hash/tamper, unsafe paths. |
| Reader | Missing/corrupt chunk -> `zero.tru.tamper`; materialize refuses overwrite/symlink; modes. |

Commands: `cargo test -p zero-mesh` (152 tests), `cargo clippy -p zero-mesh
--all-targets -- -D warnings`. Resume is local to the bundle directory; chunks
are plaintext until TEL-03; checkpoint rewrite is per-chunk (O(n²) bytes for
very large bundles).

## Teleport snapshot — T-TEL-01 (done)

`zero-mesh` now creates a signed, seven-component snapshot (session, kernel,
artifacts, goals, schedules, ledger, manifest) from caller-supplied opaque bytes
(TEL-01, TEL-03, TODO-07). The manifest is deterministically ordered, hashes
each blob with BLAKE3, records exclusions, derives a content id, and is signed
with the device key; `verify` checks schema, required components, the exact blob
set, hashes, id, and signature. `restore` verifies before writing, stages under
`.zero/teleport`, writes components with `create_new`+fsync+rename, publishes by
directory rename, writes `snapshot.json` last, refuses symlinked/different
targets, and re-verifies an identical existing snapshot. Secret-like component
labels are refused. `inspect` gives the UI a summary. Debug redacts blobs and the
signature.

| Test area | Evidence |
|---|---|
| Done criterion | Create/restore all seven components on the same device; restored bytes equal; manifest last. |
| Tamper | 17 tests: tampered blob/signature, missing component, wrong set -> refused, nothing written. |
| Safety | Secret-like labels refused; caps; no partial writes; id deterministic. |

Commands: `cargo test -p zero-mesh` (136 tests), `cargo clippy -p zero-mesh
--all-targets -- -D warnings`. Same-device only; bundle/transfer/encryption are
TEL-02/03; secret handling is a label check, not a content scan.

## Traversal — T-MESH-04 (done)

`zero-mesh` now plans NAT traversal deterministically (MESH-04, MESH-10). Five
NAT kinds and an injectable STUN probe feed a 25-cell planner: Open/FullCone
destinations are direct, Restricted/PortRestricted pairs hole-punch with
simultaneous send, and any Symmetric side with a non-public destination selects
TCP/443 fallback when enabled or `RelayRequired` with a rendezvous explanation
when not. Attempts/timeouts are bounded, the punch is an injectable seam, and
every unreachable outcome carries `RENDEZVOUS_REQUIRED` with
`needs_rendezvous = true` ("cross-network connectivity needs at least one
reachable node"). No sockets/timers live in the module (source-scan test).

| Test area | Evidence |
|---|---|
| Done criterion | 25-cell golden NAT matrix with 10 Direct, 8 HolePunch, 7 TCP fallback/relay cells. |
| Failure | Symmetric+Symmetric without fallback -> RelayRequired + rendezvous explanation. |
| Bounds | 18 tests: config validation, punch attempts, timeout, scripted punch. |

Commands: `cargo test -p zero-mesh` (119 tests), `cargo clippy -p zero-mesh
--all-targets -- -D warnings`. The transport carrier, STUN client, and real TCP
dial are later; the symmetric rule is deliberately conservative.

## Join UX — T-MESH-06 (done)

`zero-mesh` now has the one-action join flow (MESH-06, MESH-07). `one_action_offer`
issues a short-lived owner-signed token and renders both the QR payload and
short code from it; `JoinOffer`'s Debug hides payload/code/secret and `validate`
re-derives the encodings and checks times. `join_with_payload`/`join_with_short_code`
check the owner root, offer integrity/expiry, token signature/expiry/use, and
id/secret membership; then `Membership::join` consumes the token and records a
pending join. The device is not a member until `approve_pending`; expired,
reused, tampered, or foreign codes are typed errors with guidance. `JoinTimeline`
records milestones and `within_target` proves a simulated join under 60 s (and
an over-target case). The module has no sockets/account fields.

| Test area | Evidence |
|---|---|
| Done criterion | Simulated offer→scan→approve at 25.5 s is within target; 61 s is reported over. |
| Join | 14 join tests: QR/short code, idempotent pending, approval, expiry/reuse/tamper refusal. |
| Secrecy | Offer Debug hides payload/code/secret; closed serde field set. |

Commands: `cargo test -p zero-mesh` (101 tests), `cargo clippy -p zero-mesh
--all-targets -- -D warnings`. The under-a-minute result uses caller clocks; no
QR image/camera or transport wiring yet; single-use state is per membership.

## Quorum, revocation, partitions — T-MESH-08 (done)

`zero-mesh` now enforces delegate quorum writes and revocation propagation
(MESH-08, MESH-09, LCK-10). `DelegateSet` carries a threshold, delegates, and an
optional owner root; `check_quorum` binds each vote to the exact
`(state_version, update hash)`, rejects duplicate/non-delegate/wrong-hash/bad-
signature votes, and refuses below threshold — a partitioned minority cannot
write, while the owner root or a reached threshold can. Owner-signed revocation
sets are verified, older versions ignored, equal/newer versions unioned;
`drop_revoked` removes peers from discovery/presence and state/relay/update
paths refuse the revoked device, so revocation propagates across two simulated
nodes. `can_write` refuses without signed state or in a minority partition and
never writes silently.

| Test area | Evidence |
|---|---|
| Done criterion | Minority partition refuses writes; revocation applied on node B drops and refuses the revoked device. |
| Quorum | 16 partition tests: threshold, duplicate/hash/version/signature, owner path, future-dated. |
| Revocation | Signed set, older ignored, newer union, two-node propagation, healed partition. |

Commands: `cargo test -p zero-mesh` (87 tests), `cargo clippy -p zero-mesh
--all-targets -- -D warnings`. `DelegateSet` adds an optional owner key; equal-
version revocations union; revocation ids are permanent.

## Ciphertext relay — T-MESH-05 (done)

`zero-mesh` relays only opaque ciphertext through approved nodes (MESH-05,
MESH-06). `RelayEnvelope` carries ids, ciphertext, nonce, AAD, TTL, and size —
no plaintext or key field — and `Debug` prints ids/sizes only. `RelayPolicy` is
default-deny (empty relay allowlist, 64 KiB, 5 min, membership required);
`RelayNode::forward` denies an unapproved or non-member relay and non-member or
revoked source/destination, and refuses oversize/expired/future/invalid
envelopes. The relay clones the envelope unchanged and has no decrypt path;
`relay_chain` re-checks every hop and refuses loops. `Endpoint::seal/open`
demonstrates the boundary with a test-only keyed stream/MAC, proving the relay
cannot read while the endpoint can; production transport crypto remains
T-MESH-07.

| Test area | Evidence |
|---|---|
| Done criterion | The relay forwards opaque bytes and cannot decrypt; the endpoint can open. |
| Approval | 14 relay tests: unapproved/revoked relay, source, or destination refused; default-deny. |
| Bounds | Size/TTL/expiry/nonce/AAD validation; chain loop refusal; same bytes across hops. |

Commands: `cargo test -p zero-mesh` (71 tests), `cargo clippy -p zero-mesh
--all-targets -- -D warnings`. Metadata (ids/AAD/sizes/timing) is visible to the
relay; no cross-call replay ledger or per-hop TTL decrement.

## Presence and cost — T-MESH-09 (done)

`zero-mesh` now exposes presence only as online/reachable plus link class and
power (MESH-13, MESH-14). A sleeping host is offline (both by explicit sweep and
by freshness re-check in relay selection), offline forces unreachable, and the
public view is per-device only — no fleet aggregation or location. The cost
policy defers on metered links when configured, defers below a low-battery
threshold unless charging, and requires charging for relay when configured;
unknown power or link defers conservatively. Relay candidates are online,
reachable, fresh, and cost-allowed in deterministic order.

| Test area | Evidence |
|---|---|
| Done criterion | A sleeping host is offline and never a relay candidate, even without an explicit sweep. |
| Cost | 12 tests: metered pause, low battery, charging exception, relay charging, unknown power. |
| Exposure | Public view exposes exactly id/online/reachable/link; no fleet view. |

Commands: `cargo test -p zero-mesh` (57 tests), `cargo clippy -p zero-mesh
--all-targets -- -D warnings`. Unknown power is an explicit variant; deserialized
percentages must be validated by the caller.

## Authenticated discovery — T-MESH-03 (done)

`zero-mesh` now accepts LAN peers only after authentication (MESH-03, MESH-12,
MESH-14). `PeerAnnounce` carries device id, addresses, port, nonce, times, and an
Ed25519 signature over a deterministic canonical encoding (addresses sorted and
deduped). `accept` checks membership version, structure, approved membership,
revocation, key/id binding, signature, issue/expiry, and nonce replay; any
failure returns `Ignored { reason }` without adding or updating a peer — an
unauthenticated peer is ignored (the Done criterion). Presence exposes only
online/reachable state and `sweep` marks a sleeping peer offline. The mDNS TXT
record uses the fixed `_zero._udp.local` service and a closed, bounded field set;
unknown fields such as `account` are rejected.

| Test area | Evidence |
|---|---|
| Done criterion | Unauthenticated/unknown/revoked peers are ignored with a reason and no table change. |
| Integrity | 17 discovery tests: tampered/expired/replayed announce, key binding, older state version. |
| Presence | Sweep marks offline; a fresh announce revives; TXT round-trip; no service/account. |

Commands: `cargo test -p zero-mesh` (45 tests), `cargo clippy -p zero-mesh
--all-targets -- -D warnings`. No multicast socket, relay/query, or owner
re-verification inside `accept` yet; nonce history is per-process.

## Mesh signed state — T-MESH-02 (done)

`zero-mesh` now signs and versions the membership snapshot (MESH-02, MESH-09,
MESH-11). `MembershipState` carries version/epoch, devices, revoked ids, names,
timestamp, signer, and signature over a deterministic length-prefixed encoding
(sorted maps/sets, signature excluded). Only the owner root public key verifies;
a device key signature is rejected, so a stolen device cannot evict or revoke
others — the Done criterion. `apply` accepts exactly the next version, treats
identical same-version content as AlreadyApplied, flags same-version divergence
as Conflict, rejects rollbacks, and lets a valid higher snapshot replace a lower
one. The owner record cannot be revoked/evicted, names are signed and unique
case-insensitively, and the unsigned version-0 placeholder accepts exactly one
owner-signed v1 snapshot.

| Test area | Evidence |
|---|---|
| Done criterion | A device-signed eviction/revocation is rejected; only owner-signed updates apply. |
| Versioning | 15 state tests: next-version apply, rollback rejection, AlreadyApplied, same-version conflict, higher version wins. |
| Integrity | Tampered state/signature and duplicate names/ids rejected; owner self-revocation refused. |

Commands: `cargo test -p zero-mesh` (28 tests), `cargo clippy -p zero-mesh
--all-targets -- -D warnings`. No replication loop, threshold delegates, fork
merge, or owner-root rotation yet; those remain MESH-08/09/15.

## Mesh identity — T-MESH-01 (done)

`zero-mesh` now has an Ed25519 device identity (`device_id` = BLAKE3 of the
public key, private bytes never exposed), short-lived single-use join tokens
signed by the owner root, a short code/QR payload, and local membership with
pending joins. `join` verifies and consumes the token, records a pending
request, and refuses membership (`zero.pol.denied`) until the owner approves —
the Done criterion. Owner-only approve/revoke, old-key-signed rotation with
`rotated_from`, and revocation are implemented; a revoked device cannot rejoin
or rotate back without a fresh owner approval.

| Test | Evidence |
|---|---|
| Done criterion | `an_unapproved_device_cannot_join`: join returns denied; `is_member` false until approval. |
| Tokens | Expired, reused, and tampered tokens refused; short code/QR round-trip. |
| Rotation/revocation | Rotation needs the old key and changes the id; revoked devices cannot rejoin/rotate back. |
| Secrecy | Private key bytes never cross Debug; membership serde round-trip. |

Commands: `cargo test -p zero-mesh` (13 tests), `cargo clippy -p zero-mesh
--all-targets -- -D warnings`.

## Promotion and rollback — T-SI-03 (done)

`zero-agent` now gates self-improvement promotion (SI-03, SI-06, SI-07, SI-09).
An immutable core protects the evaluator, loop, promotion, audit, policy, and
secrets sources; a candidate touching them is refused (`zero.pol.denied`) after
`..`/absolute/drive/NUL/control normalization, with symlink-component checks
under a canonical root. The diff is deterministic and bounded with a
`zero.si-diff.v1` hash; a human gate must approve that exact hash, and
`ApprovedPromotion` has private fields and no Deserialize, so only
`approve_promotion` can mint it (no self-approval). Apply snapshots existing
files, writes atomically, and rolls back in reverse on failure; rollback
preflights every hash and refuses a changed target (`zero.fnd.tamper`) unless
forced.

| Test area | Evidence |
|---|---|
| Done criterion | A candidate touching `eval_suite.rs`/the immutable core is refused. |
| Gate | 13 tests: missing/denied/hash-mismatch approval refused; self-approval impossible by type. |
| Apply/rollback | Apply+reverse restores bytes; changed target refuses without partial restore; escapes/symlinks refused. |

Commands: `cargo test -p zero-agent promotion` (13 tests), `cargo clippy
-p zero-agent --all-targets -- -D warnings`. Apply-failure rollback may leave
empty directories; Windows junctions rely on canonical containment.

## Improvement loop — T-SI-02 (done)

`zero-agent` now runs the self-improvement loop (SI-02, SR-17, SI-08): a
proposal with a bounded change set and evidence refs moves through Execute →
Verify → Capture → Distil → Evaluate → Promote → Reenter. The executor gets a
fresh scratch root per attempt with path containment; verification is injected;
capture stores per-file path/bytes/BLAKE3 evidence; evaluation runs the held-out
suite for baseline and candidate and compares them. Acceptance requires no
regressions and at least one improvement; a regression is rejected with the
offending task recorded; any stage failure stops the loop with the stage named;
attempts are bounded and a re-entry seed carries the next attempt. Promotion is
pure and always still requires the SI-03 human gate; nothing mutates the real
agent.

| Test area | Evidence |
|---|---|
| Done criterion | 13 loop tests: one accepted candidate (baseline fails a task, candidate passes) and one rejected candidate (candidate regresses). |
| Stages | Order, verifier failure before evaluate, no promotion without evaluate, bounded attempts. |
| Safety | Path-safe change sets, evidence required, evaluation/version mismatch fails. |

Commands: `cargo test -p zero-agent self_improve` (13 tests), `cargo clippy
-p zero-agent --all-targets -- -D warnings`. Verification and executor are
trusted in-process seams; no real build; cross-call attempt budget is the
caller's.

## Held-out evaluation suite — T-SI-01 (done)

`zero-agent` now has a versioned, held-out evaluation suite (SI-01, SI-05,
SI-10). The suite carries tasks with fixture files and checks (exit code, file
contains/absent, output contains), a schema/suite version, unique ids, and
size/count bounds. Visibility is split by type: candidates receive a
`PublicSuite` with prompt/fixture only, never the checks or scoring key.
`load_suite` requires a trusted root (canonical, no symlink, bounded size) and
verifies a BLAKE3 suite hash; stale/tampered/unknown versions are refused. The
offline runner writes each fixture into a fresh scratch workspace (path-safe),
runs an injected candidate, evaluates the checks, and returns a deterministic
report plus a baseline/candidate regression delta. The module contains no
network calls (source-scan test).

| Test area | Evidence |
|---|---|
| Done criterion | The suite runs offline; a scan proves no network API in the module. |
| Visibility | Public view has no checks/expected text; runner receives only `PublicTask`. |
| Checks | 16 tests: all four check kinds pass/fail; fixture escapes refused; caps. |
| Integrity | Tampered/stale hash, unknown schema, duplicate ids refused. |

Commands: `cargo test -p zero-agent eval_suite` (16 tests), `cargo clippy
-p zero-agent --all-targets -- -D warnings`. The split is by type/passing, not a
filesystem sandbox; process isolation/timeouts belong to the runner.

## Desktop shell — T-DSK-01 (done)

`zero-daemon-app` now models the desktop shell (features 6.1, ACT-01). A
`ShellConfig` must use a **system** webview (WebView2, WKWebView, WebKitGTK);
`EngineSource::Bundled` is refused with `zero.pol.denied` ("no bundled browser
engine"), the UI bind must be loopback (reusing the web-app validation), the
title is bounded, and the webview kind must match the platform — mismatches are
`Unsupported` with install guidance, never a hidden fallback.
`DesktopShell::prepare` creates the local web UI, issues a one-time token, and
returns a `ShellPlan` with the token-free URL, a token snapshot, and the action
registry; `action_registry()` matches the shared-UI palette order exactly. No
process is launched (the host opens the system webview), and the launch line
hides the token.

| Test area | Evidence |
|---|---|
| Done criterion | Bundled engine refused; the shared action registry matches the shared UI entries/order. |
| Binding | 10 shell tests: non-loopback refused; platform engine enforced; title bounds. |
| Safety | Structural scan finds no bundled engine or process launch; token hidden in logs. |

Commands: `cargo test -p zero-daemon-app` (38 tests), `cargo clippy
-p zero-daemon-app --all-targets -- -D warnings`. Engine presence is not probed
at runtime; opening the webview is host work.

## Shared UI states — T-DSK-02 (done)

`zero-daemon-app` now has one shared UI model for TUI, desktop, web, and Android
(ACT-03, TUI-14, SEC-03). `SharedUiState` carries the palette (bounded filter
query/entries/results, deterministic category→title→id order), mode, approval,
secret prompt, and status. `render(surface)` uses the TUI host modal for the
terminal, a JSON view for web/desktop, and the same JSON plus a mobile flag for
Android. Secret prompts go through `SecretPrompt::view`, so the field is bullets
only and a non-host-issued prompt is refused; the value never appears.
`compare_surfaces` checks palette content/order, approval id/action/reason,
secret masking/id/tag/reason, mode/plan flag, status, modal presence, and the
Android flag, listing per-surface differences. The model is state-only and never
executes palette/approval/secret actions.

| Test area | Evidence |
|---|---|
| Done criterion | 9 shared-UI tests: scripted TUI-vs-JSON comparison matches, and an injected mismatch is detected. |
| Parity | Palette order, approval, masked secret, mode, status, Android flag. |
| Safety | Host-only secret prompt; no action execution; value absent everywhere. |

Commands: `cargo test -p zero-daemon-app` (28 tests), `cargo clippy
-p zero-daemon-app --all-targets -- -D warnings`. The TUI has no hash slot and
clips at 60 columns; JSON keeps raw text; one host modal slot draws the secret
first when both are pending.

## Local web app — T-WEBUI-01 (done)

`zero-daemon-app` now serves the UI locally only (ACT-16). `WebUiConfig` refuses
`0.0.0.0`, `::`, LAN/public addresses, IPv4-mapped loopback, and hostnames; the
bound address is re-validated after bind, so there is no public listener (the
Done criterion). A 32-byte OS-entropy token (64 hex) is strictly single-use,
expires, compares without early exit, and is redacted from Debug and logs; the
snapshot is inlined into the authorized page so one token fetches one complete
page. The server serves fixed inline HTML plus `/api/actions` JSON, accepts GET
only, caps requests at 8 KiB (413 before auth) and responses at 256 KiB, never
touches the filesystem, and rejects path tricks. Origin is exact-match when
configured, otherwise same-origin via Host; `Origin: null` and mismatches are
403 without spending the token.

| Test area | Evidence |
|---|---|
| Done criterion | Every non-loopback bind is refused; the OS-returned address is re-validated. |
| Token | 15 webui tests: one-use, expiry, foreign token, reuse 401, redaction. |
| Serving | HTML/actions JSON, origin mismatch, oversize request, shutdown, no filesystem. |

Commands: `cargo test -p zero-daemon-app` (19 tests), `cargo clippy
-p zero-daemon-app --all-targets -- -D warnings`. Plain HTTP on loopback, one
connection at a time, no event stream; second-machine unreachability is proven
structurally.

## Retention — T-OBS-03 (done)

`zero-fs` now sweeps expired data through the trash (OBS-03, OBS-06). Policies
are per class (traces, metrics, logs, audits, sessions, artifacts, teleport
staging) with age, byte quota, and `keep_min`; `sweep` resolves only class dirs
under the data root (refusing symlinks/escapes), expires old entries while
keeping the newest minimum, trims the oldest over quota, and moves every removal
to `TrashService` — never a raw delete. Zero-owned data roots are handled through
the documented trash exemption while name-based protection (`.git`, `.zero`,
journals, credentials, policy) is never bypassed. Dry-run reports without
changes; a second run is idempotent; trash failures are reported with the
original retained.

| Test area | Evidence |
|---|---|
| Done criterion | The expired item is found in the OS trash list, not deleted. |
| Policies | 14 retention tests: age, keep_min, byte quota oldest-first, dry-run/idempotence. |
| Safety | Protected paths untouched; symlinked class dir refused; trash failure reported. |

Commands: `cargo test -p zero-fs retention` (14 tests), `cargo clippy
-p zero-fs --all-targets -- -D warnings`. Quota is floor-limited by keep_min;
one top-level entry per class; sizes best-effort.

## Local tracing — T-OBS-02 (done)

`zero-store` now records a local end-to-end turn trace (OBS-02, OBS-04). Spans
carry stable trace/span ids, parent, kind (turn/provider/tool/kernel/frame/
policy/scheduler), start/end, attributes, and events; validation bounds
names/attrs/events/spans/depth, strips control characters, rejects secret-ish or
message-body attribute keys, and refuses duplicate ids, cycles, orphans, and
backwards timing. `turn_trace()` scripts a completed turn with provider, tool,
and frame spans under the turn root, and `assert_turn_covers()` verifies those
kinds, parentage, completion, and parent/child timing — the Done criterion.
Traces persist as append-only JSONL (schema version, fsync, 4 MiB cap, 0600 on
Unix, newest snapshot wins) and render deterministically as a text tree or JSON.
No network/export code.

| Test area | Evidence |
|---|---|
| Done criterion | A scripted turn trace spans provider, tool, and frame under the turn root. |
| Validation | 12 trace tests: cycles/orphans/duplicates, secret keys, control chars, torn line. |
| Storage | Append/load round-trip, summaries, deterministic render/text/JSON. |

Commands: `cargo test -p zero-store trace` (12 tests), `cargo clippy
-p zero-store --all-targets -- -D warnings`. Timestamps are caller-supplied;
each append writes a full snapshot; no OpenTelemetry/cross-process propagation.

## Local metrics — T-OBS-01 (done)

`zero-store` now has a local metrics registry and dashboard (OBS-01, OBS-03,
OBS-08). Seven closed metrics (queue depth, latency histogram, 429s, retries,
cost, requests, errors) are thread-safe; labels are bounded (32 B key/64 B
value/4 per series/64 series) and unknown or wrong-kind names are rejected.
Latency uses fixed buckets with bucket-upper-bound p50/p95/p99, and snapshots
are deterministic (`BTreeMap`, sorted labels) with Prometheus and JSON
renderings. `Dashboard` reads the same values as text/JSON, and snapshots persist
atomically with a schema version so a dashboard can read after restart. No
network or telemetry code.

| Test area | Evidence |
|---|---|
| Done criterion | `dashboard` lines/JSON read the registry values; snapshot round-trip after restart. |
| Concurrency | 12 metrics tests: 8-thread increments sum exactly; bucket percentiles. |
| Bounds | Label caps, invalid names, schema refusal; deterministic renders. |

Commands: `cargo test -p zero-store metrics` (12 tests), `cargo clippy
-p zero-store --all-targets -- -D warnings`. Percentiles are bucket bounds;
registry is process-local; label-cap overflow rejects new series.

## Service units — T-INST-05 (done)

`zero-cli` now renders and manages service units (INST-05, INST-09). Specs are
validated per target platform (absolute paths, bounded args/env, no control
characters/`..`, user only where valid, secret-looking env names refused), then
rendered deterministically as a systemd unit, a Windows service wrapper config,
or an XML-escaped launchd plist, with restart policy and log redirection. A
`ServiceManager` seam performs install/start/stop/status/uninstall; `lifecycle`
starts, reports status, stops, and reports the final status on all three
platforms, stopping at the first failure without retries. Production source has
no process/socket/unsafe calls.

| Test area | Evidence |
|---|---|
| Done criterion | Scripted start/stop/status lifecycle on systemd, Windows service, and launchd. |
| Rendering | 19 tests: required fields, escaping, restart policy, per-platform path rules. |
| Safety | Secret env names, relative paths, invalid users refused; failed start reported once. |

Commands: `cargo test -p zero-cli service` (19 tests), `cargo clippy
-p zero-cli --all-targets -- -D warnings`. Units are text only; installation
into system paths and `sc.exe`/`launchctl` are host work behind the seam.

## Kernel bootstrap — T-INST-06 (done)

`zero-cli` now bootstraps the kernel dependencies (INST-06, INST-07). A
`BootstrapPlan` lists uv/Python/ipykernel/pyzmq/wheels with version ranges,
HTTPS URLs, and SHA-256 digests; the default plan is deliberately marked with
placeholder digests/URLs so it cannot be used for a real install. `bootstrap`
enforces offline mode strictly: only the local cache is used, and a missing
component fails with guidance naming the exact seed without any downloader call
— offline bootstrap from a populated cache succeeds (the Done criterion).
Online, cache hits are reused, misses are downloaded, SHA-256 verified before
use, and stored atomically; tampered downloads install nothing. Installs use safe
names and no-overwrite, are idempotent, and return PATH entries without secrets.
A probe reports Python/ipykernel readiness.

| Test area | Evidence |
|---|---|
| Done criterion | `offline_bootstrap_from_a_populated_cache_succeeds` with zero downloader calls. |
| Integrity | 16 bootstrap tests: bad checksum/cache tamper refuse, no partial install. |
| Plan | Duplicate/bad digest/non-HTTPS/credential URL/limit validation; unsafe names. |

Commands: `cargo test -p zero-cli bootstrap` (16 tests), `cargo clippy
-p zero-cli --all-targets -- -D warnings`. Components are single verified files;
archive/env layout, PATH mutation, cache eviction/locking, and real version
probes remain installer work.

## Update and rollback — T-INST-04 (done)

`zero-cli` now verifies and applies updates atomically with rollback (INST-04,
INST-08, INST-10). An update artifact carries a signed release plus an in-memory
payload tree; `verify_update` checks the embedded-key Ed25519 signature, target
match, canonical SHA-256/size, rejects downgrades unless allowed, and writes
nothing. `apply_update` cleans/refuses foreign staging, probes disk, stages with
`create_new` + read-back hashes, snapshots the install with a hashed manifest,
swaps per file via temp+rename, writes `.zero-version`, re-hashes, runs the
injected health check, and on any post-snapshot failure restores the snapshot
and reports that rollback happened — a corrupted update rolls back cleanly (the
Done criterion). `rollback` restores explicitly and removes files not in the
snapshot.

| Test area | Evidence |
|---|---|
| Done criterion | Health-check failure and mid-swap failure restore the tree byte-for-byte. |
| Verification | 17 tests: bad hash/signature/target, downgrade refusal, path escapes, staging cleanup. |
| Apply | Idempotent version file, disk probe seam, backup manifest, explicit rollback. |

Commands: `cargo test -p zero-cli update` (17 tests), `cargo clippy
-p zero-cli --all-targets -- -D warnings`, rustdoc `-D warnings` clean. No real
archive decoding; per-file swap is not whole-tree atomic; crash recovery,
parent fsync, and install lock remain installer work.

## Packaging and SBOM — T-INST-01 (done)

`zero-cli` now builds a signed release manifest and SBOM (INST-01, INST-11,
INST-02). `ReleaseManifest` carries version/git sha/channel, per-target
artifacts (name, SHA-256, bytes), and an SBOM component list, all in a
deterministic canonical form with a manifest hash. Ed25519 signs the canonical
bytes; `verify_embedded` checks the manifest with the embedded (placeholder)
public key — the Done criterion. Bad signatures, wrong keys, duplicate targets,
malformed hashes, and invalid names are refused. Artifact naming covers the six
targets with correct extensions. `sbom_from_cargo_lock` parses name/version
pairs, dedupes/sorts, and reports licences as "see package metadata" rather than
inventing them. I/O is strict JSON with atomic save; no network or private key
in production code (structural test).

| Test area | Evidence |
|---|---|
| Done criterion | `embedded_key_verifies_a_signed_manifest`; tampered manifest/signature/wrong key fail. |
| Naming/SBOM | 10 tests: six-target naming, lockfile SBOM parse/dedupe, strict JSON. |
| Secrecy | No private-key derivation outside tests; no network; no PEM in the crate. |

Commands: `cargo test -p zero-cli packaging` (10 tests), `cargo clippy
-p zero-cli --all-targets -- -D warnings`. The embedded key is a placeholder for
release tooling; archive build/upload is separate installer work.

## Sandboxed computer use — T-MM-03 (done)

`zero-mm` now models a sandboxed computer-use boundary (MM-03, MM-05, MM-06,
MM-10). `SandboxSpec` requires a scratch root, an exact host:port network
allowlist, no host mounts, and no device access; invalid specs (host mounts,
device access, bad display/runtime, wildcards) are rejected before launch.
`SandboxSession` runs through an injectable backend and routes actions through
the computer-use policy (allow/ask/deny; destructive never bypasses).
`check_escape` blocks and records host-path access, non-allowlisted network,
device access, mount requests, and host clipboard reads with
`zero.pol.denied` — and never forwards them to the runner (the Done criterion).
Scratch writes are canonically contained; a report lists blocked attempts versus
allowed actions. No process/socket/hypervisor API appears in the module.

| Test area | Evidence |
|---|---|
| Done criterion | `host_filesystem_access_is_blocked`; escape attempts recorded and `performed` empty. |
| Boundary | 17 tests: allowlist exact match, device/mount/clipboard blocked, scratch traversal blocked. |
| Lifecycle | Launch/execute/stop typed; runner failures typed; deterministic session id. |

Commands: `cargo test -p zero-mm` (90 tests), `cargo clippy -p zero-mm
--all-targets -- -D warnings`. The backend is a seam: OS/packet enforcement,
runtime clock, and TOCTOU-safe mounts are the backend's responsibility.

## Live computer use — T-MM-04 (done)

`zero-mm` now gates live-host computer use as a high-risk class (MM-04, MM-05,
MM-11, MM-07). Live input/clipboard/launch/close actions are High risk (live
screenshots Medium); Manual mode asks for **every** live action including
screenshots (the Done criterion), Plan denies, and SemiAuto/Auto ask unless the
exact `<kind>[:<app>]` is allowlisted — a destructive action always asks.
Sandbox actions allow low/medium and ask for destructive; Plan allows only
screenshot/clipboard read. Clipboard reads on the live host always ask. Prompts
carry the action/target/app/reason but never typed or clipboard text (only
`text_len`), and the model never executes anything.

| Test area | Evidence |
|---|---|
| Done criterion | `manual_mode_asks_for_every_live_host_action` iterates every action kind, including screenshots. |
| Matrix | 13 tests: plan deny, allowlist, destructive ask, sandbox allow, clipboard ask. |
| Safety | Allowlist is exact/case-sensitive with no wildcards; no text in prompts; data only. |

Commands: `cargo test -p zero-mm` (73 tests), `cargo clippy -p zero-mm
--all-targets -- -D warnings`.

## Recordings and verification — T-MM-05 (done)

`zero-mm` now records verification flows with artifacts (MM-05, MM-08, MM-09).
A `Recording` holds chapters with labeled screenshots (BLAKE3 content hash,
bounded size/labels), assertions, and shortcut flags; `build` assigns
deterministic ids, creates an implicit intro chapter, orders chapters/shots
monotonically, and derives pass/fail from expected == actual without aborting on
a failing assertion. `verify` re-evaluates every assertion and reports failed
ids/missing shots. `write_artifacts` stages and atomically publishes
`manifest.json`, `report.md`, `shots/*.png`, and `FAILURES.md` for failing flows,
with bounded sizes and path-safe names; `read_manifest` re-validates schema,
paths, and hashes. Passing and failing flows both produce artifacts (the Done
criterion), with failure ids in the summary.

| Test area | Evidence |
|---|---|
| Done criterion | 8 recording tests: passing flow artifacts and failing flow artifacts + FAILURES.md. |
| Integrity | Unique ids, monotonic times, caps, path safety, manifest tamper/round-trip. |
| Verify | Every assertion re-evaluated; failed ids reported. |

Commands: `cargo test -p zero-mm` (60 tests), `cargo clippy -p zero-mm
--all-targets -- -D warnings`. No screenshot/PNG codec (caller bytes); manifest
read does not re-hash shot files; publish is rename, not fsync.

## Preprocessing — T-MM-02 (done)

`zero-mm` now preprocesses attachments while retaining originals (MM-02..04).
`OriginalStore` content-addresses bytes via the shared blob store; `read_full`
verifies hash and length and returns the untouched original (the Done
criterion). Image plans downscale (never upscale) and tile with guaranteed
overlap and edge alignment under a 64-tile cap; audio plans use
`min(source, target)` rate and contiguous bounded chunks; video samples strictly
increasing, evenly spread timestamps under a 64-frame cap. Processor, OCR,
transcriber, and frame-sampler traits are injectable; derived OCR/transcript
text is marked untrusted. All plans are deterministic and bounded.

| Test area | Evidence |
|---|---|
| Done criterion | Store, preprocess, then `read_full` returns bytes identical to the original. |
| Plans | 12 tests: downscale, overlap tiles, audio chunks, video sampling, bounds. |
| Safety | Original never mutated; OCR/transcript marked untrusted; caps enforced. |

Commands: `cargo test -p zero-mm` (52 tests), `cargo clippy -p zero-mm
--all-targets -- -D warnings`. No real codecs in this slice; geometry is
caller-supplied; derived text is not PII-redacted yet.

## Local CPU model consent — T-MM-06 (done)

`zero-mm` now gates local model use on explicit consent (MM-06, MM-13, MM-14).
`LocalModelRequest` validates name/licence/purpose/source, modality, disk and
memory bounds; `ConsentPrompt` deterministically renders model, modality,
licence (name + URL), required disk/memory, exact purpose, and source.
Declining leaves the modality `Unavailable` with an explanation naming the model
and confirming no download occurred — the Done criterion. Granting enables only
that model/modality and carries a `DownloadPlan`; no download, install, checksum,
disk probe, or hardware detection happens here. `CapabilityRegistry::require`
refuses a declined modality with `zero.fnd.unavailable` and the explanation.

| Test area | Evidence |
|---|---|
| Done criterion | Decline -> unavailable with model name + "no download" explanation. |
| Gate | 10 consent tests: grant one modality, others unchanged, re-consent revokes, invalid fields refused. |
| Safety | Structural scan proves no network/install/download API; deterministic prompt. |

Commands: `cargo test -p zero-mm` (40 tests), `cargo clippy -p zero-mm
--all-targets -- -D warnings`. Licence syntax is checked, not authenticated;
consent state is in-memory/serializable; one model per modality.

## Multimodal inputs — T-MM-01 (done)

`zero-mm` now models multimodal input routes (MM-01, MM-02). Attachments are
inline bytes, an absolute path inside a canonical allowed root, or an http(s)
URL without userinfo; MIME/modality consistency, per-modality size caps, strict
base64 with declared-size equality, and path/symlink checks are enforced. The
`@` grammar covers `@file:`, `@image:`, `@url:`, and bare `@name`, with
boundary-aware scanning (emails stay text), ambiguity errors, and candidate
lists for unresolved refs. Typed blocks (text/image/audio/video/document/tool
result) validate ids/text/control characters and build in order, dedupe content,
and record the reference mapping. Accounting counts per modality and lists
unknown dimensions (pixels/duration/pages/bytes) instead of guessing.

| Test area | Evidence |
|---|---|
| Done criterion | 27 integration fixtures: one per input route (inline/path/URL, audio/video/document, all `@` forms). |
| Validation | Path escape/`..`, URL userinfo, oversize, wrong MIME, malformed base64, unknown/ambiguous refs refused. |
| Accounting | Deterministic per-modality totals; unknown dimensions listed. |

Commands: `cargo test -p zero-mm` (30 tests), `cargo clippy -p zero-mm
--all-targets -- -D warnings`. `@url:` is metadata only (no fetch); paths with
spaces need direct attachment; chunking and image/pixel metadata arrive with
T-MM-02.

## M8 closure

M8 is closed: mesh identity/state/discovery/relay/presence/transport, teleport snapshot/bundle/transfer/restore/fence/portability/vault, and self-improvement are implemented and recorded above. Evidence for M9/M10 slices also present in this file is superseded by docs/m9-evidence.md and docs/m10-evidence.md.

Run [45722626227](https://github.com/Ruthvik-Anne/zero/actions/runs/45722626227) on 1801d291: all 13 jobs successful.
