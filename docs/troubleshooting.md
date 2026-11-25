# Troubleshooting

Diagnose before changing anything. Every stable error has one code, one
remediation line, and one playbook; this page maps the common symptoms to those
surfaces.

## First three commands

| Order | Command | What it covers |
|---|---|---|
| 1 | `zero doctor` | This installation: data, config, state, and cache directories plus the SQLite store. Exit 1 means a check failed. |
| 2 | `zero-doctor` | The independent diagnosis: 13 checks including config, key, workers, kernel, auth, network, mesh, ports, disk, locks, journals, and MCP. Runs with the daemon dead. |
| 3 | `zero doctor --json` / `zero-doctor --json` | The same reports for a script or a bug report. |

Run `zero-doctor` from the project root, or set `ZERO_DATA_DIR` to the data root
it should inspect. It exits `0` even when checks fail: the report is the result.
A fresh checkout has no `.zero/`, so `keys` fails and the file-backed checks
warn; that is expected, not a broken install.

Then find the exact code in [`errors.md`](errors.md). Every code has a playbook
with symptoms, ordered steps, an escalation point, and the same remediation line
as the binary; see [`doctor.md`](doctor.md#playbooks). Triage reads only the
code, never the message text.

## Symptom table

| Symptom | Likely code | Diagnose | Safe fix |
|---|---|---|---|
| Doctor reports a failing directory or store | `zero.fnd.io`, `zero.fnd.permission_denied` | The failing check names the path. Check free space and write permission. | Fix ownership or permissions on that directory, or rerun with `--data-dir` on a writable root. Do not run the whole product as administrator/root to bypass it. |
| `zero doctor` cannot open the store | `zero.fnd.corrupt`, `zero.fnd.schema_version` | Check `store: ...` in the report; a schema newer than the build is refused. | Restore the store backup, or use a build that supports the schema. Never delete `zero.db` to "reset" a store you need. |
| A provider call fails immediately | `zero.prv.auth` | `zero login <provider>` currently returns `zero.fnd.unavailable`; the verb is not wired. | Use the local adapter when driving the library, or wait for the login wiring. Do not paste a token into config or a shell profile. See [`credentials.md`](credentials.md). |
| No provider is reachable | `zero.fnd.offline`, `zero.prv.unavailable` | `zero-doctor` network check; confirm the host is online and the base URL is correct. | Reconnect, or use Ollama/LM Studio. Local file work is unaffected. |
| Model refuses tools | `zero.prv.no_tools` | The adapter probes `/api/show`; the model does not advertise `tools`. | Pick a tool-capable model, or disable tools for that turn. See [`providers.md`](providers.md). |
| Kernel cell fails to start | `zero.fnd.unavailable` | `python -m ipykernel --version`; `ZERO_PYTHON` selects the interpreter; check the kernel state in `zero-doctor`. | Install Python 3 and `ipykernel`, or point `ZERO_PYTHON` at the right interpreter. The bootstrap plan is modelled but its default manifest is a placeholder; do not treat it as a download. See [`kernel.md`](kernel.md). |
| Kernel call times out or loses output | No stable `zero.*` code on the normal path | The execution reports a timeout, partial output, and the lost cell; a restart replays successful history. | Retry. Do not assume the lost cell ran twice; it is reported, not replayed. |
| A port is already in use | `zero.fnd.io` | `zero-doctor` ports check; identify the listener. | Stop the process that owns the port, or use another port. The local web UI defaults to loopback and port `0`, so the OS chooses a free port. |
| A file or session is locked | `zero.fs.locked`, `zero.ses.lease_held` | `zero-doctor` locks check. A lock older than 24 hours counts as stale; more than five stale locks fail. | Confirm no worker is alive first. Wait for the lease holder, attach to the running worker, or stop it. Removing a lock while a writer is alive can corrupt the file. |
| A journal line does not parse | `zero.ses.corrupt`, `zero.fnd.serialization` | `zero-doctor` journals check names the file and line. | Keep the file. Restore the backup or export, then start a new session. Do not truncate or hand-edit the log. |
| An interrupted command may have run | `zero.ses.command_uncertain` | The journal has a `begin` without a result. | Check the side effect manually. The command is not replayed. See [`sessions.md`](sessions.md). |
| Disk is low | `zero.fnd.resource_exhausted` | `zero-doctor` disk check: below 5 GiB warns, below 1 GiB fails. | Free space, or move the data root with `--data-dir` to a larger volume. Retention moves expired Zero-owned data to the OS trash; it never permanently deletes. See [`observability.md`](observability.md#retention-zero_fsretention). |
| Permission denied on a path | `zero.fnd.permission_denied`, `zero.pol.self_escalation` | The path is named. Agent writes to policy, trust, config, journals, vault, audit, or credential files are refused by design. | Change permissions as the user, or choose a path outside the protected set. Do not loosen the protected set. See [`trust.md`](trust.md). |
| Mesh peer is unreachable | `zero.fnd.unavailable`, `zero.lck.no_quorum` | `zero-doctor` mesh check; inspect `.zero/mesh/registry.json`. A minority partition denies new leases. | Restore connectivity and quorum. Rejoin with a fresh single-use token if membership is gone; an expired token is refused. Do not copy a device key or registry between devices. See [`mesh.md`](mesh.md). |
| A MCP server will not start | `zero.prv.protocol`, `zero.fnd.config_invalid` | `zero-doctor` mcp check: a server needs a non-empty `command`; `args` must be strings. | Correct `.zero/mcp.json`. Remove secret-looking env values and use the credential store. Trust the project before its declarations load. See [`mcp.md`](mcp.md) and [`configure.md`](configure.md#tools-and-mcp). |
| A secret tag is refused | `zero.pol.denied` (drift), `zero.pol.approval_expired` (expiry) | Check the tag's scope and project binding in the vault index. | Open the project that owns the binding, or re-bind deliberately. Expired bindings need a fresh approval. Rotate rather than copying ciphertext. See [`secrets.md`](secrets.md). |
| A value fails to decrypt | `zero.tru.tamper` | The AAD covers tag, scope, and project; editing any of them fails. | Restore the vault backup. Do not edit `index.json`; a wrong passphrase or a tampered ciphertext is not repaired by retrying. |
| An update failed partway | Typed `UpdateError`, not a `zero.*` code | Check the update report: `rollback_state()` is `RolledBack` or `RollbackFailed`. | Leave the `.backup-<version>-<ms>` snapshot in place. Stop the running process before retrying on Windows. See [`packaging.md`](packaging.md#refusals). |
| `zero update` says nothing applies | none | The CLI is a stub and reports no signed channel. | Expected in this build. Verified update is library-only; see [`packaging.md`](packaging.md#update-and-rollback-t-inst-04). |

## Playbooks and repairs

The doctor library can plan repairs (`CreateDirectory`, `WriteFile`,
`MoveToTrash`, `RemoveStaleLock`, `RotateFile`, `RepairConfig`), dry-run them,
snapshot every affected file, apply, and roll back. The repair **CLI flag is not
wired** in this build; [`errors.md`](errors.md) mentions `zero doctor --repair`
for a corrupt store, but the flag is planned.

Until it is wired, use the safe manual form:

1. Run `zero-doctor --json` and keep the report.
2. Copy the affected file or directory aside. Never edit a journal, vault index,
   project key, or audit chain in place.
3. Restore the backup named by the error, or rerun on a fresh `--data-dir` to
   separate an installation problem from project data.
4. For a lock, confirm no `zero` or `zero-worker` process is alive before moving
   the lock aside; keep the copy.

The repair engine already snapshots before every write and refuses `..`, symlink
escapes, paths outside the allowed roots, and deletes unless explicitly allowed.
That is the behaviour to expect once the flag is wired.

## Provider and key failures

`zero login <provider>` exists but reports `zero.fnd.unavailable`; the credential
store, keychain selection, encrypted fallback, named accounts, and sign-in flows
are implemented, but the verb is not connected. There is no supported
copy-paste workaround that writes a token into config, and you should not create
one.

What works offline:

- Local file work, sessions listing, doctor, and the independent doctor.
- The Ollama/LM Studio adapter, when the library is driven directly.
- Nothing that needs a hosted provider, web access, remote MCP, or mesh.

If `zero-doctor` reports `auth` as `warn`, the backend was not probed; that is
not a failure. On Linux, a missing D-Bus session or locked keyring makes the
native store unavailable and the encrypted fallback is selected. Set
`ZERO_REQUIRE_KEYCHAIN=1` only in tests that must prove the native path; it turns
absence into a failure.

## Kernel and Python failures

The kernel needs a Python interpreter with `ipykernel`, reachable by the host
that launches it. `ZERO_PYTHON` selects the interpreter; otherwise the search is
`python`, `python3`, then `py`. Check:

```powershell
python --version
python -m ipykernel --version
```

If the second command fails, install `ipykernel` for that interpreter. The
kernel bootstrap library models `uv`, Python, `ipykernel`, `pyzmq`, and wheel
components with checksums, a cache, and an offline mode, but its default plan is
a shape with placeholder digests and URLs; it is not a downloadable bundle. Do
not run it expecting an install.

`zero-doctor` kernel states: `running` with a socket is ok; a clean `stopped` is
ok; a stale socket is a warning; running without a known socket path warns; a
running kernel whose socket file is missing fails. A restart replays successful
cells and reports the lost in-flight cell rather than replaying it.

## Locks, journals, and damaged state

Three different things are called a journal:

| File | Owner | What it records |
|---|---|---|
| `<data>/sessions/<name>.jsonl` | Session log | Append-only session entries. A torn final line is `zero.fnd.corrupt`. |
| `<data>/sessions/<name>.journal.jsonl` | Command journal | Dispatch-before-apply records; an unfinished `begin` is reported uncertain and never replayed. |
| `.zero/journal/*.jsonl` | Project/task journals | Doctor parses every line; an invalid line fails the `journals` check. |

Safe order: stop the process, copy the file aside, run `zero-doctor --json`,
restore the named backup, and start a new session. Do not truncate a file to the
last good line, and do not delete a lock or journal while a worker may hold it.
The audit chain is separate: an edited or deleted record breaks verification at
that link, and a tampered log refuses to open (`zero.tru.tamper`,
`zero.tru.audit_broken`).

## Mesh and transport failures

A join token is single-use and expires; the maximum TTL is 24 hours. An expired
token is `zero.pol.approval_expired`; a reused token is refused. A signature
mismatch is `zero.pol.denied`. Membership is signed: a peer with a revoked device
is dropped.

A minority partition denies new leases (`zero.lck.no_quorum`); existing work
follows the quorum rules. Restore connectivity rather than forcing a write.
Discovery is not a trust decision: a discovered peer still needs signed
membership.

## MCP handshake failures

Check the declaration first:

- `.zero/mcp.json` has `servers` or `mcpServers`.
- Each server has a non-empty `command`; `args`, when present, is an array of
  strings.
- No credential-looking value sits in `env`. Use `{{secret:TAG}}` and the
  credential store.
- The project is trusted. An untrusted `.zero/mcp.json` is not loaded, and its
  content contributes nothing.

Then check the transport: stdio needs the program on `PATH` for the child; HTTP
needs a reachable URL and a network. Protocol-shape failures are
`zero.prv.protocol` and usually mean the server's revision is unsupported or its
response is malformed. The client supports two checked-in revisions and rejects
an unknown one rather than guessing. See [`mcp.md`](mcp.md#transports).

## Update and rollback

`zero update` and `zero update --check` are stubs in this build: there is no
signed release channel, and the archive decoder is not wired. The verified update
library stages a payload, verifies the manifest and Ed25519 signature, snapshots
the current tree to `install_root/.backup-<old_version>-<now_ms>`, swaps files,
re-hashes, and restores the snapshot on any failure.

If an apply reports `RolledBack`, the previous tree is restored. Keep the
snapshot for inspection; it is intentionally not deleted. If it reports
`RollbackFailed`, stop and preserve both the install tree and the `.backup-*`
directory, then reinstall from source.

On Windows a running `zero` holds its executable open, so the rename fails and
the update rolls back. Stop the process or service before retrying. The swap is
atomic per file, not for the whole tree; a power loss between renames can leave a
mixed tree, and automatic crash recovery is not implemented. See the limitations
in [`packaging.md`](packaging.md#limitations).

## When to escalate

Escalate instead of improvising when:

- an audit chain fails verification, or a record is missing;
- a project key was replaced and you cannot tell which project owns the history;
- a secret value may have reached a log, transcript, or bundle;
- `RollbackFailed` names a file that cannot be restored;
- removing a lock would require deleting a file a live process may hold.

Attach `zero doctor --json`, `zero-doctor --json`, the error code, and the
relevant path. Do not attach a vault, `credentials.enc`, `.zero/key`, or a raw
journal without redacting it.
