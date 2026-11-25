# Install and first run

This page installs Zero from source, runs it for the first time, and checks that
the installation is healthy. The packaged installer is not wired yet; every
place that depends on it is marked **planned**.

Requirements: FND-11, INST-01..INST-12. The release plan is in
[`packaging.md`](packaging.md); the task list is [`tasks.md`](../tasks.md).

## Prerequisites

| Requirement | Needed for | Notes |
|---|---|---|
| Rust 1.88 or newer | Every build | The workspace sets `rust-version = "1.88"`. `keyring` 4.2 needs the same MSRV. Check with `rustc --version`. |
| Cargo | Every build | Installed by `rustup`. |
| Git | Cloning and project root detection | A repository root is used when no `.zero/` directory exists. |
| Python 3 with `ipykernel` | Kernel execution only | Optional. `zero`, `zero doctor`, and file work run without it. Check with `python -m ipykernel --version`. Set `ZERO_PYTHON` to choose the interpreter; the default search is `python`, `python3`, then `py`. |
| Network | First dependency download and hosted providers | The built binary's local file work is offline. |

There is no Node runtime requirement (INST-03).

### OS notes

| OS | Notes |
|---|---|
| Windows 10/11 | Build with the MSVC toolchain. PowerShell examples below. Credentials use Windows Credential Manager when available. |
| macOS | Install the Xcode command-line tools before building. Credentials use Keychain Services; a headless session may prompt. |
| Linux | A normal desktop build works. The native keychain path needs a D-Bus session and a Secret Service provider such as `gnome-keyring`; otherwise the encrypted fallback is used. Service units are systemd. |

Data, config, cache, and state paths are listed in
[`data-directories.md`](data-directories.md). They are resolved per OS from one
table.

## Build from source

```powershell
git clone https://github.com/Ruthvik-Anne/zero.git
cd zero
cargo build --workspace
cargo build -p zero-cli --release
cargo build -p zero-doctor --release
```

The binaries land in `target\release\` on Windows (`zero.exe`,
`zero-doctor.exe`) and `target/release/` elsewhere. Add that directory to
`PATH`, or run the binaries by path.

For a source-tree run without installing:

```powershell
cargo run -p zero-cli --bin zero -- --help
cargo run -p zero-cli --bin zero -- doctor
```

Run the workspace checks before relying on the build:

```powershell
cargo test --workspace
cargo run -p xtask -- check-docs
```

`check-docs` runs the traceability and crate-direction gates. It does not check
documentation links.

## Packaged install (planned)

The `zero install` verb exists but is a placeholder:

```text
install: verified installer wiring lands with the release milestone
```

Do not treat it as an installation. The release manifest, Ed25519 signature,
artifact naming, SBOM, update, and uninstall libraries exist in
`zero_cli::packaging`, `zero_cli::update`, and `zero_cli::uninstall`; the host
installer that downloads and registers a signed release is still planned. See
[`packaging.md`](packaging.md).

## First run

```powershell
zero --version
zero doctor
```

`zero --version` prints the version and protocol:

```text
zero 0.1.0 (protocol 1)
```

`zero doctor` creates the data, config, cache, and state directories if needed,
opens the SQLite store, and prints one line per check (paths and OS line from
Windows; the check names are the same everywhere):

```text
doctor: 6 checks, 0 failed
  ok    data_dir: ...
  ok    config_dir: ...
  ok    state_dir: ...
  ok    cache_dir: ...
  ok    store: schema 1, journal wal, ...
  ok    offline: local operation does not require a network
versions: zero 0.1.0, protocol 1, os windows
```

Exit code is `0` when every check passes and `1` when one fails. For scripts:

```powershell
zero doctor --json
```

To use a scratch location, pass `--data-dir` to `doctor` or `resume`:

```powershell
zero doctor --data-dir C:\temp\zero-data
```

`--data-dir` is read by those verbs, not by every verb.

### The independent doctor

`zero-doctor` is a separate executable for a broken installation. It loads no
plugins and never contacts the daemon, so it still runs when the daemon, kernel,
and mesh are dead:

```powershell
zero-doctor
zero-doctor --json
zero-doctor --version
```

It reports 13 checks: `versions`, `config`, `keys`, `workers`, `kernel`, `auth`,
`network`, `mesh`, `ports`, `disk`, `locks`, `journals`, and `mcp`. It reads the
project under `ZERO_DATA_DIR` when set, otherwise the current directory; run it
from a project root or set the variable. Outside a project it reports `keys` as a
failure and the file-backed checks as warnings; that is expected. It exits `0`
on every path because it reports state rather than gating a script.

`zero doctor` and `zero-doctor` are different surfaces: the first checks this
installation's directories and store, the second diagnoses project files and
services. Both are documented in [`doctor.md`](doctor.md).

## Projects and `.zero/`

A project is a random key in `.zero/key`; `projectId = blake3(key)`. There is no
`zero init` verb yet. The first project open in the agent creates `.zero/`, a
key, `project.json`, the layout, and appends `.zero/` to `.gitignore` when a
repository exists. The interactive opener is **planned**; the library behaviour
is implemented and documented in [`projects.md`](projects.md).

The layout written on first open:

```text
.zero/
  project.json
  key
  config
  plan
  tasks
  todos
  journal/
  artifacts/
  vault/
  audits/
```

Do not create `key` by hand and do not copy `.zero/key` between unrelated
projects. A copied project is detected and gets a new key with a `copiedFrom`
link; the original is left untouched.

## Login

The verb is present:

```powershell
zero login <provider>
zero logout <provider>
```

`zero login` currently reports `zero.fnd.unavailable` because the verb is not
wired to the credential store yet:

```text
error zero.fnd.unavailable: credential storage for `openai` is not built in this milestone
```

The credential store, keychain selection, encrypted fallback, and sign-in flows
are implemented in `zero-secrets`; see [`credentials.md`](credentials.md) and
[`secrets.md`](secrets.md). Wiring `zero login` to those flows is **planned**.
`zero logout <provider>` succeeds and reports that no stored credential exists in
this installation.

## Service install, start, and status

The `service` verb is present:

```powershell
zero service status
zero service start
zero service stop
```

Current behaviour:

| Command | Result |
|---|---|
| `zero service status` | Prints `service: not installed`. |
| `zero service start` | Fails with `zero.fnd.unavailable`: no service unit is installed. |
| `zero service stop` | Same failure. |

Service unit rendering for systemd, the Windows service wrapper config, and
launchd exists in `zero_cli::service`, with install/start/stop/status through an
injected manager. Registering the unit with `systemctl`, the Windows service
control manager, or `launchctl` is host work and is **planned**. Unit formats and
default paths are in [`packaging.md`](packaging.md#service-units-t-inst-05).

Do not copy a rendered unit into a system directory by hand on a machine you
depend on; wait for the host installer or use the library seam.

## Update and uninstall

Both verbs exist and are stubs:

```powershell
zero update --check
zero update
zero uninstall
zero uninstall --purge
```

`zero update --check` reports that no signed release channel is configured;
`zero update` reports that this is an unsigned development build. `zero
uninstall` prints the intended scope and changes nothing. The verified update,
atomic swap, rollback, and uninstall planning are implemented as libraries and
are documented in [`packaging.md`](packaging.md#update-and-rollback-t-inst-04).
The CLI wiring is **planned**.

## Offline notes

- Local file work, `zero --version`, `zero doctor`, `zero resume --list`, and
  `zero-doctor` work without a network.
- Hosted providers, web search and fetch, remote MCP, mesh, and catalogue
  refresh report a typed `zero.fnd.offline` when the network is unavailable.
  Startup and file work do not.
- The Ollama adapter (also used for LM Studio) is the offline model path. It is
  exercised by the provider tests; CLI provider selection is **planned**. See
  [`providers.md`](providers.md).
- Telemetry is off by default and this build has no sender. A normal session
  contacts only the providers and mesh peers you configure.
- A full offline build needs the Cargo dependencies already cached or vendored;
  otherwise the first build downloads them.

## Verify it works

Run these from the repository root or with `zero` on `PATH`. Expected results are
the contract for this build.

| Step | Command | Expected |
|---|---|---|
| 1 | `zero --version` | `zero 0.1.0 (protocol 1)`, exit 0. |
| 2 | `zero doctor` | `6 checks, 0 failed`, exit 0. |
| 3 | `zero doctor --json` | A JSON object with a `checks` array. |
| 4 | `zero-doctor` | A human report with 13 checks, including `daemon: not contacted`. |
| 5 | `zero resume --list` | Either saved session paths or `no saved sessions in ...`, exit 0. |
| 6 | `zero completion powershell` | A PowerShell completer for the nine verbs. |
| 7 | `zero resum` | Exit 2, with the closest permitted verb (`resume`) named. |
| 8 | `cargo run -p xtask -- check-docs` | `traceability: OK` and `architecture: OK`. |
| 9 | `cargo test -p zero-cli --test cli --test line` | Both CLI integration suites pass (9 + 2 tests). |

If step 2 fails, go to [`troubleshooting.md`](troubleshooting.md). If the failure
is a permission, disk, or path problem, the failing check names the path.

## Known gaps in this build

| Area | State |
|---|---|
| Interactive TUI and the agent session UI | Library and protocol work exist; no interactive binary is wired. `resume --line --script` is a test-only client. |
| Packaged install, signed update, uninstall | Libraries and tests exist; `zero install`, `zero update`, and `zero uninstall` are stubs. |
| `zero login` / `zero logout` | Store and sign-in flows exist; the login verb is not wired. |
| Service registration | Unit rendering and lifecycle seam exist; host registration is not wired. |
| Project creation verb | Library creation exists; first-open creation is not reachable from this CLI. |
