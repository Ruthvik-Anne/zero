# Doctor

`zero-doctor` is the diagnosis surface for an installation that is already
broken: the daemon, kernel, and mesh may all be dead (DOC-09). It is its own
executable, not a subcommand that needs a live runtime, and its core loads no
plugins and never opens a daemon socket. It is also available through
`zero doctor`, `/doctor`, as a tool, and as a panel (DOC-01).

## The independent core

`zero_doctor::run_core_with(&DoctorContext)` returns a `DoctorReport`:

| Field | Meaning |
|---|---|
| `version` | the `zero-doctor` version |
| `independent` | always `true`; the core ran without plugins or a daemon |
| `daemon` | `not_contacted`; the core never probes it |
| `checks` | one `CheckResult` per check, in the fixed order below |

`run_core()` is the default-context form. Both functions are pure with respect
to services: they read injected snapshots, never a daemon socket, and never send
network traffic. `run_core_with` cannot panic on a missing or malformed input;
each check turns that into `warn`/`fail` with a short detail.

## Context model

Every check reads a `DoctorContext` captured once before the checks run. This
keeps results deterministic and lets tests inject pass, warn, and fail states
without a live installation.

| Field | Kind | Meaning |
|---|---|---|
| `versions` | `VersionsSnapshot` | `zero_version` plus one captured `rustc --version` string |
| `config` | `FileSnapshot` | config path and text (`None` when absent or unreadable) |
| `project_key_path` | `PathBuf` | project key file; contents are never printed |
| `workers_journal` | `FileSnapshot` | supervisor worker journal path and text |
| `kernel` | `KernelSnapshot` | `running`/`stopped`/`unknown` plus the socket path |
| `credential_backend` | `CredentialBackend` | OS store name, encrypted fallback, unavailable, or unknown |
| `network` | `NetworkSnapshot` | proxy, base URL, and offline flag; values are not echoed |
| `mesh_registry` | `FileSnapshot` | mesh registry path and text; identities are not echoed |
| `ports` | `PortsSnapshot` | expected and actually listening ports |
| `disk` | `Option<DiskSnapshot>` | free and total bytes, injected |
| `locks` | `LocksSnapshot` | lock paths, modification times, threshold, and a fixed `now` |
| `journals` | `Vec<PathBuf>` | JSONL journals to parse |
| `mcp_config` | `FileSnapshot` | MCP config path and text; only server names are reported |

`DoctorContext::from_root(root)` derives the local layout:
`.zero/config.toml`, `.zero/key`, `.zero/workers.json`, `.zero/journal/*.jsonl`,
`.zero/locks/*.lock`, `.zero/mesh/registry.json`, and `.zero/mcp.json`. The
default root is `ZERO_DATA_DIR` when set, otherwise the current directory.
Kernel state, credential backend, ports, and disk are not derivable without a
live service, so the default context leaves them unknown and the corresponding
checks say `skipped`/`unknown` instead of passing.

## Checks

The names and order are `zero_doctor::CHECK_NAMES`; a test asserts the report
contains exactly those 13 checks, so one cannot silently disappear.

| # | Name | Passes when | Warns when | Fails when |
|---|---|---|---|---|
| 1 | `versions` | zero version and toolchain are known | toolchain not detected | zero version is unknown |
| 2 | `config` | config text has valid TOML shape | config is absent/unreadable | malformed TOML (line number, path) |
| 3 | `keys` | key exists, is non-empty, and is not group/world-readable | — | missing, empty, not a file, or readable by group/world (Unix) |
| 4 | `workers` | journal parses with at least one worker record | journal parses but has no records | malformed JSON or unexpected shape |
| 5 | `kernel` | running with its socket, or cleanly stopped | state unknown, or stopped with a stale socket, or running without a known socket path | running but the socket file is missing |
| 6 | `auth` | OS credential store | encrypted-file fallback, or backend not probed | no backend available |
| 7 | `network` | configured URLs are valid | URL malformed, or offline mode | URL has whitespace/control characters |
| 8 | `mesh` | registry parses with at least one entry | registry empty | malformed JSON or unexpected shape |
| 9 | `ports` | every expected port is listening and nothing extra is | extra listeners | an expected port is missing |
| 10 | `disk` | at least 5 GiB free | below 5 GiB | below 1 GiB, zero total, or free > total |
| 11 | `locks` | no lock files, or none stale | 1–5 stale, or unknown mtime | more than 5 stale |
| 12 | `journals` | every line is valid JSON | no journals configured | unreadable file or an invalid JSONL line |
| 13 | `mcp` | servers have a command and string args | inline secret-looking env values | malformed JSON, or a server without a command |

### Thresholds

| Setting | Value | Effect |
|---|---|---|
| disk fail | `< 1 GiB` free | `disk` fails |
| disk warn | `< 5 GiB` free | `disk` warns |
| lock age | `> 24 hours` | lock counts as stale |
| lock fail | `> 5` stale | `locks` fails |
| list detail | first 3–8 entries | keeps details short |

### Redaction rules

Details contain paths, counts, status names, server names, port numbers, and
line numbers only. Key bytes, tokens, config values, mesh identities, and MCP
env values are never formatted into a result. File-supplied text used in a
detail (worker states, server names) is stripped of control characters and
truncated. Config and MCP parse failures report only the path and line.

## CLI

```
zero-doctor            # human report
zero-doctor --json     # the DoctorReport as JSON
zero-doctor --version  # the version, then exit
```

The human output starts with the version, `independent`, `daemon`, and the check
count, then one `status  name  detail` line per check (`ok`, `warn`, or `fail`).
The binary exits zero on every path in this task: the doctor reports state, and
callers decide what a failed check means. Playbooks, repair, and forensics
arrive in T-DOC-03 through T-DOC-05.

## Fixture strategy

The check functions take `&DoctorContext`, so every fixture is just a struct
literal plus a temporary directory:

- File-backed checks (`config`, `keys`, `workers`, `mesh`, `journals`, `mcp`)
  write real files into a `tempfile::tempdir()` and read them back, so path
  handling, presence, and parse failures are exercised end to end.
- Injected checks (`versions`, `kernel`, `auth`, `network`, `ports`, `disk`,
  `locks`) set the snapshot directly. `locks` also injects `now` and each
  modification time, so staleness is deterministic.
- Each check has at least one pass and one failure fixture, plus a warn fixture
  where the state exists. `keys` has a Unix-only permission fixture.
- Security assertions live with the fixtures: the config failure fixture asserts
  its secret value does not appear in the detail, and the MCP warning fixture
  asserts the env value is not echoed.
- `tests/independent.rs` keeps the T-DOC-01 guarantee: the binary runs with the
  daemon dead, reports `daemon: not contacted`, and serializes 13 named checks.

## Known limits

These are deliberate for T-DOC-02 and are not fabricated passes:

- TOML validation is structural only (balanced brackets, closed strings, table
  headers, `key = value` shape). The allowed dependency set has no TOML parser,
  so value semantics are left to the config loader.
- Key permission checking is Unix-only; on Windows the detail says permissions
  were not checked.
- `network` validates URL shape and offline state without DNS or connectivity
  probes.
- `disk`, `ports`, `kernel`, and `auth` report the injected snapshot; the
  default context cannot discover them while the daemon is dead, so they warn.
