# Doctor

`zero-doctor` is the diagnosis surface for an installation that is already
broken: the daemon, kernel, and mesh may all be dead (DOC-09). It is its own
executable, not a subcommand that needs a live runtime, and its core loads no
plugins and never opens a daemon socket. It is also available through
`zero doctor`, `/doctor`, as a tool, and as a panel (DOC-01).

## The independent core

`zero_doctor::run_core()` returns a `DoctorReport`:

| Field | Meaning |
|---|---|
| `version` | the `zero-doctor` version |
| `independent` | always `true`; the core ran without plugins or a daemon |
| `daemon` | `not_contacted`, `reachable`, or `unreachable` |
| `checks` | one `CheckResult` per check: stable name, `ok`/`warn`/`fail`, detail |

For this task the core does not probe anything: `daemon` is `not_contacted`
and `checks` is empty. `CheckResult` exists so the checks in T-DOC-02 can be
added without changing the report shape. Nothing in the crate or the binary
imports `zero-daemon`, so the doctor cannot accidentally depend on a healthy
supervisor.

## CLI

```
zero-doctor            # human report
zero-doctor --json     # the DoctorReport as JSON
zero-doctor --version  # the version, then exit
```

The human output is one `name: value` line per field, including
`daemon: not contacted`, which makes it easy to grep from a support script.
The binary exits zero on every path in this task: the doctor reports state, and
callers decide what a failed check means. Checks, playbooks, repair, and
forensics arrive in T-DOC-02 through T-DOC-05.
