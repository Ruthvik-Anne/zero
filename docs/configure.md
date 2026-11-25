# Configure

Where each setting lives, what is actually read today, and where the full
reference is. This build has a stable configuration *model* but not a frozen
user-facing key set: `zero_types::config` resolves six layers, and the binary
does not yet load a user `config.toml`. File formats that components do read are
shown with copy-pasteable examples. Anything not wired is marked **planned**.

## File locations

Paths are resolved per OS from one table; the full list is in
[`data-directories.md`](data-directories.md).

| What | Location |
|---|---|
| User data root | Windows `%LOCALAPPDATA%\Zero\data`; macOS `~/Library/Application Support/Zero/data`; Linux `~/.local/share/zero` |
| User config root | Windows `%APPDATA%\Zero\config`; macOS `~/Library/Application Support/Zero/config`; Linux `~/.config/zero` |
| Cache | Windows `%LOCALAPPDATA%\Zero\cache`; macOS `~/Library/Caches/Zero`; Linux `~/.cache/zero` |
| State | Windows `%LOCALAPPDATA%\Zero\state`; macOS `~/Library/Application Support/Zero/state`; Linux `~/.local/state/zero` |
| SQLite store | `<data>/store/zero.db` |
| Session logs | `<data>/sessions/*.jsonl` (the path `zero resume` lists) |
| Encrypted credentials | `<data>/credentials.enc`, plus a machine key sibling when unattended unlock is used |
| Project root | `.zero/` at the nearest project root |
| Project key and history | `.zero/key`, `.zero/project.json` |
| Project layout placeholders | `.zero/config`, `.zero/plan`, `.zero/tasks`, `.zero/todos` |
| Project vault | `.zero/vault/index.json` |
| MCP declarations | `.zero/mcp.json` |
| Monitor declarations | `.zero/monitors.json` |
| Mesh registry | `.zero/mesh/registry.json` |
| Review artifacts | `.zero/audits/run-N/`, `.zero/audit-profile.json` |
| Teleport bundles | `.zero/teleport/<bundle_id>/` |

Project creation writes the layout files as `{}`. `configuration.md` and doctor
name `.zero/config.toml` for the trusted project layer. Those are two different
names today; no loader consumes either. Use `--data-dir DIR` on `zero doctor` or
`zero resume` to point one command at another root; `zero-doctor` reads
`ZERO_DATA_DIR`.

## Resolution order

Lowest to highest; the highest layer that supplies a key wins.

| # | Layer | Source | Trust |
|---|---|---|---|
| 0 | `defaults` | Built into the binary | trusted |
| 1 | `user` | Per-user config directory | trusted |
| 2 | `trusted_project` | `.zero/config.toml` in a trusted project | trusted only after explicit trust |
| 3 | `environment` | Environment variables | trusted |
| 4 | `cli` | Flags on this invocation | trusted |
| 5 | `session` | Values set for this session | trusted |

An untrusted project supplies nothing: its layer is dropped before resolution,
so it cannot override a default or introduce a key. The matrix and inertness
rules are in [`configuration.md`](configuration.md).

## Providers and models

The adapters are configured in code; a config-file key set and CLI flags are
**planned**.

| Adapter | Real fields | Defaults |
|---|---|---|
| OpenAI-compatible (`OpenAiProvider`) | `base_url`, `api_key`, `model`, `timeout_ms`, `context_limit`, `output_limit` | 120 s, 128k context, 8,192 output |
| Ollama / LM Studio (`OllamaProvider`) | `base_url`, `model`, `timeout_ms`, `tool_support` | 120 s; `tool_support` defaults false, then `/api/show` is probed |

Current library construction:

```rust
use zero_model::OpenAiConfig;

let config = OpenAiConfig::new(
    "https://api.openai.com/v1",
    std::env::var("OPENAI_API_KEY").unwrap_or_default(),
    "gpt-5",
);
```

Role defaults are representative and configurable: `planner` → `gpt-5`,
`coder` and `tester` → `gpt-5-codex`, `reviewer` and `vision` →
`claude-sonnet-4-5`, `researcher` → `gemini-2.5-pro`. A user pin wins over the
role default; an upgrade needs budget approval and a reason. See
[`routing.md`](routing.md) and [`providers.md`](providers.md).

Live-test variables are not runtime configuration:

| Variable | Use |
|---|---|
| `ZERO_LIVE_OPENAI=1`, `OPENAI_API_KEY` | Run the hosted adapter's live smoke test. |
| `ZERO_LIVE_OLLAMA=1`, `OLLAMA_HOST` | Run the local adapter's live smoke test. |

Put real credentials in the credential store, never in a config file, a shell
profile, or a service unit.

## Modes and approvals

Five modes: `plan`, `manual`, `semi-auto`, `auto`, `headless`. The full matrix of
mode × action class is in [`policy.md`](policy.md). The defaults that matter
most:

- `plan` denies writes, mutating shell, deletes, and network writes.
- `manual` asks for almost everything that changes state.
- `semi-auto` allows writes and asks for shell, delete, and network writes.
- `auto` allows most tool classes, but `computer` and `credential` still ask; both
  regulators are required.
- `headless` queues every `ask` instead of blocking unrelated work.

Mode changes are actions, not agent choices: `mode.set` and `mode.cycle` are
`policy_class: mode_change`, `agent_invocable: false`. `Shift+Tab` is the default
`mode.cycle` binding. Approvals are bound to an action hash, expire, and are
recorded once; a mutated command needs a fresh approval. The interactive surface
that renders these actions is **planned**.

An untrusted project always runs plan-equivalent, whatever mode is configured.

## Tools and MCP

Tool metadata, search, activation, and policy filtering are in
[`tools.md`](tools.md). MCP transports, revisions, and client behaviour are in
[`mcp.md`](mcp.md).

Project MCP declarations use `.zero/mcp.json`. Doctor reads either `servers` or
`mcpServers`; a server needs a non-empty `command` and, when present, string
`args`. Copy this shape:

```json
{
  "servers": {
    "files": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "."],
      "env": {
        "MCP_LOG_LEVEL": "info"
      }
    }
  }
}
```

Rules that apply today:

- Declarations in an untrusted project are inert. Trust the project first; see
  [`trust.md`](trust.md).
- A credential-looking `env` name or value is flagged by doctor. Explicit env
  entries are scrubbed before a stdio server is launched: any name containing
  `KEY`, `TOKEN`, `SECRET`, `PASSWORD`, or `CREDENTIAL` never reaches the child.
  Use the credential store and a `{{secret:TAG}}` placeholder instead.
- Streamable HTTP is the default transport; stdio launches a local child; the
  legacy HTTP+SSE shim is default-off and refused by `connect` in this build. A
  remote server reports `zero.fnd.offline` when the host is offline.
- Doctor validates stdio-style declarations, so a server entry needs a `command`.
  The loader that starts every declared server at session start is **planned**.
  The client transports are implemented and tested directly.

## Credentials and secrets

Two stores, two purposes. Read [`credentials.md`](credentials.md) and
[`secrets.md`](secrets.md) before putting a value anywhere.

| Store | Holds | Location |
|---|---|---|
| Credential store | Provider tokens and named accounts | OS keychain, or `credentials.enc` with a machine-bound key |
| Project vault | Named secret tags bound to a project and scope | `.zero/vault/index.json` (ciphertext only) |

Backend selection is automatic: Windows Credential Manager, macOS Keychain,
Linux Secret Service, else the AES-256-GCM encrypted file. On Linux the native
path needs a D-Bus session and a provider such as `gnome-keyring`.

Use tags in prompts, tool arguments, and headers:

```text
{{secret:DEPLOY_TOKEN}}
Secret("DEPLOY_TOKEN")
```

Scope precedence is project > session > user. A tag bound to a different project
is drift and is refused; an expired binding is refused. A value is substituted
only for a header, query, stdin, or env/SDK destination; the chat destination
always renders `[secret:TAG]`. Audit rows carry the tag, never the value.

`.env` must be git-ignored when a repository exists; `.env.example` is created,
and the pre-commit guard refuses a staged value of eight or more characters.
`zero login` is **planned** to write provider tokens to the credential store;
the store and sign-in flows are implemented.

## Projects

`projectId = blake3(key)`. A moved folder keeps its key; a copied folder is
detected and gets a new key plus `copiedFrom`. A replaced key offers adopt or
restore. The full rules are in [`projects.md`](projects.md).

The project root is the nearest `.zero/`, else the nearest git root, else the
working directory, stopping at home or the filesystem root. First open appends
`.zero/` to `.gitignore` when a repository exists.

Do not edit `key` or `project.json` by hand, and do not copy a key between
projects. Recovery actions (`init`, `list`, `show`, `bind`, `move`, `rekey`,
`forget`) are user-only.

## Mesh

Device identity is an Ed25519 key pair; `device_id` is the blake3 hash of the
public key. Joining uses a single-use signed token with a short code or QR
payload; the owner approves the pending device. Membership state is signed and
replicated. The registry lives at `.zero/mesh/registry.json`. Quorum rules deny
new leases on a minority partition.

The identity, join, discovery, relay, traversal, presence, and partition surfaces
are implemented as libraries. A `zero mesh` CLI or panel is **planned**. See
[`mesh.md`](mesh.md).

## Teleport

A teleport snapshot carries the session, kernel checkpoint, and workspace
manifest, plus artifacts, goals, schedules, and the usage ledger when present.
Bundles are content-addressed and can be transferred encrypted. Restore stages
conflicts under `.zero/restore-staging/<bundle_id>/` and writes components under
`.zero/teleport/<bundle_id>/components/`.

Excluded by name, always: `.zero/vault`, credential files, `.env`, and private
keys. There is no vault in a bundle. The transfer and restore surfaces are
libraries; a CLI verb is **planned**. See [`teleport.md`](teleport.md).

## Monitors

A project or plugin declares monitors in `.zero/monitors.json`. The schema is
validated before anything spawns; unknown fields are ignored.

```json
{
  "schema_version": 1,
  "monitors": [
    {
      "name": "deploy-watch",
      "command": "zwatch",
      "args": ["--follow"],
      "description": "Stream deploy logs",
      "when": "skill:deploy",
      "source": { "kind": "log_tail", "path": "/srv/logs/deploy.log" },
      "requires_shell": false,
      "max_output_bytes": 4096
    }
  ]
}
```

`when` is `manual`, `session_start`, or `skill:<name>`. `source.kind` is
`script`, `log_tail`, `directory_watch`, `ci_poll`, or `websocket`. A child
inherits a scrubbed environment: credential-looking names are removed. Monitors
in an untrusted project are not loaded. See
[`monitors.md`](monitors.md#declarative-monitors).

## Usage budgets

Costs are recorded in the usage ledger. A budget adds a warn line and a stop line
per scope; the stop line is inclusive and is the maximum permitted total.

| Scope | Value |
|---|---|
| `Global` | Every unit of work |
| `Project(name)` | Work attributed to a project |
| `Device(name)` | Work observed on one device |
| `Day(epoch_day)` | Work observed during one UTC day |

The real struct is `BudgetLimit { scope, warn_micros, stop_micros }`. At least
one threshold is required, both are nonzero, and `warn_micros <= stop_micros`.
There is one limit per scope. A `Stop` decision must not dispatch; a `Warn`
permits dispatch and reports headroom. Budget configuration is library-level;
CLI flags and a settings panel are **planned**. See
[`usage.md`](usage.md#cost-budgets-usg-03).

## Telemetry

Telemetry is **off by default**. `TelemetryMode::Off` counts an event locally and
drops it; `transmit` returns `zero.fnd.unavailable` and opens no socket. Opt-in
exists only to permit a future sender; this build has no sender. Do not expect a
telemetry endpoint, key, or config file in this milestone. See
[`observability.md`](observability.md).

## Review

Review has three request modes: `guidance`, `audit`, and `full_report`. A plain
question cannot open a full audit, and guidance cannot open a hunting wave. Runs
write under `.zero/audits/run-N/`. A project file at
`.zero/audit-profile.json` is read only to be checked: a project cannot pick a
shallower profile, omit a phase, or lower the evidence bar, and such a request is
refused before any directory or task is created. Target code runs only through
the sandbox seam, and only when a real platform mechanism is available. There is
no review CLI verb yet; the library is documented in [`review.md`](review.md).

## Where each topic is documented

| Topic | Page |
|---|---|
| Layers, precedence, untrusted inertness | [`configuration.md`](configuration.md) |
| Per-OS paths and environment overrides | [`data-directories.md`](data-directories.md) |
| Modes, matrix, permits, approvals, regulators | [`policy.md`](policy.md) |
| Trust, protected files, audit integrity | [`trust.md`](trust.md) |
| Projects and `.zero/` layout | [`projects.md`](projects.md) |
| Credential backends and accounts | [`credentials.md`](credentials.md) |
| Vault, tags, placeholders, `.env`, leakage | [`secrets.md`](secrets.md) |
| Provider adapters and retry classes | [`providers.md`](providers.md) |
| Model classes, roles, routing, prices | [`routing.md`](routing.md) |
| MCP client, transports, server config | [`mcp.md`](mcp.md) |
| Monitor schema and triggers | [`monitors.md`](monitors.md#declarative-monitors) |
| Mesh identity, join, quorum | [`mesh.md`](mesh.md) |
| Teleport bundles and restore | [`teleport.md`](teleport.md) |
| Review gate, ledger, profiles | [`review.md`](review.md) |
| Usage ledger, budgets, export | [`usage.md`](usage.md) |
| Metrics, traces, retention | [`observability.md`](observability.md) |
| Local web UI binding and token | [`webui.md`](webui.md) |
| Auto-resume policy | [`auto-resume.md`](auto-resume.md) |
| Install, service, update, uninstall | [`packaging.md`](packaging.md) |
| Errors and remediation lines | [`errors.md`](errors.md) |
| Diagnose a failure | [`doctor.md`](doctor.md), [`troubleshooting.md`](troubleshooting.md) |
