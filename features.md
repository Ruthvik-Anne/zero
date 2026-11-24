# Zero: features, research, and tooling inventory

Reference inventory of the pre-rewrite system, moved to `old/`. This records
what existed, what is worth keeping, and where the evidence lives.

---

## Part 1: Features of Zero

### Core model

- **Recursive Language Model (RLM).** The model works inside a persistent
  IPython kernel and composes capabilities as code instead of one tool per
  capability. Reading, editing, shell, search, skills, and delegation all start
  from `ipython`. Variables, imports, functions, and parsed results survive
  across tool calls and compaction.
- **Continual Harness.** Supplemental prompts, memories, skill descriptions,
  and reusable subagent specs are durable state. `/refine` applies small,
  evidence-backed updates with recorded history and snapshots for rollback. It
  never rewrites the immutable base system prompt.
- **Programmatic subagents.** `await rlm("task", name=...)` admits a child and
  returns a handle immediately; results arrive via `agent_message` or files,
  never as an `rlm()` return value. Children inherit model, provider config,
  skills, tools, retry policy, and resource loader.
- **Parent-scoped child registry.** `rlm.list_subagents()` and
  `rlm.delete_subagent()` survive compaction, kernel restart, and parent
  restoration.

### Agent runtime

- **Daemon-backed sessions.** Each root session tree runs in a resident worker
  process. Closing the terminal detaches the client; the worker keeps running.
  Reattach with `zero attach`.
- **Session workers and supervisors.** A detached supervisor owns routing,
  attachments, worker health, message delivery, command journalling, and
  coordinated updates. A catalog subprocess handles saved-session scans.
- **Process isolation for recovery, not security.** Workers and kernels are
  separate processes with the same OS permissions as the client.
- **Crashes contained per root tree.** Recovery retries at 250 ms, 1 s, and
  5 s; three failures mark that root failed. A new supervisor adopts live
  workers and active-session IDs.
- **Session leases.** Process-safe lease per canonical JSONL path prevents
  concurrent writers; concurrent creates converge on one worker.
- **Idempotent commands.** Mutations keyed by `clientId + commandId`, journalled
  before dispatch; uncertain side effects are reported, never replayed.
- **Reconnect and replay.** Generation-aware `{ generation, sequence }` cursors,
  coherent attach snapshots, bounded chunked snapshot streaming, file-backed
  transcript caches above 4 MiB.
- **Attachment-local backpressure.** A blocked client stops receiving events
  without stalling other clients or workers; no unbounded per-client queues.
- **Coordinated updates.** Two-phase prepare/validate/commit before stopping
  workers; a failed prepare leaves every root running.

### Long-running and background work

- **Heartbeats.** `/heartbeat every 10m ...` with status, pause, resume, clear,
  and `--follow-up` delivery.
- **Agent-created heartbeats.** `rlm_heartbeat.create/list/update`, separate
  from the user-owned heartbeat.
- **Schedules.** `zero schedule add <agent> "in 30m" -- "..."` or cron. Ticks
  are claimed before delivery, missed ticks coalesce, jobs persist per session.
- **Persistent goals.** `/goal` keeps an objective across turns with token,
  time, and continuation accounting until complete, paused, or cleared.
- **Bounded autonomous mode.** `/autonomous` adds continuations until configured
  quality gates pass or turn/token/time limits are reached. Failed gates return
  bounded output; an unchanged workspace does not rerun the same gate.
- **Direct agent-to-agent messaging.** `agent_message.list_agents/send` with
  `auto`, `steer`, and `follow_up` modes, delivery receipts, size/rate limits,
  and family-scoped broadcast.
- **Automatic compaction.** Summarizes older context, retains recent messages
  and kernel state, and is not a completion signal.

### Sessions and context

- Named, resumed, forked, cloned, and tree-structured sessions (`/tree`,
  `/fork`, `/clone`).
- Branch summaries with cumulative file tracking and structured sections:
  goal, constraints, progress, decisions, next steps, critical context.
- Session compaction with cut-point rules and extension hooks
  (`session_before_compact`, `session_before_tree`).
- JSONL transcripts plus session artifacts; message, model-change,
  thinking-level, service-tier, compaction, branch-summary, custom, child-usage,
  label, info, state, status, and git-state entries.
- Context-file loading from `AGENTS.md` and `CLAUDE.md`.

### Providers and models

- Subscription logins: OpenAI Codex, Claude Pro/Max, GitHub Copilot.
- API-key and auth-file providers: Anthropic, OpenAI, Google, Groq, Cerebras,
  xAI, OpenRouter, Z.AI, Mistral, MiniMax, Moonshot/Kimi, Hugging Face,
  Fireworks, Cloudflare Workers AI and AI Gateway, OpenCode and OpenCode Go,
  Xiaomi, Vercel AI Gateway.
- Cloud providers: Azure OpenAI, Amazon Bedrock, Google Vertex AI.
- Custom and overridable providers, custom headers, per-model overrides,
  thinking-level maps, Anthropic-messages and OpenAI compatibility shims.
- Generated catalogue from models.dev plus per-provider overrides.
- Router package with retry/backoff, a usage ledger, and model classification
  used for routing decisions.
- Provider fallback, service tiers, model cycling, and `/login` / `/models`
  flows.

### Customization

- **Skills.** Agent Skills `SKILL.md` format plus Python-backed skills installed
  into the kernel and callable by import name. Built-in skills include websearch,
  browser, goal, compact, advise, agent-message, agent-observe, ask-user,
  attach-image, edit, linear, notion, refine, rlm-heartbeat, skill-creator,
  vault, and the Prime Intellect skill.
- **Extensions.** Rich lifecycle API: resource, session, agent, model, tool,
  bash, and input events; custom tools, commands, shortcuts, flags, message
  renderers, autocomplete, widgets/status/footer, dialogs, custom editor, theme
  colors, custom providers, and session navigation (`newSession`, `fork`,
  `navigateTree`, `switchSession`, `reload`).
- **MCP integrations.** Declared servers, shipped skill packages,
  enable-by-login lifecycle, and a documented `McpIntegration` API.
- **Packages.** Install from npm, git, or local path; convention directories,
  dependency resolution, filtering, enable/disable, scoping, deduplication.
- **Themes.** Full color-token system (core UI, backgrounds, markdown, diffs,
  syntax, thinking borders, bash, HTML export), 256-color palette, custom themes.
- **Keybindings.** Fully configurable action map, Emacs and Vim examples, no
  hardcoded key checks.
- **Prompt templates.** Project and user templates with arguments and loading
  rules.

### Interfaces

- Interactive TUI with editor features, message queue, overlays, fullscreen
  transcript, subagent tray, and status/footer widgets.
- Print mode, JSON mode, RPC mode (LF-delimited JSONL with streaming events),
  and ACP mode.
- SDK: `createAgentSession`, `createAgentSessionRuntime`, `AgentSession`,
  `ResourceLoader`, custom tools, extensions, and in-process run modes.
- CLI surface: `zero agents|attach|list|rename|stop|status|doctor|update|
  shutdown|send|schedule`, `--resume`, autonomous flags, model/tool/resource
  flags, and file arguments.
- Shell aliases and platform setup docs for tmux, Termux, Windows, Kitty,
  iTerm2, Ghostty, WezTerm, VS Code, and Windows Terminal.

### Safety and observability

- Plan, auto, and manual modes.
- Git-backed rollback plus session checkpoints.
- Audit log and loop auditor for agent behaviour.
- Usage/cost accounting, child usage attribution, context usage, and token
  budgets.
- Explicit trust model: the kernel is a durable control environment, not a
  sandbox; untrusted repositories need an external sandbox.

---

## Part 2: Research, audits, and findings

The wiki database (`old/.repowise/wiki.db`) has schemas for health findings,
dead-code findings, decisions, graph metrics, coverage, and external systems,
but every analysis table is empty. The substantive research is in the documents
and data below.

### 1. Claude Code parity research and plan

Sources: `old/packages/coding-agent/docs/zero-claude-parity-spec.md`,
`zero-claude-parity-plan.md`, `zero-tui-agent-upgrade-spec.md`.

Worth keeping:

- Classify every parity item as retain-and-polish, required, capability-gated,
  or not-applicable. Do not present decorative parity.
- UX contract: identity-based selection indexes, never presentation-only
  headings; loading keeps cached rows; one provider failure does not erase
  others; empty states distinguish no models, no auth, and no matches.
- Async lists preserve input and selection, and reject stale generations.
- Prompt doctrine is advisory only; permissions must be enforced by one central
  evaluator before native, extension, MCP, and subagent tool calls.
- Never hardcode key checks; never block render/input loops on I/O.
- Weaker-model contract: instruction precedence, untrusted tool output, bounded
  steps, evidence before completion, approach change after failure,
  compaction-safe durable notes.
- Phased delivery as independently testable vertical slices.
- Gated features: Vim mode, prompt suggestions, voice input, per-shell
  backgrounding, status scripts, agent teams, worktree orchestration, remote
  control, computer use.

### 2. Code review rules (`.cursor/BUGBOT.md`)

- Delete migration/refactor scaffolding when the migration lands: no alias
  types, compatibility re-exports without a live consumer, or migration-era
  vocabulary in names, comments, or test titles.
- Flag options/constants with exactly one legal value at every call site.
- Flag exported symbols, fields, and methods with zero non-test consumers.
- Flag predicates equivalent to an existing check and duplicate conditions
  spelled two ways.
- Comments only where code cannot express intent; no history or control-flow
  narration.
- Regression tests only for meaningful behaviour that fails before the fix; no
  incidental, duplicate, or label-restating snapshot assertions.

### 3. Security policy (`old/SECURITY.md`)

- Private disclosure only; never public issues for vulnerabilities.
- Reports include affected version/commit, component and environment,
  reproduction or minimal PoC, expected vs observed impact, and mitigations.
- Never include real keys, tokens, personal data, or credentials; use redacted
  or disposable values.
- Fixes target the default branch; older versions are not guaranteed.

### 4. Daemon architecture findings (`daemon.md`)

- Generation-aware cursors make replay correctness explicit instead of implicit.
- Idempotency journal plus "uncertain, do not replay" is the right crash model
  for side-effecting agent work.
- Leases keyed by canonical path are simpler and safer than global locks.
- Stream compact start/delta/end payloads between worker and supervisor, and
  reconstruct the public event once per delta; do not resend the growing
  assistant message.
- Large snapshots must be streamed as opaque chunks; the supervisor must never
  build a history-sized object.
- Backpressure must be per attachment, never a shared queue.
- Update preparation must be non-destructive and validated as an aggregate
  before stopping anything.
- Benchmarks cover fanout, attach, serialization count, throughput, elapsed
  time, and sampled RSS, including 100 MiB and 500 MiB synthetic sessions and a
  50-worker stress case.

### 5. RLM runtime findings (`rlm.md`, `rlm-runtime.md`)

- One model-facing tool (`ipython`) is a coherent design; everything else is a
  library call.
- Subagent admission returns a handle, not a result. This keeps the parent
  context focused and avoids blocking turns.
- Authoritative state (credentials, providers, transcripts, routing,
  scheduling) stays in the TypeScript host behind typed host requests.
- Child registries and usage attribution must be parent-scoped and survive
  kernel restart and compaction.
- The trust boundary is explicit: model-generated Python runs with worker
  permissions.

### 6. Model classification research

Sources: `old/llm_classification_2026_full.json`,
`old/packages/ai/src/router/model-classification/` (73 models, five tiers).

Method worth reusing:

- Weighted rubric: coding 50%, reasoning 40% (weight rises with tier),
  instruction following 10%.
- Relative percentile binning over the real score distribution rather than
  fixed absolute cutoffs.
- Demotion rule: if coding exceeds reasoning by two or more points, demote one
  class.
- Distinguish verified third-party harness results from provider self-reports.
- Sources: BenchLM, Terminal-Bench 2.1, LMArena, CodingFleet, Artificial
  Analysis, PricePerToken.
- Top tier is SS ("Apex"); five tiers total, each with model, provider,
  parameters, weights type, hosting, per-axis benchmarks, relative grades,
  pricing, and rationale.
- The router consumes this to select models by required capability instead of a
  single global default.

### 7. Measurement tooling as research

- `old/scripts/edit-tool-stats.mjs`, `read-tool-stats.mjs`,
  `session-context-stats.mjs`, `session-transcripts.ts`, `tool-stats.ts`,
  `stats.ts`, `cost.ts` — transcript-driven analysis of tool use, context
  growth, and cost.
- `old/scripts/bench-attach-bytes.mjs`, `bench-daemon-startup.mjs`,
  `boot-bench.mjs`, `profile-coding-agent-node.mjs` — startup, attach, and
  profile measurement.
- `old/scripts/check-installer-render.mjs` — renders the installer at many
  terminal sizes to catch layout regressions.
- `old/scripts/check-browser-smoke.mjs`, `browser-smoke-entry.ts` — browser
  bundle smoke check.

---

## Part 3: Installation and operational scripts

### `old/install.sh` (POSIX `sh`, `curl | sh`)

- Forkable target via `ZERO_GITHUB_REPO`; no CDN or bucket.
- Release channels `stable` and `beta`; `beta` is a force-moved floating tag.
  `ZERO_RELEASE_CHANNEL`, `ZERO_VERSION`, `ZERO_PACKAGE`, and `ZERO_CMD` override
  behaviour. Version arguments accept `stable`, `beta`, or an explicit version.
- Animated full-screen installer with a responsive ASCII lab field and logo
  that adapts to terminal width and height, framed with synchronized-output
  escapes; falls back to plain text without a TTY.
- Install lock prevents concurrent installers; traps and signal handlers restore
  the terminal and clean temp directories.
- Preflight checks Node.js >= 20.6.0 and npm, and reports any existing `zero`
  binary on `PATH`.
- Interactive Node installation by Homebrew, apt, apk, or a standalone tarball
  with checksum verification; detects whether sudo or su exists and gives
  actionable guidance instead of a raw permission error.
- Downloads all four release tarballs (main, ai, core, tui) and verifies them
  against `SHA256SUMS`.
- Global `npm install` with a one-time privilege retry through sudo or su, and
  plain-language failure help that points at a log file.
- Optional IPython bootstrap: installs `uv`, Python 3.11, `ipykernel`, and the
  Zero runtime. Controlled by `ZERO_BOOTSTRAP_KERNEL_ON_INSTALL`.
- Preloads search tools with `ZERO_BOOTSTRAP_TOOLS_ON_INSTALL=1`.
- Adds standalone Node to the detected shell profile and explains manual PATH
  steps when it cannot.
- `curl` retries (`--retry 5 --retry-delay 1 --retry-connrefused`) to survive
  release-CDN connection resets.

### `old/install.ps1` (Windows, `irm | iex`)

- Forces TLS 1.2 for older Windows PowerShell and disables the slow progress
  bar.
- Retry wrapper for downloads and GitHub API calls.
- Node installation through winget, or a portable Node zip with no admin
  rights.
- Per-user PATH update; version resolution for stable and beta; checksum
  verification; install lock; conflict detection.
- Non-interactive/CI mode continues without confirmation instead of hanging.
- Same optional IPython bootstrap as the shell installer.

### `old/zero.sh` (source launcher)

- Exports `ZERO_LAUNCHER_PATH` and a `ZERO_BUILD_ID` from
  `git describe --tags --always --dirty`.
- `--no-env` unsets every provider credential for clean-auth testing.
- `--dist` runs the bundled build instead of `tsx`, documented as roughly 3x
  faster startup.
- Forwards all other arguments to the CLI.

### `old/test.sh` (credential-isolated test run)

- Backs up and restores `auth.json` around the run via an `EXIT` trap.
- Unsets every provider key and token.
- Sets `PI_NO_LOCAL_LLM=1` to skip local Ollama/LM Studio tests.

### Release and packaging scripts (`old/scripts/`)

- `pack-zero-release.mjs` — packs the four packages and rewrites the
  coding-agent tarball's internal `@zero-agent/*` dependencies to relative
  `file:` references so adjacent tarballs install correctly.
- `release.mjs` — version bump, changelog finalization, commit, tag, publish,
  and new `[Unreleased]` sections.
- `build-binaries.sh` — binary build pipeline.
- `sync-versions.js` — lockstep version sync across packages.
- `render-logo.py`, `preview-installer-splash.sh` — installer artwork preview.
- `setup-kernel-venv.sh` — kernel virtual environment setup.
- `test.sh`, `zero.sh`, `install.sh`, `install.ps1` are documented above.

### CI workflows (`old/.github/workflows/`)

- `ci.yml` — checks and tests; builds before test runs.
- `build-binaries.yml` — pushes to `main` refresh the floating `beta`
  prerelease; `vX.Y.Z` tags publish a production release with the four tarballs
  and `SHA256SUMS`. Manual `workflow_dispatch` accepts a `release_tag`.
- `contribution-gate.yml` — guards contribution intake.
- `nightly-process-stress.yml` — scheduled multi-worker/daemon stress run.

---

## Part 4: Uncommitted work that was in the tree

- **Operating contract** in the RLM prompt: DISCOVER -> PLAN -> EXECUTE ->
  VERIFY -> RECOVER -> DONE, instruction precedence, untrusted tool output,
  evidence before completion, approach change after failure, compaction-safe
  notes. Tests in `old/packages/coding-agent/test/system-prompt.test.ts`.
- **Model selector rewrite**: provider grouping, current/recent/sign-in labels,
  flat fuzzy search, preserved selection across refresh, explicit
  loading/error/no-auth/no-models/no-match states, short-terminal support.
- **Refresh plumbing**: `setModelRefreshState` on the configuration menu and
  selector; inline loading and error handling instead of toasts.
- **Mode cycling**: works from the child-agent tray; `Alt+M` fallback on
  Windows.
- **Composer keys**: `app.screen.redraw` on Ctrl+L; model selector on Alt+P;
  Ctrl+D requires a second press within 800 ms with a hint that clears on
  typing.
- **Regression tests**: cycle, status, selector actions, scoped model order, and
  system prompt.
- **Design docs**: Claude parity spec, implementation plan, superseded TUI
  upgrade spec.

---

## Part 5: Keep for the rewrite

1. Programmatic execution as the primary model interface.
2. Admission-handle subagents with message/file result delivery.
3. Durable state that outlives a turn: goals, heartbeats, schedules, children.
4. Daemon isolation with generation cursors, leases, idempotent journals, and
   attachment-local backpressure.
5. Capability-gated features with explicit loading, error, and empty states.
6. Central permission evaluation, never prompt-only enforcement.
7. Configurable keybindings and identity-based selection state.
8. Honest trust boundaries and non-blocking render/input paths.
9. Measured claims: benchmarks for startup, attach, serialization, and
   session size.
10. Installers that verify checksums, survive permission and network failures,
    and degrade gracefully without a TTY.

---

## Part 6: Target system specification

Parts 1-5 describe the archived system. This part is the specification for the
rebuild. It is a set of requirements, not a description of existing code.

### 6.0 Ground rules

- **Concept-only reuse.** When we "use" Claude Code, Codex, OpenCode, Kimi Code,
  DeepSeek Harness, Hermes, or Tencent's work, we mean we read and understand
  the idea and implement our own version. No packages, no vendored source, no
  MCP servers, no borrowed runtime. The only code in the tree is ours.
- **No external endpoint dependency for core capability.** Web search, fetch,
  crawl, tool search, deletion guarding, and the agent loop are implemented in
  this repository. A hosted provider is an optional adapter, never a required
  hop. If an adapter is unavailable, the core feature still works or degrades
  to an explicit, honest "unavailable" state.
- **Feature flags are reserved for Halcyon-linked features.** See 6.15. Core
  and optional subsystems are controlled by ordinary configuration, not flags.
- **Dependency policy.** "No packages" means no borrowed agent-harness code
  (Claude Code, OpenCode, Codex, Kimi, DeepSeek Harness, Tailscale, NetBird,
  Firecrawl, MCP servers). Audited, general-purpose building blocks are allowed
  where hand-rolling would be unsafe or absurd: a WireGuard implementation,
  SQLite, the IPython kernel, a TLS and crypto library, and a headless browser
  engine. Rules: permissive licences only (Apache-2.0, MIT, BSD, public
  domain), pinned versions and hashes, an SBOM, every runtime download
  checksum-verified, and no dependency that is a wrapper around an agent
  harness. Adding a dependency requires a recorded decision.
- **Threat model.** The primary threat is accidental harm by a well-meaning
  agent (wrong delete, wrong overwrite, wrong mode, runaway cost) plus hostile
  content reaching the agent (prompt injection from web pages, repositories,
  MCP output, and images). A determined local attacker with the same OS
  privileges is out of scope; optional OS-level sandboxing hardens it but is
  not claimed as a guarantee. See 6.18.
- **Nothing is claimed verified without a fresh run.** Unknown beats a guess.
- **No faux backends.** Never build a stand-in, demo, or parallel version of a
  component. Integrate the real thing or report it as missing.

### 6.1 Surfaces

**Desktop app (DeepSeek Harness concept, our code).**

- Electron-style shell around a local web UI. Loopback-only by default.
- Everything-is-a-plugin seams: model adapter, tool registry, session log,
  agent loop, and UI panels each replaceable without a privileged core.
- Profiles and bundles: named plugin compositions with a user overlay layer.
- Append-only session log that can be inspected, resumed, forked, searched, and
  replayed.
- Plugin manager plus a "creator mode" that can author a plugin from chat.
- Permission and sandbox policy as one seam, enforced centrally.
- Headless, ACP, and SDK surfaces over the same core, not separate binaries.
- Desktop packaging and signing owned by the release pipeline.

**TUI (Kimi Code concept, our code).**

- True-color, millisecond-startup terminal UI on our own renderer.
- Plan mode, shell mode (`!`), backgrounded commands, task panel.
- Built-in coder/explore/plan subagents with isolated contexts.
- Lifecycle hooks that can gate tool calls, audit decisions, and notify.
- Image and optional video input.
- Fullscreen transcript mode with folded tool calls and thinking blocks.
- Themes and a complete, remappable keybinding set.

**Keybindings (all surfaces).**

- One action registry shared by TUI and desktop, with per-surface defaults.
- Users can remap, disable, or bind chords; no hardcoded key checks anywhere.
- Platform fallbacks where a chord cannot be distinguished (for example
  back-tab on Windows) are declared in the default, not special-cased in code.
- Conflict detection, a generated help panel, and `/help`-style discovery.
- Keybindings are configuration, never build-time constants.

**Commands and actions.**

There is one model for every command, slash command, and menu item: a typed
**action** in a shared registry. Each action is available from the TUI, the
desktop app, the web app, and the Android app, and is callable by the agent when
the action allows it. Surfaces render the registry; they do not own commands of
their own.

- **Action record:** id, title, description, category, aliases, argument schema,
  required capabilities, mutating or read-only, deterministic or not, policy
  class, approval requirement, whether the agent may invoke it, whether it may
  run unattended, idempotency key, and audit metadata.
- **Two forms, one implementation.** An action is either **slash-first** (typed
  as `/name`, because it is deliberate, dangerous, or part of a workflow) or
  **native** (reached from a button, menu, palette entry, shortcut, or automatic
  trigger). Both call the same code and write the same audit record.
- **Discovery:** a command palette with fuzzy search, grouped by category,
  reachable from every surface, with generated help.
- **Deterministic actions run automatically.** When an action is marked
  deterministic and its inputs are known, the system executes it without a model
  call: no token cost and no variance. Non-deterministic work stays agentic.
- **The agent can trigger actions.** `actions.list` and `actions.run(id, args)`
  expose the registry. An action marked agent-invocable can be called directly.
  Policy decides, not the surface: the same action gets the same allow, ask, or
  deny from a person or an agent, and `mode_change`, `credential`, `delete`, and
  `install` stay gated by their action class (6.10.6).
- **Only these stay on the command line:** `zero resume`, `zero login`,
  `zero logout`, `zero doctor`. Machine-level lifecycle also stays there:
  `zero install`, `zero update`, `zero uninstall`,
  `zero service <start|stop|status>`, and shell completion. Every other command
  is an in-app action. No hidden subcommand is a second path to an action.
- **Scripting and headless.** Headless runs, one-shot execution, the SDK, ACP,
  and MCP server mode drive the app through the protocol and the action registry,
  never through new CLI verbs.
- **Realtime.** Each action declares what it subscribes to and emits, so the UI
  updates from the same event stream the agent sees.
- **Extensions add actions.** A plugin, skill, or MCP server may register
  actions. They are namespaced, inherit every rule above, and cannot shadow a
  core action.
- **No decorative controls.** If an action does not need explicit invocation,
  it has **no button, no menu entry, and no slash command**. It either runs
  automatically when its condition holds, is reached by a keybinding, or is
  simply visible as state. A control that exists only to be clicked is a defect.

**The registry, as decided**

*Implicit: no slash command, no button.* Runs automatically, by keybinding, or
as state:

| Action | Invocation |
|---|---|
| Mode switch | `Shift+Tab` cycles; `/mode` is not offered (6.10.6) |
| Project create, list, show, bind, move, rename, key recovery | automatic; recovery UI appears only when a project is broken |
| Init and refresh project instructions | state-driven: offered inline when `AGENTS.md` is missing or stale, never a command |
| Secret request and `.env` sync | agent-triggered; the secrets UI appears only when a tag is needed (6.22) |
| Shell and background commands | a leading `!` runs a shell command directly; agent-run commands show in the jobs panel |
| Session and worker switching | `Ctrl+B` opens the daemon app (below) |
| Monitors | plugin- or session-triggered; events appear as they arrive (6.10.5) |
| Approvals and questions | appear only when an action is blocked |
| Self-improvement (`/reflect`, `/promote`, `/rollback`) | automatic or agent-triggered with human approval on promotion (6.7) |
| Daemon, worker list, attach, detach, stop | the separate daemon app (below) |
| Mesh up, join, leave, rename, status, doctor | user-only panel, opened with `/node`, surfaced by state (7.2) |
| Halcyon status, task board, joker and epb views | panels that reflect state (6.6) |
| Task and todo lists, context meter, usage meter | always-visible state, no command |

*Slash-first: explicit invocation.*

| Command | Area |
|---|---|
| `/help` | action discovery and generated help |
| `/compact`, `/rewind`, `/fork`, `/clone`, `/tree`, `/rename`, `/delete`, `/export`, `/share` | sessions and chat |
| `/link` | explicitly share one project identity across paths (never for copies; AI-triggerable) |
| `/models`, `/accounts`, `/route`, `/usage` | accounts, models, routing, spend |
| `/secrets` | open the secrets surface yourself (the request path is agent-triggered) |
| `/permissions` | allow, ask, deny matrix |
| `/context`, `/memory`, `/skills` | context, durable memory, skills |
| `/goal`, `/heartbeat`, `/autonomous` | long-running work |
| `/plan`, `/tools`, `/mcp`, `/node` | plan artifact review, tool inventory, MCP servers, mesh panel |
| `/teleport`, `/resume` | move or recover a session |
| `!` prefix | run a shell command directly, without the model |
| `/security-review`, `/cost-audit`, `/doctor`, `/ledger` | audit, review, diagnosis, records |
| `/theme`, `/keybindings`, `/transcript`, `/layout` | display and interface |

*Command line: exactly four commands*, plus machine-level lifecycle:
`zero resume`, `zero login`, `zero logout`, `zero doctor`; and `zero install`,
`zero update`, `zero uninstall`, `zero service <start|stop|status>`, completion.
`/login` and `/logout` are not offered in the app because the CLI owns them.
`/doctor` opens the doctor panel, which is the same action as `zero doctor`
with a view attached.

**The daemon has its own app.** Workers, attachments, health, updates, and
history live in a separate daemon surface with its own UI, reachable through
`/daemon` and `/update`. Worker list, rename, attach, detach, stop, and
inspection are actions inside that surface, not commands anywhere else.

### 6.2 Tool system and tool search

Core tools loaded every turn: `ipython`, `tool_search`, `trash`, `web_search`,
`web_fetch`. Everything else is deferred.

- **Registry metadata per tool:** name, description, argument names and
  descriptions, tags, examples, risk class, cost class, scope, and whether it
  is deferred.
- **`tool_search(query)`**: BM25 over the registry plus optional regex mode and
  optional embeddings. Searches names, descriptions, arguments, tags, and
  examples. Returns the 3-5 best tools and loads their full schemas.
- **Context-based activation:** rules over file extension, working directory,
  git state, detected language, task keywords, and recent tool use surface
  candidate tools before the model asks. Activation is advisory: it only makes
  discovery cheaper.
- **Thresholds:** load everything while definitions stay under roughly 1-5% of
  the context window; switch to progressive discovery above that.
- **Lifetime:** discovered tools stay loaded until compaction, then are
  rediscovered on demand.
- **Telemetry:** record what was surfaced, chosen, rejected, and failed, so the
  self-improvement loop can tune descriptions and activation rules.
- **Accuracy guard:** flag near-duplicate tool names and ambiguous descriptions
  at registry build time.
- **Scope of discovery.** `tool_search` indexes native tools, kernel library
  functions (`files.*`, `todo`, `monitor`, `doctor`, `task`), MCP tools, and
  skills in one registry. The model-facing surface stays small: `ipython`,
  `tool_search`, `trash`, `web_search`, `web_fetch`. Native tools are also
  importable inside the kernel; both routes enforce the same policy.
- **Cache safety.** Newly discovered tools are appended after the stable prefix,
  never inserted before it, so provider prompt caches are not invalidated.
- **Ranking trust.** Native tools outrank MCP tools on ties. Name or
  description stuffing by a server cannot lift it above a native tool. Tools
  denied in the current mode are not surfaced.

### 6.3 IPython kernel

- One persistent kernel per root session, preloaded with `web_search`,
  `web_fetch`, `web_crawl`, `tool_search`, `trash`, and the Halcyon adapters
  when that mode is active.
- Python state, imports, helpers, parsed results, and task handles survive
  across tool calls and compaction.
- `%%bash` cells run in a throw-away subshell; `%cd` and Python state persist.
- Typed host requests carry capability calls whose authoritative state lives
  outside the kernel (sessions, providers, transcripts, scheduling, deletions).
- Kernel restart rehydrates from the session log; in-flight work is reported,
  not silently lost.
- Output capture with truncation, streaming, and byte/token accounting.
- Resource limits and a documented trust boundary: the kernel runs
  model-generated code with the worker's OS permissions.

#### 6.3.1 File editing tool

Goal: edits are cheap, safe, and batchable, and the model never has to re-emit
file contents or carry a file body in context.

**Model.** Files are handles, not text.

- `f = files.open(path)` returns a handle, a version token (content hash,
  size, mtime), line count, encoding, and newline style. It does not return
  contents.
- `files.read(f, start, end)` and `files.find(f, pattern)` return only the
  requested slice or matches.
- `files.edit(f, ops)` applies a batch in one call.
- `files.batch([...])` applies ops across several files in one call.
- Handles are cheap values in the kernel; they hold no file body in the
  prompt.

**Operations.**

- `replace(anchor|range, text)`, `insert(after, text)`, `delete(range)`,
  `wrap(range, before, after)`.
- `move(from, to)`, `copy(from, to)`, `rename(path)`.
- `write(path, text)`, `patch(unifiedDiff)`.
- Anchors are content-addressed: the exact span text or its hash, plus an
  optional line range. Drift fails closed instead of editing the wrong lines.

**Receipts.**

- Success returns `{ ok, files: [{ path, applied, newVersion }], firstError? }`.
  No diff and no file body.
- Failure returns one line per problem: path, op index, reason, and at most a
  three-line context window. Never the whole file.
- `verbose: true` returns a unified diff only when explicitly requested.

**Safety.**

- Optimistic concurrency: verify the version before writing; a changed file
  returns `stale` and the caller retries with a fresh read.
- Atomic writes via temp file plus rename; preserve mode, encoding, BOM, line
  endings, and symlink targets.
- Per-file locks and batch locks; concurrent batches on the same file
  serialize.
- Batches are all-or-nothing by default; `continueOnError` is opt-in.
- Refuse binary files unless explicitly forced. File deletion is not an edit
  operation; it belongs to `trash`.
- Dry-run and an undo journal; every applied batch is reversible.
- No auto-format by default; a formatter can run after an edit when configured.

**Context economy.**

- N edits become one tool call and one compact receipt.
- Reads are sliced; the tool never echoes a full file into the transcript.
- Errors are bounded to the failing span.
- Handles, versions, and hashes are the only persistent representation.
- The edit journal is part of the session snapshot, so teleport and auto-resume
  keep edit history without replaying file bodies.

**Performance.**

- Lazy line index per file; small edits cost O(edits), not O(file size).
- Large files are edited by range without loading the whole file where the
  platform allows, otherwise streamed.
- Grouped fsync and atomic renames for batches.

### 6.4 Deletion safety

Purpose: **prevent accidental deletion by an AI agent.** This is a guard against
mistakes, not a defence against a hostile local user. Deletion is denied by
default and allowed only through the `trash` tool; anything deleted that way is
recoverable. The goal is that a wrong command costs the user nothing.

**Layers (each catches mistakes the previous one misses)**

1. **Command guard.** Parse every shell command before execution, for POSIX
   shells, PowerShell, and `cmd`. Block `rm`, `rmdir`, `unlink`, `shred`,
   `truncate`, `find -delete`, `find -exec rm`, `xargs rm`, `rsync --delete`,
   `git clean`, `git reset --hard`, `git checkout -- <path>`, `git restore`,
   `git stash -u`, `git branch -D`, `tar --remove-files`, `dd` to a file target,
   redirections that truncate an existing file, `sed -i` without a backup,
   `mv`/`cp` onto an existing file, and the Windows equivalents: `del`, `erase`,
   `rd`, `rmdir /s`, `Remove-Item`, `[IO.File]::Delete`, `robocopy /mir`,
   `format`. Recognise wrappers (`sh -c`, `bash -c`, `powershell -Command`,
   `cmd /c`, `env`, `sudo`, `busybox`). Blocked attempts return an actionable
   message that names `trash`.
2. **Shims.** PATH shims and PowerShell function overrides catch destructive
   commands that reach the shell through scripts or Makefiles.
3. **Python guard.** An audit hook and import wrappers block `os.remove`,
   `os.unlink`, `os.rmdir`, `os.removedirs`, `os.truncate`, `shutil.rmtree`,
   `Path.unlink`, `Path.rmdir`, and overwrite-by-move (`os.replace`,
   `shutil.move` onto an existing file), raising a typed `DeletionBlocked`.
4. **Other surfaces.** Node `fs.rm`/`fs.unlink`, extension APIs, and every
   internal tool use the same policy evaluator. There is one policy.
5. **Safety net (backup before overwrite).** Overwriting or truncating a file
   destroys its old content, so every write, move-over, and truncate made
   through our tools first snapshots the previous content into the undo
   journal. A mistake that slips past layers 1-4 is still undoable.

**Honest limits.** Native extensions, `ctypes`, an absolute path to a binary,
or an obfuscated command can evade the guard. That is acceptable for the
accidental-harm threat model, and layer 5 plus the OS trash is the backstop.
Optional OS sandboxing (Landlock/seccomp, Windows job objects) can be added
later as hardening.

**Zero-owned data.** Zero may remove its own temp files, caches, expired
journals, and snapshots inside its data directories. That is internal garbage
collection, subject to a separate retention policy and logged. Atomic writes
(temp file plus rename) are internal and covered by layer 5.

**`trash(paths)`.** Moves files and directories to the operating system's
native trash and returns a per-path result.

- Windows: Recycle Bin through `IFileOperation`/`SHFileOperation`.
- macOS: `NSFileManager.trashItemAtURL`.
- Linux: freedesktop.org trash spec (`~/.local/share/Trash/files` plus
  `.trashinfo`), with `gio trash` as a fallback.
- Handles cross-device moves, read-only files, symlinks, open files, and long
  Windows paths.
- **Protected paths** are refused even by `trash`: the home directory, drive
  roots, `.git`, `.zero`, the audit log and journals, the credential store, and
  system directories. These need an explicit user action.
- Never permanently deletes. `purge` is a separate, **human-only** action:
  never callable by the agent, with a dry-run, explicit confirmation, and an
  audit record.
- Third-party code (MCP servers, plugins, monitors) runs under the same
  command guard where Zero launches it; Zero cannot guard code it did not
  launch.
- Modes: `trash` is a reversible delete class. It is `ask` in manual, per-class
  configurable in semi-auto, regulated in auto, denied in plan, and allowed in
  headless only under a pre-existing allow rule.

### 6.5 Web access as inherent tools

All of this is our implementation. No MCP server, no bundled package.

**`web_search`**

- Parallel keyless engines: DuckDuckGo, Bing, Yahoo Japan, and a long-tail
  engine. Optional engines enabled by configuration or keys.
- Reciprocal-rank fusion across engines, then deduplication by fuzzy title and
  canonical host plus path.
- Filters: freshness (`day`/`week`/`month`/`year`), include/exclude domains,
  category routing (papers, finance, news, software, security, weather), and
  required/forbidden substrings.
- Every result carries its age and where the date came from.
- Per-engine rate limits, exponential backoff, a circuit breaker, and a reserve
  engine. A CAPTCHA or login wall benches the engine and says so; it never
  fails the whole search.
- Markdown-first output with provenance and a token estimate.
- SQLite FTS5 cache with per-category TTLs and a cache-age filter.

**`web_research`**: search, fetch the top N pages, return one Markdown brief
with dated sources.

**`web_fetch`**

- Reader-mode extraction to Markdown, implemented in-house.
- JavaScript-heavy pages fall back to a local headless browser, installed on
  demand.
- Documents: PDF, DOCX, XLSX, PPTX, EPUB, CSV, code, text, archives.
- Images and binaries return metadata (type, size, dimensions, hash) instead of
  bytes unless inline output is requested.

**`web_crawl`**

- Our crawler with a persistent job store: frontier queue, robots.txt handling,
  sitemap discovery, depth and page limits, include/exclude path regexes,
  same-domain and subdomain rules, query-parameter deduplication, concurrency
  limits, retries, and resumable status.
- Job states (`queued`, `scraping`, `completed`, `failed`, `cancelled`),
  progress counters, result paging, and a separate errors list for pages that
  failed and URLs blocked by robots.
- Per-page cost accounting so a crawl can be budgeted before it starts.
- Polling, webhook, or streamed completion.
- Crawling is entirely local and always works without a key or a hosted
  service. Firecrawl is not a built-in backend and is not shipped. A user who
  wants it adds the Firecrawl MCP server through the regular MCP support; it
  then sits beside the native tools with no special-casing and no core
  dependency.

**Reach beyond crawl (native, Firecrawl-class capabilities)**

- `web_map`: discover a site's URLs from sitemaps and links without fetching
  every page.
- `web_extract`: fetch pages and return structured JSON against a caller
  schema, using the model pool for extraction.
- `browser`: our own browser automation over the DevTools protocol (navigate,
  click, type, wait, evaluate, screenshot, download), replacing the old browser
  skill. It is separate from desktop computer use in 6.12.

**Safety and reach limits**

- **SSRF protection** on `web_fetch`, `web_crawl`, `web_map`, and `browser`:
  block loopback, private, link-local, and cloud-metadata ranges, resolve DNS
  once and pin the address (no rebinding), re-check every redirect, and refuse
  `file://` and other non-HTTP schemes. Loopback is allowed only when
  explicitly enabled.
- **Untrusted content.** Page text, search snippets, and downloaded documents
  are data. They never become instructions, and they are labeled as untrusted
  in the transcript.
- **Egress control.** Outbound requests are checked for secrets in URLs,
  queries, and bodies. Per-mode network policy applies to every tool in this
  section; POST and other state-changing requests are not "read-only".
- **Archive and document safety.** Extraction rejects path traversal (zip-slip),
  symlink escapes, and decompression bombs, with byte, file-count, and depth
  limits. Parsing runs in a bounded worker.
- **Browser isolation.** The headless browser uses a fresh profile with no
  user cookies, its own network policy, and a checksum-verified download.
- **Politeness.** Honest user agent, per-host rate limits, `robots.txt` for
  crawls, and backoff on 429.
- **Search fragility.** Keyless HTML scraping breaks and can violate a site's
  terms. Each engine is an adapter with health checks, a kill switch, and an
  honest "engine unavailable" state. Queries are redacted of secrets and
  project-identifying text before leaving the device. API-key engines are
  supported where the user wants stability.

### 6.6 Halcyon mode

Halcyon mode is a file-bound, signature-gated feature flag. When it is not
present, it is invisible: no tools, no prompt text, no cost, no behavioural
change.

**Activation**

- Trigger file: `.halcyon-mode` (single file, no directory).
- Discovery walks the current directory, every ancestor up to the repository
  root, and immediate child directories (bounded depth, skipping
  `node_modules`, `.git`, and build output).
- Absent file: the module is not registered at all.
- Present file: the mode becomes eligible, then must pass the multi-exchange
  authentication in 6.6.1. The file is the switch; the environment alone can
  never enable the mode.
- The file is per-repository and is ignored by git by default.

#### 6.6.1 Halcyon file authentication

The goal is narrow: a repository must not be able to switch on Halcyon mode by
shipping a marker file. A static file cannot answer a live challenge, so the
design relies on a **signature verified against a key the user pinned**, not on
a nonce exchange. Contents are always data: never `eval`, never shell-expanded,
never imported.

1. **DISCOVER.** Find `.halcyon-mode` in the current directory, ancestors, or
   immediate children. Reject symlinks that resolve outside the repository.
   If several are found, the nearest to the working directory wins; two at the
   same distance is an error that disables the mode and reports why.
2. **PARSE.** Strict, schema-validated, size-capped parse of the file's
   canonical form. Unknown required fields fail closed.
3. **VERIFY.** The default and required method is an Ed25519 signature over the
   canonical bytes, checked against a public key pinned in the *user*
   configuration (never in the repository or project config). The signed bytes
   include the file version, the `projectId` (not the path), an issued-at time,
   an optional expiry, and a key ID. Fallbacks, explicit opt-in only:
   `passkey` (WebAuthn) and `password` with Argon2id for portable or legacy
   setups. Plaintext is discouraged and never the default.
4. **EVALUATE.** Run the file's `evals` list against the live runtime,
   read-only. Evaluations are declarative predicates, not code: the deletion
   policy is enforced, `trash` exists, the provider allowlist matches, cost and
   session ceilings hold, and required binaries (`tkb`, `joker`, `epb`) exist at
   a minimum version.
5. **ATTEST.** Compare the results to the file's `expect` block. A required
   mismatch fails closed.
6. **UNLOCK.** Issue a short-lived in-memory capability token bound to the file
   hash, `projectId`, process, and build hash. That token enables the mode. On
   any failure the mode stays hidden and the failure is logged without secrets.

**Key management**

- **Halcyon key** actions (keygen, sign, pin, unpin, rotate, revoke, verify)
  live in the Halcyon panel. They are user-only; the agent may read status and
  never sign or rotate.
- Key pinning is explicit (no trust-on-first-use). Multiple pinned keys,
  key IDs, expiry, and a local revocation list are supported.
- Private keys live in the OS keychain or a hardware key, never in the repo.

Constraints:

- Passwords are never logged or persisted; buffers are zeroised and compared in
  constant time. Failed attempts are rate-limited with lockout.
- The token invalidates on file change, `projectId` change, process restart,
  expiry, or explicit revoke. There is no persistent global "enabled" boolean.
- Binding uses `projectId`, so a move, a teleport, or another mesh device keeps
  working without re-approval, while a *copy* (new key, new `projectId`) needs
  its own signed file. Path and git remote are informational, not identity.
- The mode file in an untrusted workspace (6.18) is ignored until the folder is
  trusted *and* the signature verifies.
- The mode cannot be enabled by environment variables or project config alone.
- Adapters negotiate versions: each CLI (`tkb`, `joker`, `epb`) is probed for its
  version and capabilities; features it lacks degrade to disabled with a clear
  message, so upgrading a CLI never breaks Zero.

**Behaviour, encoded natively (never read from Halcyon's AGENTS.md)**

- Session start runs `tkb now` and either takes existing work or records what
  is about to be done.
- Every skipped item, discovered bug, scope addition, or missing endpoint is
  recorded with `tkb add` at the moment it is found, with a real component and
  a kind. A gap named only in prose is not recorded.
- Tests, vet, and build gates run only through `joker`. The verdict comes from
  `joker run` plus `joker watch` or `joker verify`. Falling back to a bare
  `go test`, `cargo test`, or `pytest` is a violation, not a shortcut.
- Endpoint work goes through `epb`: `list`, `need`, `requests`, `impact`,
  `change`, `sync`, `check`. No mock backend is ever created.
- Before finishing: `tkb check` must show zero errors, and a handover is
  written with `tkb handover write`.
- Token discipline: cheapest capable agent, bounded subagents (about 60 steps
  or 150k tokens, under 300 words of report), selective output, sessions under
  about 300k tokens, fresh session from handover after five minutes idle.
- Routing: the nearest repository rules win; Dawn and Aegis own their
  subsystems; Awan owns everything above them; KingKong is vendor-only.
- Verification: no claim without a re-run; unknown beats a guess.
- Dependencies: Apache-2.0, MIT, or BSD only; a licence blocker means
  clean-room or no change.
- Git: never push to `main` or `shared`; feature branch, then component
  branch, then PR. Sealed registries are never hand-edited.
- No faux backends; no stand-in services.

**Tool surface (concept adapters, no compile-time binding)**

- `tkb`: `now`, `list`, `start`, `add`, `note`, `done`, `block`, `check`,
  `handover`, `diff`, `branches`.
- `joker`: `run`, `watch`, `verify`, `status`, `slow`, `pg`.
- `epb`: `list`, `need`, `requests`, `impact`, `change`, `sync`, `check`,
  `done`.
- Adapters detect the CLIs at runtime. Missing binaries produce disabled tools
  that explain how to install them. Nothing is vendored, linked, or required
  at build time, so the mode keeps working when the tools are upgraded.
- Destructive shortcuts are refused by default: no `--force` bulk output, no
  branch pushes, no sealed-file edits.

### 6.7 Self-improving loop (Tencent concepts, our implementation)

Reference concepts, not code:

- **Terminal-RSI:** alternate recursive self-rewriting and policy refinement;
  verified trajectories become general, reproducible demonstrations; the
  stronger behaviour re-enters the environment and generates the next round.
  It directly targets "laziness": claiming success after partial completion.
- **DeepVerifier:** verification is easier than generation. Grade against an
  explicit rubric derived from a failure taxonomy instead of a single score.
- **Rehearse:** compare candidate changes before spending a run; keep a
  focused outcome memory; guard against the confidence cliff late in a loop.
- **SkillHone:** persist decision history (diagnosis, revision, evidence,
  outcome), not just the final artifact, so later rounds do not rediscover the
  same rationale.

**Our loop.** No weight training; improvement lands in skills, prompts, tool
descriptions, routing, and cost policy.

1. Execute the task.
2. Verify with the real environment, not self-report.
3. Capture the trajectory and the decision record.
4. Distill a bounded change: one skill edit, one prompt edit, one tool
   description, or one routing/cost rule.
5. Evaluate on a held-out set and on the original failure.
6. Promote with a version, evidence, and a rollback path; otherwise discard.
7. Re-enter and repeat.

**Guardrails.**

- The evaluator is versioned. The candidate may not modify its own acceptance
  test or holdout in the same run.
- Promotion requires fresh evidence; a passing gate proves only what it checks.
- Every accepted change is reconstructable, diffable, and reversible.
- The loop never runs concurrently with the task it is measuring.
- **Immutable core.** The loop may never modify the deletion policy, the mode
  and permission policy, the protected-path list, the audit log, the evaluator,
  credentials handling, or its own promotion rules.
- **Human gate.** Promotion into skills or prompts that loop-visible untrusted
  content could have influenced requires user approval. Web, repository, and
  MCP text is never a promotion source by itself.
- **Eval set.** Held-out tasks live in a versioned, local evaluation suite that
  the candidate cannot read or write. Building that suite is a prerequisite for
  slice 14.

**`/cost-audit`.** New slash command in the self-improving loop.

- Reads the session and provider ledger: input, output, cache reads, cache
  writes, retries, subagent share, per-tool cost, and wall-clock time.
- Reports dollars spent, cost per successful task, and the largest avoidable
  buckets. Cache writes, long cache reads, and subagent fan-out are expected
  to dominate, based on the archived spend analysis.
- Proposes bounded changes: cheaper model tier for the task class, cache
  hygiene (avoid cold resumes, shorter TTLs), context trimming, bounded
  subagents, fewer retries, routing changes.
- Applies only changes that are reversible, measures the next window against
  the previous one, and rolls back on regression.
- Default is analysis plus a proposal; `--apply` is required to change
  behaviour.

Companion commands: `/reflect` (draft a change from the last trajectory),
`/promote` (accept with evidence), `/rollback` (restore a prior version).

`/security-review` (6.23) is a native capability implemented with the same
behaviour as a skill, but it is invoked as a command and is not loaded through a
skill file or an MCP server.

### 6.8 Providers

- Add OpenCode Console as a first-class provider: documented endpoints under
  `https://opencode.ai/inference/...`, `oc_sk_` API key, paid or Go usage.
- Keep OpenCode and OpenCode Go providers.
- Provider access uses documented, authenticated routes. Client-identity
  spoofing and free-tier bridging are out of scope.
- Cost-aware routing: classification from model metadata, per-task tier
  selection, fallback chains, and the `/cost-audit` feedback loop.

### 6.9 Concepts to mine from other harnesses

- **Claude Code:** tool search and progressive disclosure, hooks, checkpoint
  and rewind, central permissions, plan mode.
- **Codex:** sandbox and approval modes, per-command policy.
- **OpenCode:** provider-grouped model dialog, TUI interaction patterns.
- **Warp:** base skill plus improver skill; human feedback as the training
  signal.
- **bmo:** four loops (build now, capture corrections, session reflection,
  periodic battery change).
- **Hermes/pi:** plugin and skill ecosystem, hot reload.
- **Cline/Cursor/Windsurf/Zed:** AGENTS.md-style project rules and per-tool
  guards.
- **Tencent:** Terminal-RSI, DeepVerifier, Rehearse, SkillHone.

### 6.10 Projects, conversation control, credentials, and monitors

#### 6.10.1 Projects (automatic)

A project is identified by a key, not by a path. The whole lifecycle is
automatic; the user should never have to run `project init`.

- **Creation.** On the first session in a directory with no `.zero/`, create
  `.zero/` and a key automatically. The key is 32 random bytes in
  `.zero/key` (mode 0600). It is an *identity*, not a secret: `projectId` is its
  hash, it is never used for authentication, and it is not stored in the OS
  secret store, so it travels with a copied or teleported folder. The name is
  derived from the directory basename, sanitised, with a numeric suffix on
  collision. When a git repository exists, add `.zero/` to `.gitignore` and say
  so (it is the one automatic edit to a user file). No prompt unless the
  location is not writable or policy forbids it.
- **Root detection.** Walk up from the working directory: nearest `.zero/`,
  else git root, else the working directory. Stop at the home directory or the
  filesystem root. A session started in a subdirectory attaches to the nearest
  project.
- **Moved project.** Same key, a new path, and no concurrent copy: rebind the
  path silently.
- **Copy detection.** The same key at two paths, locally or across the mesh,
  with independent histories is a copy. Pause once and ask for a new name,
  prefilled "<name> copy". On answer, create a new binding immediately: mint a
  new key, derive a new `projectId`, write a new `.zero/project.json` with
  `copiedFrom` provenance, and register the new path binding. The original
  project and its binding are left untouched. A non-interactive run uses the
  prefilled name and still creates the new binding, because silent sharing is
  worse than a duplicate.
- **Same project is explicit only.** Sharing one identity across two paths is
  never offered in the copy prompt. It requires the deliberate advanced action
  the **Link project** action, used for synced folders and never for copies.
It is deliberately not agent-invocable.
- **Replaced key.** A path whose key changed is ambiguous: ask whether to
  adopt the new identity or restore the previous one. Never silently discard
  history.
- **One decision per pair.** The copy prompt is shown once per key pair. The
  chosen name and the new binding are stored, so it never nags again.
- **Naming.** Automatic from the directory; `project rename` is optional.
  Copies get "<name> (copy)" and then a suffix.
- **Sessions.** Auto-named from the project and timestamp. Switching project by
  changing directory is automatic.
- **Migration.** Legacy layouts (`.pi`, older `.zero/` without a key) migrate
  once automatically and log what changed.
- **Sync.** Project keys replicate over the mesh; the same key on two devices
  is the same project at whatever path each device uses.
- **Escape hatches.** Recovery actions (init, list, show, bind, move, rekey,
  forget) live in the app and appear only when a project is ambiguous or
  broken. They are not agent-invocable, and scripts use the SDK.

The same principle applies to the rest of the project surface: automatic
unless there is genuine ambiguity or risk, and then exactly one prompt with a
safe default.

- **Ambiguity cases.** If the old path is unreachable (offline drive, another
  device, restored backup), a same-key arrival is ambiguous: ask once. On CI and
  other ephemeral checkouts there is no `.zero/`, so a headless run uses a
  stable project name from configuration instead of minting a new project per
  run.
- **`.zero/` layout.** `project.json` (id, name, `copiedFrom`), `key`, `config`
  (project policy, untrusted until the folder is trusted), `plan/`, `tasks/`,
  `todos/`, `journal/`, `artifacts/`, `vault/` (the encrypted secret vault and
  its tag index; see 6.22), and `audits/run-N/` (security review output).
  **No plaintext secret values and no credentials are ever stored here**, and
  the vault is ciphertext that is useless without a key held outside the
  repository. Agents cannot write `config`, `journal/`, `vault/`, or audit
  files (protected paths).

#### 6.10.2 Prompt queue and steering

- Messages typed while a turn runs are queued, persisted, and shown in the
  composer. They survive compaction, teleport, and auto-resume.
- Delivery modes: `steer` (inject into the running turn), `follow_up` (run
  after the current turn), `auto` (steer when busy, immediate when idle), and
  `interrupt` (cancel and replace).
- Steering lands at the next safe boundary. It cannot rewrite a tool call that
  is already executing; the tool result arrives first.
- Queue actions: edit, reorder, cancel, send now, take back.
- Queue limits and overflow policy are configurable; the default rejects new
  items with a clear message instead of dropping old ones.
- Keyboard shortcuts are configurable on every surface; desktop, TUI, and
  Android expose the same operations.

#### 6.10.3 Credential storage

OpenCode stores provider credentials as plaintext JSON or SQLite rows with
mode 0600. That is not secure storage, so we do not copy it. We keep the same
centralised credential model and put the secrets in the OS store.

- Storage order: OS keychain (Windows Credential Manager, macOS Keychain,
  libsecret/Secret Service); otherwise an encrypted file (AES-256-GCM with a
  key wrapped by DPAPI, Keychain, libsecret, or a user passphrase through
  Argon2id); otherwise refuse to persist and require per-session entry.
- Config holds secret references such as `{secret:openai/work}`, never
  plaintext. Environment variables work but are discouraged and listed as
  such.
- Provider accounts are named and multiple per provider are supported:
  `/accounts` and `/route` actions, with **Sign in** and **Sign out** owned by
`zero login` and `zero logout` on the command line. Export is redacted by
  default and needs confirmation to print a secret.
- MCP OAuth tokens, project keys, and mesh keys use the same store.
- Secrets are redacted from logs, transcripts, tool output, and crash reports.
  Buffers are zeroised; the store locks on screen lock and after idle.
- Import from plaintext `auth.json` is explicit, warns, and moves the old file
  to trash after a successful import.
- **Unattended hosts.** A daemon on a machine with no keychain unlocks through a
  machine-bound key (TPM, DPAPI machine scope, or `systemd-creds`) or a
  passphrase entered once at start. If neither exists, the host runs with
  per-session entry only and says so.
- **Child processes.** Bash, the kernel, monitors, and MCP stdio servers get a
  scrubbed environment: no provider keys, tokens, or `ZERO_*` secrets. The
  agent cannot read credentials through `os.environ`.
- **Token refresh.** One refresher per credential (cross-process lock) so
  rotating refresh tokens are never consumed twice. Revoked or expired tokens
  produce `AUTH_EXPIRED` and never a retry storm.
- **Teleport and mesh.** Credentials are per device by default. A target device
  either signs in itself, receives a credential through an explicit, approved,
  end-to-end encrypted transfer, or proxies model calls through the source
  device. There is no silent credential copy.
- Printing or exporting a secret is a user-only action, never an agent tool.

#### 6.10.4 Sign-in flows

- **OpenCode Console:** OAuth with PKCE in the browser, device-code fallback
  for remote shells, refresh tokens, account label, logout.
- **ChatGPT / Codex:** OAuth login, account ID, token refresh. If the Codex CLI
  is already signed in, offer a read-only reuse of that login instead of a
  second flow.
- **API keys:** paste or environment, validated before storing, multiple named
  accounts.
- Provider picker with search, per-provider methods, and enterprise URLs.
- Android and web controllers complete OAuth through a QR handoff and store
  the resulting token only on the device that will use it.
- **Terms of service.** Each subscription or OAuth flow ships only if the
  provider documents it for third-party clients. Flows that need client-identity
  spoofing, borrowed token files or client IDs, or pooled accounts are out of
  scope. Outcomes, checked against primary sources on 2026-11-24 and
  re-checked before each release:
  - **Claude Free, Pro, Max, Ultra sign-in: not offered.** Anthropic's Claude
    Code legal page says consumer OAuth is for Anthropic's own apps; developers
    must use API keys (Console, or Bedrock, Vertex, Foundry). It states that
    third parties may not offer Claude.ai login, route requests through plan
    credentials, or collect, store, or intermediate Claude.ai credentials or
    session tokens. Zero uses Claude by API key or a cloud provider only.
  - **ChatGPT plan sign-in: allowed through OpenAI's documented flow only.**
    OpenAI documents "Sign in with ChatGPT" plan usage for open-source and
    locally hosted apps (a preview): dynamic client registration, a
    system-browser PKCE flow on a loopback callback, the
    `chatgpt.tokens.use.direct` scope, and a per-host `ext_agent_host_id`.
    Paid or remotely hosted apps must file OpenAI's interest form instead.
    Preview limits: Responses API over HTTP with `store: false` and
    `stream: true`; no hosted tool search, file search, code interpreter,
    native computer use, or hosted MCP; no audio or video input. Our own tool
    search and MCP client are unaffected because they run client-side.
    OpenAI documents the credentials as local files; we store them in the OS
    credential store instead. Borrowing the Codex CLI's client ID or token file
    is not part of the documented flow and is out of scope. For teleport,
    OpenAI documents a self-hosted-VM path for transferring the credential;
    use it instead of copying tokens. Whether Zero counts as "open-source or
    locally hosted" depends on its distribution and licence, which are still
    open (see Open questions).
  - **GitHub Copilot sign-in: disabled until GitHub confirms in writing.**
    GitHub's 2026-01-16 changelog announces official Copilot authentication
    for Pro, Pro+, Business, and Enterprise subscribers through a formal
    partnership with OpenCode. That covers OpenCode, not Zero, and a GitHub
    community thread shows the question for other agents and for Copilot
    Student is unanswered.
- OAuth uses loopback redirects with PKCE and `state`, or the device-code flow.

#### 6.10.5 Monitors (Claude Code concept)

A monitor is a background command whose stdout lines become session events.
It is for "tell me the moment this happens", not "tell me when the command
finishes".

- `monitor` tool: start a command, stream each stdout line as an event,
  coalesce bursts, and send stderr to logs only.
- Sources: log tail, CI or PR polling, directory watch, WebSocket feed, any
  long-running script.
- Lifecycle: manual, at session start from a plugin, or on first use of a named
  skill. Cancel explicitly or stop with the session.
- Declarative plugin monitors in a JSON file with `name`, `command`,
  `description`, and `when` (`always` or `on-skill-invoke:<skill>`).
- Safety: shell approval, allowlist, sandbox, denied private/link-local/
  cloud-metadata addresses, output caps, rate limits, line buffering.
- Distinguish the four mechanisms:
  - background task: run a command and notify once when it ends;
  - monitor: stream each event line into the conversation;
  - MCP Tasks: a server-owned long operation with polling;
  - MCP Events: upstream events delivered by poll, push, or webhook.
- Monitors are project-scoped definitions and session-scoped processes. They
  are restarted after teleport or auto-resume only with confirmation.
- Events cost tokens only when they wake the model; coalescing and thresholds
  keep noisy logs from flooding the context.
- Notifications go to the desktop app, TUI, and Android; each can be muted per
  monitor.

#### 6.10.6 Modes

Five modes. A mode is three things at once: a policy (what may run), a prompt
profile (how the model plans, acts, and reports), and a harness profile (tool
exposure, checkpoints, budgets, UI). Switching mode changes all three, and the
change applies immediately, including mid-turn and mid-generation.

**1. Plan**

- Allowed: reads, search, read-only shell, MCP tools, and writes to the plan
  store. No project writes, no mutating shell, no deletes.
- Prompt profile: decompose the objective, form explicit tasks with acceptance
  criteria, identify risks and unknowns, sequence the work, and propose the
  verification. Ask only questions that block the plan.
- Harness profile: plans are first-class artifacts. Approval promotes the plan
  into semi-auto or auto, and the task list seeds the run.

**2. Manual**

- Allowed: nothing runs without an explicit yes or no, except reads that need
  no approval.
- Prompt profile: small, explainable steps. State the exact action and its
  effect before asking. No bundled approvals and no guessed intent.
- Harness profile: one decision per action with a durable record. A denied
  action is not retried without a change.

**3. Semi-auto**

- Automatic: file writes and MCP calls. Manual by default: bash. Deletes,
  network, subagents, and package installs are configurable per action class.
- Every class can be set to `auto`, `ask`, or `deny`, per project and per user.
- Prompt profile: batch related edits, state one short rationale per batch, and
  stop at the configured checkpoints.
- Harness profile: batched edits plus per-class gating, a checkpoint after each
  batch, and easy rollback.

**4. Auto**

- Automatic for ordinary work, with two independent regulators:
  - **Code-based regulator (deterministic).** Hard rules that never depend on a
    model: protected paths, deletes, secrets and credential access, network
    allowlists, resource limits, cost ceilings, recursion depth, and tool
    schema changes.
  - **AI-based regulator.** A separate classifier reviews intent and scope
    against the user's request and the project policy. It may allow, ask, or
    block, and it must give a reason.
- Both must allow. Either can escalate to ask or deny. If the classifier is
  unavailable, the affected class degrades to manual, never to allow.
- Prompt profile: autonomous execution with evidence, verification, and
  recovery. Ask only when blocked; report blockers instead of stalling.
- Harness profile: budgets, checkpoints, and a decision log that records the
  regulator verdict for every action.

**5. Headless**

- No human is available. Every user-dependent item — questions, approvals,
  credentials, ambiguous product decisions, irreversible actions — goes into a
  durable **user queue**. Everything independent keeps going.
- Prompt profile: maximize self-sufficiency. Record assumptions. Never invent
  an answer for a queued item. Prefer reversible choices. Keep working until
  the goal is met, the work is done, or a hard limit is reached.
- Harness profile: the user queue is persisted and reviewable. Blockers do not
  stall unrelated work. Goals, budgets, and stop conditions are explicit. The
  final report lists completed work, evidence, open queue items, assumptions,
  and next actions.
- Destructive or irreversible actions never run headless without a pre-existing
  explicit allow rule.

**Common rules**

- Evaluation order is deny, ask, allow; the first match wins. Hard deny applies
  in every mode, and auto cannot override it.
- Enforcement is central at every tool dispatch, including mid-turn and
  mid-generation. A tool already running cannot be un-run; its result is
  reported and the next dispatch uses the new mode.
- Mode switching is a keybinding (`Shift+Tab` cycles) and a status indicator,
  with no slash command and no button, because it needs no explicit
  invocation beyond the key.
- Mode changes are versioned, and each dispatch records the version it used. A
  change while a permission prompt is open re-evaluates that prompt.
- Mode state persists per session, with a project default, and survives
  compaction, teleport, and auto-resume.
- The status bar always shows the active mode. The cycle shortcut is
  configurable, and the active mode is set by the cycle keybinding (Shift+Tab by
  default) or by choosing a mode in the status menu. There is no `/mode`
  command.
- Transitions: plan to semi-auto or auto on approval; any mode to manual is
  immediate; auto to manual is immediate; a headless run must end before an
  interactive mode can take over.

The prompt and harness profiles are part of the mode, not an afterthought.
Plan mode changes how tasks are formed. Manual changes the step size and the
questioning. Semi-auto changes batching and checkpoints. Auto changes
verification and recovery. Headless changes assumptions, the user queue, and
how work continues without a person.

**Action classes.** Policy is a matrix of mode by class. The canonical classes
are: `read`, `write`, `shell_readonly`, `shell_mutating`, `delete` (trash),
`network_read`, `network_write`, `mcp_read`, `mcp_write`, `subagent`,
`install`, `computer`, `credential`, `mesh`, and `mode_change`. The matrix is
defined in one table, with the defaults shown in the mode descriptions, and is
the only place policy lives.

**Safety rules for modes**

- **The agent cannot raise its own authority.** Only the user (or an approved
  plan) changes mode. `mode_change`, policy and config files, the audit log, and
  journals are protected paths that agents cannot write. Escalating from
  Android needs biometric confirmation.
- **Subagents** inherit the parent's mode and never exceed it. A mid-run mode
  change propagates to every child at its next dispatch.
- **Unattended triggers.** Schedules, heartbeats, monitors, and MCP events that
  wake a session run in headless or in a restricted profile, never in a more
  permissive mode than the session's own.
- **Kernel gating.** Inside `ipython`, every effect (file, shell, network,
  credential, mesh) is a host request evaluated against the live mode, so a
  long-running cell cannot outlive a mode change. In plan mode the kernel is
  read-only: write, mutating shell, and network-write host requests are denied.
- **Plan mode and MCP/network.** MCP and network tools are allowed in plan mode
  only when the tool is known read-only (user-marked, or marked and pinned by
  hash). Self-declared `readOnlyHint` alone is not trusted; unknown tools ask.
  A shell command is "read-only" only if the parser can prove it.
- **Exact-bytes approval.** Regulators and approvals judge the exact command or
  diff that will run, after expansion where possible. An approval carries an
  action hash and an expiry; a changed action needs a new approval.
- **Auto regulator inputs.** The AI regulator sees the user's request, the
  policy, and the proposed action, never raw tool, web, or MCP output. A cheap
  deterministic fast path handles clearly safe actions without a model call; the
  regulator's model, cost, and latency are budgeted, and it is tested against a
  red-team set for false allows.
- **Headless entry and exit.** Headless starts by an explicit flag or an
  approved plan, never by the agent. It ends when the goal is met, work is
  done, only queued items remain, or a hard limit (default token, time, and
  step limits) is reached, and then produces the final report. A user may
  attach read-only or steer-only at any time without ending the run.
- **Multiple clients.** The first valid decision on an approval wins; the others
  see it resolved. Stale approvals expire.

#### 6.10.7 Task manager

One source of truth for all work in a project: goals, plan tasks, subagent
jobs, background commands, monitors, schedules, and MCP tasks.

- Stable task IDs and explicit states: `queued`, `ready`, `running`,
  `blocked`, `waiting_input`, `done`, `failed`, `cancelled`.
- Dependencies form a DAG. A task becomes `ready` only when every dependency is
  done.
- **Claims and leases.** A worker claims a task with a lease carrying owner,
  generation, and TTL. Only the leaseholder may mutate it. A fencing token
  rejects writes from a stale owner.
- **Atomic transitions.** Every state change is a compare-and-swap on the task
  version and is appended to an event journal. Concurrent updates cannot lose
  each other.
- **Parallelism.** The scheduler never hands the same task to two workers.
  Claims are idempotent, retries are bounded, and cancellation propagates to
  children.
- Backpressure and per-project concurrency limits; priorities and fairness.
- Crash recovery replays the journal, expires stale leases, and marks
  interrupted work as resumable rather than failed.
- Blocked-on-user items feed the headless user queue. Blocked-on-dependency
  items wait without consuming a worker.
- Cross-device: task state replicates over the mesh with a single writer per
  task.
- Audit: who changed what, when, and with what evidence.
- The Halcyon `tkb` adapter is a view over this manager, not a second store.
  It maps task manager entries to `tkb` tasks; the todo manager (6.10.11) syncs
  with `tkb` through the same mapping, so there is one source of truth with
  three views (tasks, todos, `tkb`).
- Plan-mode artifacts seed tasks on approval; the agent's own progress list is a
  task-manager view, while the user's todo list is separate (6.10.11).

#### 6.10.8 File manager

Every read, write, rename, and delete goes through one access layer. Tools and
agents never touch the filesystem directly.

- **Versioned handles.** A handle carries content hash, size, and mtime.
  Writes are optimistic: a changed version returns `stale` instead of
  overwriting.
- **Locks and leases.** Per-file and per-subtree locks with TTL and fencing.
  Locks are acquired in a deterministic order to avoid deadlock. Cross-process
  coordination runs through the daemon, not best-effort file locks.
- **Atomic writes.** Temp file, fsync, rename. Preserve mode, encoding, BOM,
  line endings, and symlink targets.
- **Read-your-writes** for the owning session; watcher events for everyone
  else.
- **Parallel edits.** If two writers touch the same file, the manager either
  serializes them, performs a three-way merge, or fails with a precise
  conflict. It never silently overwrites and never leaves a torn file.
- **Batch transactions.** A multi-file batch is all-or-nothing by default,
  with a journal, dry-run, and rollback.
- **Cross-device.** A single-writer lease over the mesh; teleport fences the
  old owner before the new one writes. No split brain.
- **Crash recovery.** Stale locks expire, journals replay, and deletes go to
  the OS trash.
- The file editing tool in 6.3.1 is a client of this manager, so both share
  the same versioning and locking rules.
- Performance: lazy per-file line index, range edits, and O(edits) small
  changes.
- **Honest scope.** The manager sees only access that goes through it. Bash,
  builds, formatters, test runners, installers, IDEs, and git write directly.
  For those, a file watcher records external changes and raises `stale`
  conflicts on the next managed write, instead of pretending to prevent them.
- **Per-agent isolated workspaces.** For parallel subagents, each gets a
  copy-on-write overlay of the files it touches. Results merge back with a
  three-way merge against the stored base version (no git needed); conflicts
  surface precisely. This is the primary parallelism strategy; locks cover
  short critical sections only.
- **File identity.** Locks and versions are keyed by file ID (inode or Windows
  FileId), not by path, with canonicalisation for case-insensitive filesystems,
  Unicode normalisation, symlinks, junctions, hardlinks, Windows long paths,
  reserved names, and UNC paths.
- **Merge inputs.** Three-way merge needs a base: the manager stores base
  versions for open handles. Binary files are never merged; they conflict.
- **Windows and synced folders.** Rename-over fails while another process holds
  the file; retry with backoff and report. Cloud-sync folders (OneDrive,
  Dropbox) are detected and warned about.
- **Clocks.** Leases and fencing use monotonic counters and generations, never
  wall-clock comparison across devices.

#### 6.10.9 Deadlock avoidance (Banker's algorithm)

Requirement: deadlock-free coordination. Banker's algorithm needs declared
maximum claims and a global view, so we apply it where it is sound and use
other proven techniques where it is not.

**Banker's algorithm: bounded, countable pools**

- Resource types: kernel slots, provider concurrency slots, mesh transfer
  slots, subagent slots, and browser or desktop sessions.
- Each worker declares its maximum claim per pool before it starts. The manager
  tracks available, allocated, maximum, and remaining need.
- A request is provisionally allocated, then a safety check looks for a safe
  completion sequence. If one exists the request is granted; otherwise the
  worker waits and its partial allocation is rolled back.
- Allocation is atomic across a batch. Priority with aging prevents starvation.
  Exceeding a declared maximum aborts that worker's request with a clear error.
- The safety check is small and bounded and runs in the daemon, never in the
  render or stdin path.

**File and task resources: avoidance without declared claims**

- Files are many single-instance resources whose use an LLM cannot declare in
  advance. They use ordered acquisition (canonical file-ID order), all-or-
  nothing batch acquisition, **wound-wait** priority rules (a younger holder is
  preempted for an older requester at a safe point), lock timeouts, and
  optimistic versioning. Isolated workspaces (6.10.8) remove most contention.
- When a worker can declare a bounded set up front (a batch edit), Banker's
  applies to it too. Otherwise the manager reports the degraded mode.
- External holders (a human, an IDE, git) are outside the model; they appear as
  watcher conflicts, never as locks the manager pretends to own.

**Across devices**

- No node is privileged, so the safety check is not global. Each resource has
  one owner chosen deterministically (lowest healthy node ID that holds the
  resource lease); the owner runs the check for that resource. Ownership moves
  by fenced lease handoff with generation counters. A partitioned minority
  cannot acquire new leases.
- Leases keep fencing tokens, so a stale holder cannot write after preemption.

#### 6.10.10 Agent and API scheduling

Scheduling exists to avoid rate limits, protect interactive latency, and spend
fewer tokens for the same result.

- **Agent registry.** Every agent and subagent has a class (interactive,
  background, batch), priority, deadline, token budget, dependencies, and
  current state.
- **Scheduler.** Multi-level feedback queue with priority and aging. Short
  tasks are served first within a class, equal classes round-robin, and each
  project gets a weighted fair share. Preemption happens only at a safe
  boundary.
- **Provider admission control.** Per-provider and per-model concurrency
  limits, token buckets per credential, and a queue with deadlines. Rate-limit
  headers and `Retry-After` drive the bucket.
- **Backoff.** Exponential backoff with jitter, a circuit breaker per provider,
  and a cap on retries. A provider failure never stalls unrelated providers.
- **Cost-aware routing.** Pick the cheapest model that can do the task class,
  downgrade low-risk work, cache aggressively, avoid cold-cache rewrites, and
  bound subagent fan-out.
- **Priority and fairness.** Interactive work preempts background work at safe
  boundaries. Aging prevents starvation. A large batch cannot consume the whole
  budget while an interactive turn waits.
- **Backpressure.** Queue-depth limits, coalescing of low-value work, and an
  explicit "deferred" state instead of an unbounded queue.
- **Budget guards.** Refuse or defer work whose projected cost would exceed a
  session, project, or daily budget, with a clear explanation.
- **Observability.** Throughput, 429 rate, queue latency, preemptions, and cost
  per completed task feed `/cost-audit`.
- **Durability.** Queues persist; a restart resumes with leases and does not
  duplicate in-flight calls.
- **Cost model honesty.** An LLM request is not preemptible mid-call, so
  scheduling decisions happen between requests. Priority and aging operate on
  the queue of pending calls. Cost is predicted before dispatch by reserving
  `max_tokens` and an estimate of reasoning tokens, and reconciled afterward.
  Price tables are data with a source and an update path.
- **Shared limits.** One API key used from several devices shares one provider
  limit, so the token bucket is distributed: each device receives a share from
  the key's owner node and borrows or returns capacity over the mesh, falling
  back to a conservative local share when offline.
- **No evasion.** Limits are respected, not circumvented. Using several accounts
  to bypass a provider's per-account limits is out of scope.
- **Usage windows.** Providers with usage windows (for example subscription
  5-hour and weekly caps) are modeled: remaining capacity, reset time, and a
  planned sleep until reset (see 7.6).

#### 6.10.11 Todo manager

A lightweight, user-facing list that is deliberately separate from the
executable task manager.

- Scopes: per project and per session, with a merged view.
- Item fields: id, title, notes, state (`open`, `doing`, `blocked`, `done`,
  `dropped`), priority, due date, tags, linked task IDs, and evidence.
- Fast capture from TUI, desktop, and Android; keyboard-first; inline edit;
  bulk select; filters; search; daily review; stale-item detection.
- Agent tool `todo` with `add`, `list`, `update`, `complete`, `block`, and
  `drop`. Every change is versioned, journaled, and audited.
- Todos are intentions; tasks are executable units. Linking is explicit.
  Completing one never silently completes the other.
- Persists per project, survives compaction, teleport, and auto-resume.
- Due reminders and notifications; each item can be muted.
- **Halcyon sync (flag-gated).** When `halcyon.todo_sync` is on and Halcyon
  mode is active, each todo maps to a `tkb` task with stored cross-IDs. Create,
  update, close, and reopen sync both ways through an offline queue. The sync
  is idempotent and version-checked; a conflict becomes a visible conflict item
  instead of a silent overwrite. `tkb` stays authoritative for Halcyon work.
- With Halcyon mode off, the todo store is standalone and needs no flag.
- **Who may change what.** The user owns todos. The agent may add, update, and
  block items, but completing or dropping a user-created item needs the user's
  confirmation in every mode except auto with a matching rule.

### 6.11 Multi-model orchestration (Devin concept)

Devin coordinates several models for one task: a strong model plans, cheaper
models execute, a vision model inspects, and a reviewer checks. We model that
explicitly instead of pinning one model to a session.

**Model pool**

- Every model is registered with provider, family, version, context window,
  output limit, cost (input, output, cache), rate limits, availability, and
  capability grades for coding, reasoning, instruction following, tool use,
  vision, long context, and latency.
- Grades come from the classification dataset in Part 2.6, provider metadata,
  and measured outcomes. Every turn records the model, version, and settings.
- Local-only and privacy-restricted models are first-class pool entries.

**Routing**

- Classify each unit of work (plan, edit, review, test, research, summarize,
  visual inspection) and choose the cheapest model that clears the capability
  floor for that class.
- A security-sensitive or destructive task needs a minimum capability and is
  never silently downgraded.
- Escalation: on failure, timeout, refusal, or low confidence, retry on the
  next tier with the failure evidence attached. De-escalate when a task proves
  simple.
- Draft-then-review: a cheap model drafts, a stronger model reviews or fixes.
- Ensemble only when the decision is expensive to get wrong and the budget
  allows it; otherwise one strong pass is cheaper.
- Fallback chains cover provider outages. No single provider is a hard
  dependency.

**Subagents**

- Named roles with their own default model: planner, coder, reviewer, tester,
  researcher, and vision.
- A subagent may request an upgrade; the scheduler approves it within budget.
- Fan-out is bounded by budget, rate headroom, and task dependencies.
- Every result carries the model that produced it, so review and cost stay
  auditable.

**Cost and performance**

- Per-task, per-project, and per-day budgets with a predicted cost before
  dispatch.
- Track success rate, retries, latency, and cost per completed task, per model
  and per task class. Route on measured results, not reputation.
- Prompt caching per provider with stable prefixes; avoid cold-cache rewrites.
- Rate-limit awareness and admission control come from the scheduler in
  6.10.10.
- `/cost-audit` recommends routing changes from this data.

**Modes**

- Plan prefers reasoning-strong models.
- Manual asks before switching to a more expensive model.
- Semi-auto balances quality and cost inside the configured budget.
- Auto switches within budget and records every switch.
- Headless enforces budgets hard and queues decisions that would exceed them.

**Safety and reproducibility**

- Every turn records the model, version, parameters, and the router's reason.
- Replays and audits reconstruct which model did what.
- Model deprecation triggers an explicit re-route with a warning, not a silent
  change.
- User pinning, allowlists, denylists, and privacy constraints always win over
  the router.

**Cross-provider mechanics**

- Switching models mid-task loses the provider's prompt cache, so the router
  includes that cost in its estimate. Subagents start from fresh context, which
  is the cheap path.
- A transcript translation layer converts between provider formats on an
  escalation: tool-call IDs, content block shapes, and thinking-block signatures
  that are not portable (they are dropped or summarised, and the change is
  recorded).
- Capability metadata includes vision, tool use, context length, and latency.
  The Part 2.6 dataset has no vision axis, so vision grades come from provider
  metadata and measured results.
- Routing learns from outcomes with minimum sample sizes and a small
  exploration rate, and the data is refreshed on a schedule with a recorded
  source. A static 73-model table is a seed, not the final answer.
- Direct providers include Anthropic, DeepSeek, Moonshot/Kimi, OpenAI, Google,
  and local runtimes (Ollama, LM Studio), plus the existing catalogue.

### 6.12 Multimodal input and computer use (Devin concept)

Separate from multi-model orchestration: the agent can take visual and audio
input, drive a desktop, and verify work by looking at it.

**Inputs**

- Text, images, PDFs and documents, audio, video, code snippets, and attached
  files.
- Paste, drag-and-drop, Android share sheet, `@` references, and clipboard
  images.
- Typed content blocks in the transcript with per-modality token accounting.
- Preprocessing: downscale, crop, tile, OCR, frame sampling, and audio
  transcription. Originals are kept so a later turn can re-read at full
  resolution.
- Redaction of secrets and PII before anything leaves the device, with an
  explicit override and warning.

**Computer use**

- A full desktop on Linux, Windows, or macOS, or a sandboxed VM, plus browser
  and terminal UIs.
- Screenshot, identify elements, act (click, type, scroll, drag, keys, wait,
  zoom), screenshot again.
- Deterministic waits and retries for loading states, dialogs, and pop-ups.
- Session recording with annotations at key moments.
- Interactive takeover: the user can watch and control the same desktop. The
  agent pauses before takeover so the two never fight over the same input.
- File manager locks prevent the human and the agent editing the same file
  concurrently.

**Visual verification**

- Build, launch, exercise the flow, assert, and fix.
- Reports with labeled screenshots; recordings with chapters, compressed idle
  time, and pass/fail assertions.
- Vision-heavy testing routes to vision-strong models, while editing routes to
  coding-strong models, through multi-model routing in 6.11.
- Prefer real user paths over script-triggered state changes, and flag
  shortcuts instead of presenting them as end-to-end proof.

**Outputs**

- Screenshots, recordings, annotated reports, diagrams, and generated images
  when enabled.
- Artifacts are stored per project, referenced from the transcript, and
  available on desktop and Android.

**Safety**

- Images, screenshots, and video frames are untrusted data; never follow
  instructions embedded in them.
- Sandbox the desktop, allowlist the network, and deny host filesystem access
  by default.
- Never type credentials unless the user approved it, and then only from the
  secret store.
- CAPTCHA and MFA pause for the user. They are never bypassed.
- Redact before upload and prefer local processing.

**Modes**

- Plan: visual exploration allowed, no mutations.
- Manual: every computer action asks.
- Semi-auto: browsing and screenshots automatic; clicks and typing
  configurable; downloads, purchases, and account changes ask.
- Auto: computer actions pass the code and AI regulators; irreversible
  purchases and account changes always ask.
- Headless: queue CAPTCHA, MFA, and credential steps; continue everything else.

**Remote and mobile**

- Android can send photos, screenshots, and video, and watch the agent's screen
  live.
- Desktop can hand off a live view. Everything stays on the mesh; nothing is
  publicly exposed.

**Two execution targets**

- **Sandboxed target (preferred).** A VM, container, or virtual display where
  host filesystem access is denied by default. On Windows this requires Windows
  Sandbox or Hyper-V (Pro editions) or a Linux VM; availability is detected.
- **Live host desktop.** Driving the user's real desktop is a higher-risk class:
  `computer` always asks in manual and semi-auto, is never used in headless
  without an explicit allow rule, and the "deny host filesystem" rule does not
  apply, so it must be stated to the user.

**Dependencies and limits**

- Audio transcription, OCR, and video frame understanding use the provider's
  native multimodal input when available. Otherwise they may use a **local
  model that runs on a CPU** (no GPU required), a declared, checksum-verified
  dependency (6.0). Candidates and sizes are in `architecture.md` section 13a.
  Models that need a GPU are not used.
- **Ask first.** A local model is never downloaded, installed, or run without
  the user's explicit consent. The prompt names the model, its licence, its disk
  and memory cost, and what it will be used for, and the answer is remembered
  per project or per user. In headless mode the request joins the user queue and
  the modality reports as unavailable until answered.
- Without a provider capability or a consented local model, the modality
  reports as unavailable.
- A non-vision model that receives an image is routed to a vision model or an OCR
  path, never silently ignored.
- Redaction of images and screenshots is best effort (OCR plus pattern match)
  and is described as such. It is not a guarantee.

### 6.13 MCP support

Act as an MCP client for user servers and as an MCP server for editors and
external clients. Target the `2026-07-28` revision and negotiate older ones.

**Core protocol**

- Stateless core: no protocol sessions, no `Mcp-Session-Id`, and no required
  handshake. `server/discover` is available for capability discovery.
- Per-request capabilities in `_meta`; `MCP-Protocol-Version`, `Mcp-Method`,
  and `Mcp-Name` headers for routing, metering, and WAF rules.
- Every result carries `resultType` (`complete` or `input_required`); results
  from older servers are treated as `complete`.
- Cacheable list results via `ttlMs` and `cacheScope`, with deterministic
  ordering so tool catalogues stay stable across reconnects.
- JSON Schema 2020-12 for input and output, `$ref` resolution, and resource
  bounds on composition keywords.
- Transports: stdio and Streamable HTTP. Legacy HTTP+SSE is a compatibility
  shim with a twelve-month offramp, never the default.
- Respect the allocated error-code ranges; `-32020` to `-32099` are reserved
  by the specification.

**Multi Round-Trip Requests**

- A server returns `input_required` with `inputRequests`; the client retries
  the original call with `inputResponses`.
- Elicitation supports form mode for structured data and URL mode for anything
  sensitive. Credentials, API keys, and payment details must use URL mode and
  never form mode.
- No dependence on held-open streams for server-initiated requests.

**Extensions**

- **Tasks** (`io.modelcontextprotocol/tasks`): a `tools/call` may return a
  durable task. Poll with `tasks/get`, supply input with `tasks/update`,
  cancel with `tasks/cancel`. Handle `working`, `input_required`,
  `completed`, `cancelled`, and `failed`; respect TTL and poll interval; treat
  task IDs as bearer secrets; there is no task listing.
- **Events** (`io.modelcontextprotocol/events`): negotiate the capability,
  read `events/list` schemas, and support all three delivery modes: poll
  (`events/poll`), push (`events/stream`), and webhook (`events/subscribe`).
  Track cursors, assume no resumption, verify signed webhook payloads, and
  renew TTLs.
- **MCP Apps**: `ui://` resources, tool-to-UI references, sandboxed iframes,
  and bidirectional JSON-RPC under a strict CSP.
- **Skills over MCP**, **Enterprise Managed Authorization**, and future
  extensions: negotiate, use when supported, ignore when not, and never fail
  the server because of an unknown extension.

**Authorization**

- OAuth 2.1 with PKCE, resource indicators, and RFC 9207 issuer validation.
- Client metadata documents (CIMD) are the primary registration path. Dynamic
  Client Registration is supported for compatibility only.
- Tokens live in the OS keychain, are scoped per server, are refreshed and
  revoked explicitly, and never appear in logs or transcripts.

**Security**

- Server output is untrusted data, never instructions.
- Pin tool schema hashes and warn on a changed definition (rug-pull defence).
- Per-server and per-tool allow/deny, with destructive tools defaulting to ask.
- Sandbox Apps iframes and block top-level navigation.
- Validate schemas, cap output size, enforce timeouts, and propagate
  cancellation.
- SSRF protection for URL elicitation and webhooks; block private ranges unless
  loopback is explicitly allowed.
- Replay protection and signature checks on webhooks.
- Audit every server connect, tool call, elicitation, task, and event delivery.

**Event integration**

- MCP events map onto the internal event bus and can wake a session, enqueue a
  prompt, fire a schedule, or notify a device.
- The webhook receiver binds to loopback or the mesh only.
- Events are deduplicated by ID and persisted within the cursor window.

**Server mode**

- Optionally expose our native tools, sessions, and events over MCP so editors
  and other clients can drive Zero.
- Capability-gated and disabled by default.

**Compatibility**

- Server definitions per user and per project, with env, OAuth, and enable
  flags.
- Conformance tests against `2025-11-25` and `2026-07-28` fixtures.
- Roots, sampling, and logging keep working for twelve months but new code does
  not adopt them.

**Missing surfaces and edge cases**

- **Resources, prompts, and completions** are supported: resources become `@`
  references, prompts become slash commands, and completions feed autocomplete.
- **Elicitation and MRTR** in headless mode enqueue into the user queue; on
  Android they appear as a prompt on the phone; URL mode never opens a page
  without approval.
- **stdio servers** are launched by us: scrubbed environment, per-project
  approval, resource limits, and the command guard in 6.4 applies.
- **Output cost.** Tool results are truncated with a token budget, large ones are
  stored as artifacts and referenced, and the model gets a handle.
- **Trust.** Project-defined servers do not start until the folder is trusted
  (6.18). Tool descriptions and annotations from servers are untrusted.
- **Spec fidelity.** Details above were taken from research of the
  `2026-07-28` revision; they are re-verified against the published
  specification at implementation time and corrected where they differ.

### 6.14 Doctor and recovery

- `zero doctor` is one of the few CLI commands; `/doctor` opens the same action
  as a panel. It runs on demand, on
  startup failure, after a crash, and after an update.
- **Diagnosis:** versions, config validity, project key and binding,
  supervisor and workers, kernel and virtual environment, providers and auth,
  network and mesh, ports, disk, locks, session journals, MCP handshakes, and
  logs.
- **Failure taxonomy:** stable codes with one playbook each. Examples:
  `KERNEL_BOOT`, `DAEMON_STALE`, `AUTH_EXPIRED`, `JOURNAL_CORRUPT`,
  `DISK_FULL`, `PORT_CONFLICT`, `LOCK_STALE`, `MESH_UNREACHABLE`,
  `MCP_HANDSHAKE`, `PROJECT_KEY_MISSING`.
- **Recovery:** bounded, reversible actions. Dry-run first, snapshot before
  repair, use trash instead of permanent deletion, roll back on failure, and
  never force-kill unrelated processes.
- **Automatic repair:** safe fixes apply automatically; risky ones require
  confirmation. Every action records its evidence and outcome.
- **Forensics:** incident timeline, recent events, and a redacted support
  bundle. Works offline and sends no telemetry.
- **Agent API:** `doctor.diagnose()`, `doctor.plan()`, `doctor.apply(plan)`.
  The agent must report unresolved failures, never hide them.
- **Health checks:** preflight, post-update, and periodic, with exit codes and
  `--json` for CI.
- **Independence.** The doctor is a separate, minimal-dependency executable. It
  runs with the daemon, kernel, and mesh dead, and never depends on the
  component it is diagnosing.
- **Policy.** Repairs run under their own policy, which is never more permissive
  than the current mode: plan and manual ask, auto applies safe fixes, headless
  queues risky ones.
- **Testing.** Every failure code has a playbook and a fault-injection test that
  reproduces it and proves the repair.

### 6.15 Feature flags

Flags are reserved for features that link to Halcyon tooling, where the
capability may be absent, disabled, or upgraded independently. There is no
general-purpose flag for core behaviour.

- Core features are always on and controlled by ordinary configuration, not
  flags: tools, projects, modes, task manager, todo manager, file manager,
  scheduler, doctor, web, MCP client, mesh, teleport.
- Only these are flags: `halcyon.mode` (master), `halcyon.todo_sync`,
  `halcyon.joker`, `halcyon.epb`.
- Off means the integration is not registered: no tools, no prompt text, no
  sync jobs, no cost. The core feature it augments keeps working.
- On means capability-detected: a missing CLI or repository shows a disabled
  state with an actionable message, never a crash and never a fake.
- Resolution order: pinned-key-verified mode file, then user config, then an
  explicit session override. **Project config from the repository can never set
  a Halcyon flag.** The Halcyon mode file remains the master switch.
- Adding a new flag requires a Halcyon-linked capability. If it does not touch
  Halcyon, it is configuration, not a flag.

### 6.16 Delivery slices

Moved to `plan.md` section 2, together with acceptance criteria and the test
strategy. Ordering follows `plan.md` section 1: foundations, agent core, safety
core, TUI, then the remaining subsystems.

### 6.17 Architecture and stack

Moved to `architecture.md`, which holds the language and runtime decision,
the TUI and process architecture, storage, protocol, repository layout, and
performance budgets. Delivery scope and order live in `plan.md`.

### 6.18 Trust model and threat model

- **Threats.** Accidental destructive or costly agent actions; prompt injection
  from untrusted content; a repository that ships config trying to execute on
  open; a stolen or lost device; a hostile network or relay.
- **Workspace trust.** A folder is untrusted until the user trusts it. In an
  untrusted workspace, project config, hooks, monitors, MCP servers, skills,
  `AGENTS.md`/`CLAUDE.md` instructions, and `.halcyon-mode` are inert (loaded as
  text for display only), and the agent is limited to plan-equivalent
  behaviour. Trust is per project key, revocable, and never inferred.
- **Untrusted content.** Web pages, search results, MCP output, images, and
  repository text are data. They are labeled, never instructions, and never
  reach the auto regulator.
- **Audit log.** Append-only with a hash chain, stored outside agent-writable
  paths, covering mode changes, approvals, deletions, MCP calls, sign-ins,
  mesh joins, and teleports.
- **Optional hardening.** OS sandboxing of the kernel and shell (Landlock/
  seccomp, job objects) can be enabled; it strengthens but does not replace the
  guards.

### 6.19 Installers (target)

Carry forward from Part 3: forkable release repo, `stable` and `beta`
channels, install lock, terminal restoration, retries, no-TTY fallback,
per-user PATH changes, non-interactive CI mode, and actionable permission and
network errors.

Changes for the rewrite:

- **Authenticity.** Releases publish a manifest signed with an Ed25519 release
  key whose public key is embedded in the installer. `SHA256SUMS` alone from the
  same origin proves integrity, not authenticity.
- **No Node prerequisite.** The core is a single native binary
  (`architecture.md`), so the old Node and npm preflight is dropped.
- **Kernel bootstrap.** Optional `uv`, Python, and `ipykernel` setup, with
  checksum verification and an offline mode.
- **Lifecycle.** `install`, `update` (signed, atomic, rollback), `uninstall`
  (moves user data to trash after confirmation), and an offline upgrade path.
- **Service integration.** systemd unit, Windows service, launchd agent.
- Installer layout checks across terminal sizes remain a CI test.

### 6.20 Test and acceptance strategy

Moved to `plan.md` section 3. It keeps the same content: per-slice acceptance
criteria and a verification command, deterministic simulation and model checking
for the lock, task, and file managers, guard corpora and parser fuzzing, a mode
matrix test, doctor fault injection, network-impairment tests for the mesh and
teleport, the held-out evaluation suite, performance budgets, and the security
test suites.

### 6.21 Traceability matrix

Every archived and parity feature has a status: **keep**, **changed**,
**dropped (with reason)**, or **later**. Unlisted items default to *needs a
decision*, never to "assumed kept".

| Archived feature (Part 1) | Status in the rewrite |
|---|---|
| RLM and single `ipython` surface | changed: `ipython` plus a few native tools and `tool_search` |
| Continual Harness, `/refine` | changed: 6.7 loop and immutable core |
| Programmatic subagents, child registry | keep, with the model pool (6.11) |
| Daemon, supervisor, leases, idempotent commands, cursors, backpressure | keep (Part 2.4, slice 1) |
| Heartbeats, schedules, `/goal`, `/autonomous` | keep; run under headless or restricted mode (6.10.6) |
| `agent_message` | keep |
| Compaction, branch summaries, session tree | keep |
| Skills (SKILL.md and Python) | keep (slice 10) |
| Extensions, packages, themes, prompt templates | keep (slice 10) |
| Print, JSON, RPC, ACP, SDK | keep (slice 10) |
| Subscription logins: Claude Pro/Max | dropped: prohibited by Anthropic's terms; API key only (6.10.4) |
| Subscription logins: ChatGPT/Codex | changed: OpenAI's documented "Sign in with ChatGPT" flow only (6.10.4) |
| Subscription logins: GitHub Copilot | later: disabled until GitHub confirms for Zero (6.10.4) |
| Provider catalogue, router, classification | changed: model pool (6.11) |
| Plan/auto/manual modes | changed: five modes (6.10.6) |
| Git-backed rollback, checkpoints | changed: undo journal and snapshots, git optional |
| Loop auditor, audit log | keep, hash-chained (6.18) |
| Credential store | changed: per-project secrets manager with IDs, `.env` generation, no plaintext (6.22) |
| Vim mode, voice input, agent teams, worktree orchestration | later: gated items from Part 2.1 |
| Installers, launchers, CI | changed (6.19) |

OpenCode parity items in Part 8 are scoped v1 versus later in `plan.md`. The
matrix is completed row by row during slice 0 and is part of its acceptance.

### 6.22 Project secrets manager

The agent never holds a secret value. It holds a **tag** and writes a
**placeholder**. A separate UI collects the real value directly from the user,
stores it encrypted, and the manager substitutes the value into a
**trigger** the agent declared, at the moment the trigger fires.

**Flow**

1. The agent decides it needs a secret and writes a placeholder plus a trigger
   in its tool call or code:
   - placeholder: `{{secret:openai_api_key}}` or `{{secret:@openai_api_key}}`;
   - trigger: the exact operation that may consume it, for example
     `http POST https://api.openai.com/v1/chat/completions`, `exec:gh auth login`,
     or `env:OPENAI_API_KEY for pid`.
2. The manager sees a tag with no stored value. It opens the **secrets UI**
   (below), prefilled with the tag, why it was requested (a short agent-supplied
   description that the UI shows verbatim as untrusted text), the bound trigger,
   and the scope.
3. The user sees the request, can edit the tag and its binding, and enters the
   value in a masked field that the terminal and the agent never see. The user
   can also generate a random value, paste from the clipboard, or decline.
4. The manager encrypts the value and stores it under the tag in the project
   vault.
5. The agent retries, or the manager re-fires the trigger automatically, and the
   placeholder is replaced with the real value **inside the outbound request
   only**. The agent, the transcript, the logs, and the kernel see the tag and
   the result, never the value.

**Placeholders and substitution**

- Syntax: `{{secret:TAG}}` in text, and `Secret("TAG")` in kernel code, which
  returns an opaque handle that can be stringified only by the transport layer.
- Substitution happens in the transport: HTTP headers and query strings, a child
  process environment, stdin of a bound command, or an SDK credential slot.
  Never in chat output, tool receipts, or file writes.
- Substitution only happens for the operation the tag is **bound** to. A tag
  bound to `api.openai.com` is not substituted into a request to another host.
  A mismatch fails closed with `SECRET_BINDING_MISMATCH`.
- The value is applied after the policy check and after the AI regulator sees the
  action, so neither sees the secret. The action is checked against the tag and
  the binding, not against the value.
- Redaction: the resolved value is added to the run's redaction set for the rest
  of the session, so an accidental echo elsewhere is scrubbed.
- One tag may have multiple bindings (for example the same key for the API and
  for a CLI), each explicit.
- Unknown tag, declined request, or expired binding: the trigger fails with
  `SECRET_UNAVAILABLE` and an exact message. Nothing is retried silently.

**The secrets UI**

A separate, host-owned surface, shown in **every** Zero app: the TUI, the
desktop app, the web app, and the Android app. It is never a chat message and
never something the agent can draw.

- Rendered by trusted host code, not by the agent's output stream. In the TUI it
  is a host-owned modal (the agent cannot print into it); on desktop and web it
  is in host chrome, never inside agent-rendered content or an MCP App iframe;
  on Android it is a native dialog with `FLAG_SECURE` so it is absent from
  screenshots and the recents thumbnail.
- All four surfaces show the same request, drawn from one host-side model:
  the tag, the requester, the exact binding and trigger, the scope, the reason
  text (shown as untrusted), and the expiry.
- Actions: enter, generate, paste, replace, rotate, revoke, and "remember for
  this project only". Masked entry, no echo, no clipboard-history capture where
  the OS allows it.
- Whichever surface answers first resolves the request; the others close. The
  value travels only from that surface to the host, never through the transcript
  or the session event stream, so teleport, replay, and logs never contain it.
- If no surface is reachable (no display, no paired device), the request enters
  the user queue and the dependent work waits or fails honestly.
- A screen share shows the dialog title and the tag, not the field.

**Storage**

- Encrypted at rest: a per-project data encryption key wrapped by the OS
  credential store (DPAPI, Keychain, libsecret), or by a user passphrase through
  Argon2id when there is no keychain. Values use AES-256-GCM with a per-secret
  nonce and associated data binding the tag, scope, and project ID.
- The encrypted vault is `{project}/.zero/vault/secrets.enc`, plus
  `vault/index.json` with tags, providers, bindings, creation and rotation
  times, and drift hashes. No values in the index.
- A value is never persisted in plaintext anywhere: not in `.env`, not in
  `auth.json`, not in the kernel, not in a log.

**Mesh and teleport**

- The vault travels with the project through teleport (7.4) and mesh sync as
  **ciphertext**, so a copied or teleported workspace keeps its tags and
  bindings.
- The wrapping key never travels. The target device cannot decrypt a transferred
  vault on its own, so on first use after a teleport it asks the user once to
  unlock that copy with a passphrase, or to re-enter the affected values, or to
  pull them from the source device over an approved, end-to-end encrypted
  channel. The choices and their consequences are stated in one prompt.
- A vault from another project, an unchanged wrapping key on the same device, or
  a missing index is a hard error, not a silent empty vault.

**`.env` generation**

- The **Secrets sync** action writes a **git-ignored `.env`** holding resolved values
  for tools that cannot ask the host, at mode 0600.
- A git-tracked `.env.example` lists every tag with its placeholder, so a fresh
  clone knows the shape without carrying secrets.
- A generated `.env` is excluded from teleport by default (values travel in the
  encrypted vault instead), and a pre-commit guard refuses a file whose values
  match stored secrets.

**API**

- Actions: **Secrets list**, **show** (tags only), **bind**, **unbind**,
  **rotate**, **revoke**, **export**, **sync**, **scan**. Requests and sync are
  agent-triggered, and `/secrets` opens the surface directly. There is no action
  that prints a value without the secrets UI.
- Tools: `secrets.request(tag, binding, reason)`, `secrets.status(tag)`,
  `secrets.revoke(tag)`. There is deliberately no `secrets.get`.
- Kernel: `Secret("TAG")` handles and the placeholder syntax above.
- Config and provider flows: `{{secret:TAG}}` in config values, and provider and
  MCP OAuth tokens land in the same vault under their own tags.

**Safety**

- `credential` is its own action class: plan denies it, manual and semi-auto ask,
  auto passes both regulators, headless requires a pre-existing rule or queues
  the request.
- Every request, approval, refusal, substitution, rotation, and revocation is
  audited: tag, binding, requester, purpose, and outcome, never the value.
- A tag is scoped to one project by default, has an optional expiry, and is
  revoked on suspicion.
- Mesh and teleport: the vault moves as ciphertext (see above). Another device
  unlocks it only with the user's passphrase or re-entry, or receives values
  through an explicit, approved, end-to-end encrypted transfer. There is no
  silent plaintext copy.
- `secrets scan` finds leaked values in files and in git history and offers to
  rotate them.

### 6.23 Security review (`/security-review`)

Models the behaviour of Cloudflare's published `security-audit` skill (the
`cloudflare/security-audit-skill` repository, Apache-2.0, read 2026-11-24):
multi-phase, coverage-led, independently verified, machine-readable findings.
The behaviour is reimplemented here; no code is copied.

**Operating modes.** Loading guidance is not authorisation to run a full audit.

- **Guidance mode:** answers a security question, triages a specific finding, or
  reviews a focused area. It does not create an output directory or write audit
  artifacts, and it may still delegate focused agents.
- **Full audit mode:** only when the user asks to audit or pen-test, asks for a
  full or end-to-end review, or asks for report artifacts.
- If the request could be either, ask one focused question first.
- `/security-review [scope] [--profile quick|standard|deep] [--budget N]`
  selects full mode explicitly; `/security-review --quick <path>` is a bounded
  pass.

**The checklist comes first and is explicit.** Phase 1 produces the checklist
the run will be graded against, before any hunting. It has two parts: the
trust-boundary map, and the **coverage ledger**, one unit per material
combination of entry surface, trust boundary, subsystem, and attack class.

- Attack classes: injection, access control, resource and file handling,
  cryptography and secrets, business logic, feature abuse and data leakage,
  chained vulnerabilities, a wildcard class, and an "obvious things" class.
  Domain companions are selected from reconnaissance facts, not from a language
  name: memory safety and binary, AI and LLM agents, web and auth, client-side,
  supply chain and release, cloud and deployment, protocols and messaging,
  resource exhaustion, data isolation and lifecycle, desktop, mobile, and local
  IPC.
- Every unit records canonical references (paths plus the exact class block),
  starting paths, selected and excluded companion blocks with reasons, status,
  owner, reviewed paths, local checks, and result fingerprints.
- The ledger **is** the coverage claim. "Auth was reviewed" is not coverage.

**Steps.** Run in order, all six, never stop mid-phase:

1. **Prepare the checklist.** Reconnaissance agents map the product and stack,
   principals and authority, entry surfaces and sinks, and local execution
   visibility. The parent writes the trust-boundary summary (about 1,000 words)
   and seeds the ledger, then validates it.
2. **Hunt, one wave per unit.** Each unit goes to an isolated agent assigned only
   that unit, so coverage is deterministic rather than "someone looked". A
   coverage critic reopens weak units. Large targets are split by subsystem.
3. **Validate every candidate independently.** Fresh agents try to refute each
   candidate from source and bounded local evidence. A candidate without a named
   lower-trust principal, crossed boundary, and concrete result is not a finding.
4. **Write structured output.** `findings.json` with separate `confirmed`,
   `needs_validation`, and `rejected` records, each with a stable fingerprint,
   plus `coverage-ledger.json`. Both are schema-validated.
5. **Verify the records with fresh eyes.** One new agent per final record,
   checking traces, conditions, impact, and severity. A stronger verdict needs
   another independent pass.
6. **Report, target-neutral.** `REPORT.md`, `FINDINGS-DETAIL.md`, and
   `NEEDS-VALIDATION.md` are derived from the final records, never written by
   hand, with coverage, budget spend, and every deferred or out-of-scope gap
   stated. A partial run says so.

**Rules**

- Only `confirmed` records carry severity, and severity never exceeds the
  demonstrated impact. `needs_validation` is a blocked hypothesis with an exact
  missing fact and a safe next check, never a parking place.
- The audit **never modifies target source**. Fixes are proposals with the
  smallest effective change and a regression test. Applying them is a separate,
  mode-governed action (`/security-review --fix`).
- Target code runs only in the OS sandbox (6.18) with no external network, an
  allowlisted empty environment, a read-only target, scratch-only writes, and
  explicit CPU, memory, process, file, and time limits. If the sandbox cannot be
  enforced, no target code runs and the gap is reported.
- Agents write only their own scratch directory. Only trusted parent code
  promotes declared files into the run directory, with no path traversal, no
  symlinks, no special files, and size limits.
- Live or shared systems are never probed. Dummy principals, fixtures, and
  throwaway secrets only; secrets from 6.22 are never given to target code.
- Prior runs are read. A prior `confirmed` record is carried only when the
  relevant source is unchanged, and is always re-verified; changed source,
  blocked, and deferred units become current work; `out_of_scope` never means
  covered.
- Budget is counted in agent invocations with reserves for critics and
  validators. Spend runs through the scheduler and the ledger (6.10.10, 7.5).
  If the budget cannot fund a clean pass, say so instead of thinning evidence.
- Profile: `quick` (one wave, coarsened units, one merged verifier),
  `standard` (default), `deep` (per-subsystem and lifecycle units, critic waves
  to a clean pass, separate validation and verification). A scoped run is
  explicitly partial.

**Integration with Zero**

- Each ledger unit is a task-manager task, so progress, retries, budgets, and
  cancellation are visible, and parallel agents run in isolated workspaces
  (6.10.8).
- Output goes to `{project}/.zero/audits/run-N/` and is linked from the
  transcript. A failed or incomplete run is reported as such.
- Findings feed the self-improving loop (6.7): a confirmed finding can produce
  one bounded regression test and fix, promoted only after fresh evidence.
- Reuses the deployment: Windows, macOS, and Linux sandbox backends; the same
  report schema for CI; the **Security review** action runs it from the app and
the SDK.
- A built-in checklist ships with Zero and can be extended per project (a
  `SECURITY.md` or a project skill), but the evidence bar and the six phases
  cannot be relaxed by project configuration.

---

## Part 7: Multi-device mesh, remote control, and teleportation

All of this is our code. Tailscale and NetBird are concept references only; no
client, package, or control-plane code is reused.

### 7.1 Mesh networking

Purpose: a private, encrypted path between the user's devices without opening
ports, exposing IP addresses, or running a central service.

- **Overlay.** WireGuard. Use an audited implementation (OS kernel WireGuard
  where available, `wireguard-go` otherwise). We own discovery, traversal,
  ACLs, relay, and clients; we never hand-roll tunnel cryptography.
- **Decentralized control plane.** There is no central or privileged node.
  Every node can act as the control plane. Registry, ACLs, name records, and
  network state are signed, versioned, and replicated with gossip/CRDT, so any
  node can answer and losing one node never stops the network.
- **LAN mode.** On a LAN, nodes find each other over mDNS and form the mesh
  with no control service, no account, and no configuration.
- **NAT traversal.** STUN-style discovery, UDP hole punching, and a TCP/443
  fallback. When a direct path fails, any willing node may relay, and the
  relay sees ciphertext only.
- **No exposure.** Default-deny inbound. No public listeners. Peers are
  addressed by mesh identity. A direct path necessarily reveals each endpoint
  to the peer at the other end, so the guarantee is: IP addresses are never
  shared with third parties or other mesh members who are not part of the
  connection, and a relay-only mode hides endpoints from the peer too.
- **Easy by default.** Mesh up creates the identity, starts the mesh, and shows
  a QR when the mesh is off. Mesh join accepts that QR or a short word code.
  Both are user-only and appear only when needed. Advanced configuration exists
  but is never required.
- **Identity and trust.** Ed25519 identity per device, explicit device
  approval, short-lived single-use join tokens, key rotation and revocation,
  and signed network state that prevents silent node insertion.
- **Names.** Stable device names resolved inside the mesh; no external DNS.
- **Self-hostable and offline.** No vendor service, no required relay, no
  account. LAN-only is a first-class mode.
- **Root of trust.** The owner holds a root key, ideally offline or in a
  hardware key. It signs the device set and changes to it. Any approved device
  can request a join, but only an owner-signed (or owner-delegated, threshold)
  change alters membership, so a stolen device cannot evict the others.
  Revocations are gossiped and also checked at connection time, and a partition
  can lag them; the spec reports that window.
- **Rendezvous.** Two devices on different networks need at least one node with
  a reachable address (a VPS, a home port-forward, or any device with a public
  address) to exchange candidates. Any node can take that role. With none,
  and with symmetric NAT or CGNAT on both sides, devices cannot connect, and
  the spec says so rather than hiding it. STUN uses a node with a public address
  or a user-chosen server; none is built in.
- **Overlay scope.** Zero needs app-layer connectivity, not a system VPN. Prefer
  a userspace WireGuard stack with no TUN device: no admin rights or driver on
  Windows, and no `VpnService` on Android, so a user's existing VPN keeps
  working.
- **LAN safety.** mDNS announcements are authenticated; unauthenticated peers are
  ignored and never listed.
- **Always-on cost.** Mesh and monitors respect battery and metered networks;
  sleeping devices are reported as offline, not as failures.

### 7.2 Joining and presence

The mesh exists to secure connectivity, not to manage a fleet. Keep this
surface small.

- Actions: mesh up, join, list, leave, rename, status, and doctor. They live in
  the mesh panel, which `/node` opens, and are never agent-invocable.
- Pairing by QR or short code, approved on an existing device.
- Presence only: online/offline and reachability. No scheduling, placement,
  capability marketplace, or fleet orchestration.
- Sessions stay on the device that runs them. Other devices attach to that
  device; they do not reassign work.
- Optional encrypted snapshot cache for teleport, off by default.

### 7.3 Android app (remote control)

- Native Android client (Kotlin, Compose) with an embedded mesh client using
  `VpnService` and the same WireGuard overlay.
- Pairing by QR or one-time code; biometric unlock; no public endpoint.
- Session list, live transcript, prompt send, steer, queue, cancel, approve or
  deny permission requests, and diff viewing.
- Notifications for completion, failures, and approval requests.
- Offline queue and reconnect with a cursor.
- Share target for text, images, and links.
- Battery- and network-aware: relay vs direct status, data-use estimate.
- v1 is remote control only. Running an agent or kernel on the phone is out of
  scope, and nothing in the mesh design requires the phone to be more than a
  controller.
- **Approvals are bound.** A phone approval names the action hash and expires. The
  lock-screen notification shows no code or secrets. Raising the mode needs
  biometric confirmation.
- **Notifications without a push service.** A foreground service keeps the mesh
  connection for live events; optional UnifiedPush works without Google. Normal
  Android push through Google's service would be an external dependency and is
  off by default. When the app is not connected, notifications arrive on the
  next reconnect and the spec says so.
- **Device sleep.** If the laptop is asleep or off, the phone shows it offline;
  optional wake-on-LAN works on the same LAN only.

### 7.4 Teleportation (session migration)

Move a live session from device A to device B without losing state.

1. **Select target.** Preflight capabilities, disk, model access, and policy.
2. **Quiesce.** Finish or checkpoint in-flight tool calls; stop accepting new
   input; snapshot the draft.
3. **Snapshot.** Transcript, session entries, kernel state, artifacts, goals,
   schedules, heartbeats, permissions, tool state, usage ledger, and a
   workspace manifest.
4. **Bundle the workspace.** Move the files themselves, never a clone.
   The manifest records every path with type, size, mode, symlink target, and
   content hash. Payloads are content-addressed, chunked (about 4 MiB),
   resumable, and deduplicated. Changed and untracked files are included by
   default; `node_modules`, build output, and other excludes are configurable.
   `.git` is optional metadata, never a requirement.
5. **Transfer.** Chunked, resumable, end-to-end encrypted over the mesh. The
   source keeps the content-addressed snapshot until the target verifies it.
6. **Restore.** Recreate directories, files, modes, and symlinks from the
   manifest, replay the transcript, restore the kernel, rebind schedules and
   children. If the target has a conflicting workspace, stage into a new
   directory or reconcile explicitly; never silently overwrite.
7. **Verify.** Check every file hash and the manifest hash, then mark the
   snapshot complete.
8. **Fence.** The old host loses its write lease before the new host gains one;
   a generation counter prevents split brain.
9. **Resume.** Reattach clients, continue the turn, verify.

**No repository assumption.**

- Teleport works for arbitrary directories, including non-git projects.
- Git, if present, is copied as data. We never run `git clone`, `git fetch`,
  `git checkout`, or depend on a remote being reachable.
- A target with no repository, no access to a forge, and no matching branch can
  still restore the session because the files travel in the bundle.
- Files that cannot be read or written (permissions, locks, size) are reported
  by path; the transfer is not reported as complete.
- The snapshot may live on the source, on the target after pull, or on an
  optional storage node. There is no central object store.

Honest limits:

- Pure-Python kernel state is checkpointed where possible (`cloudpickle`-style);
  unpicklable objects are reported and can be rebuilt by re-running their
  setup.
- Live processes, PTYs, and open sockets do not move. They are either
  reattached on the source or restarted on the target, and the user is told
  which.
- A failed transfer leaves the old host authoritative from its last checkpoint.
- Teleport is recorded in the usage ledger and the audit log.

**Additional rules**

- **Secrets and ignored files.** The bundle excludes secret patterns (`.env*`,
  key files, `.zero/key` is included as identity, credentials never) by default
  and lists every exclusion. Other git-ignored files are included unless the user
  excludes them. Bundles and snapshots are encrypted in transit and at rest,
  and only an approved device receives them.
- **Platform differences.** Kernel pickles and virtual environments are not
  portable across OS or Python versions; they are rebuilt from the session log.
  Absolute paths in the transcript are remapped to the target path, and the
  model is told the working directory changed. Symlinks, modes, line endings, and
  case sensitivity are reconciled and reported.
- **Required tools.** Preflight checks that the target has the tools the session
  needs (for example `tkb`, `joker`, `epb`, shells); missing ones are listed.
- **Unreachable source.** If the old host cannot be fenced, the user may force a
  takeover that bumps the generation. When the old host returns it discovers it
  is fenced, becomes read-only, and keeps its divergent edits as a separate
  snapshot for reconciliation.
- **Return trip.** Moving back reconciles workspace changes with the same
  three-way merge as the file manager.

### 7.5 Usage tracking

- Ledger per session, device, model, provider, and tool: input, output, cache
  read, cache write, cost, wall-clock time, retries, and subagent share.
- Local-first append-only event log. Each device writes only its own log;
  other devices store copies. Events are immutable and keyed by device and
  sequence, so syncing is a union and no conflict resolution is needed.
- Budgets and alerts per project, device, or day, with warn and stop modes.
- Dashboards in the TUI, desktop app, and Android app.
- `/cost-audit` reads this ledger.
- No telemetry leaves the user's mesh; export to CSV or JSON on demand.

### 7.6 Auto-resume

Two meanings, both in scope:

**Crash, reboot, disconnect, and teleport resume**

- Journal every state transition so a crash, reboot, disconnect, or teleport
  can resume.
- Resume policy: automatic on daemon restart; prompt when the device changed;
  bounded attempts with backoff; budget-aware refusal.
- Reconnect with a `{ generation, sequence }` cursor; replay or take a snapshot.
- Tool calls are idempotent where possible; uncertain results are surfaced,
  never replayed.
- Subagents, goals, heartbeats, and schedules resume with the root session.

**Usage-limit resume**

- When a provider reports a usage or rate-limit window (headers, a 429 with
  reset time, or provider usage endpoints), the session records the reset time,
  pauses at a safe boundary, and **resumes automatically when the window
  resets**, bounded by budgets and the active mode.
- The wait is visible: reason, reset time, and a cancel or "switch model/provider
  now" action. Routing may use another provider immediately where policy and
  budget allow.
- Resume never repeats an uncertain side effect, and never bypasses a limit by
  rotating accounts.

### 7.7 Self-hosted deployment

- One binary with `up`, `join`, `serve`, `relay`, `status`, `doctor`, and
  `teleport` subcommands.
- Embedded SQLite by default; optional Postgres for teams.
- systemd unit, Windows service, Docker Compose, and a LAN-only profile.
- Signed releases and an offline upgrade path.
- No required cloud account, no required relay, no central hosting.

### 7.8 Security model

- Threat model: hostile network, hostile relay, stolen device, malicious
  repository, compromised control plane.
- End-to-end encryption; relay sees ciphertext only.
- Device approval, short-lived join tokens, key rotation, revocation.
- Signed network state prevents silent node insertion.
- Audit log for joins, approvals, teleports, deletions, and permission
  decisions.
- Secrets live in the OS keychain where available; never in the repository.

---

## Part 8: OpenCode feature parity

Parity targets, verified against the current OpenCode documentation at
implementation time. Concepts only; no OpenCode code.

### Interfaces

- Terminal UI, desktop app, web UI, Docker image.
- `pair`-style one-time web link to drive a local session from a browser.
- Our additions: Android remote-control app, multi-device mesh, teleportation.

### Providers and auth

- Broad provider catalogue with `/connect`, OAuth and API keys.
- Local models (Ollama, LM Studio) and fully custom providers.
- OpenCode Console (paid, `oc_sk_`) and Go.
- Per-model variants and reasoning effort.
- `auth login|list|logout`.

### Agents and modes

- `build` (full access) and `plan` (read-only, asks before shell) agents,
  switchable from the composer.
- A `general`-style subagent for complex search and multi-step work, invocable
  by mention.
- Custom agents with their own model, prompt, tools, and permissions.
- Per-agent permission policy.

### Configuration

- Global and project config files, JSON/JSONC, environment overrides, and CLI
  flags.
- Themes, keybindings, TUI settings, terminal title, notifications.
- Model, provider, agent, MCP, plugin, command, and permission sections.

### Extensibility

- MCP servers (user-added), plugins with lifecycle hooks, custom tools, custom
  commands, and skills.
- LSP integration, formatters, and diagnostics.
- Our web tools stay native; MCP remains available for user servers only.

### Sessions

- List, resume, rename, fork, revert, export, import, share, and statistics.
- Auto-compaction and branch summaries.
- Multi-session tabs and prompt queue/steering.
- Snapshots and git-backed rollback.
- Share links and a local `share`/`pair` flow, disabled by default.

### Permissions

- Per-tool allow/ask/deny, per-agent, with project and user scopes.
- Central evaluation before every native, extension, MCP, and subagent call.
- Explicit approval UI with a durable decision record.

### Programmatic access

- `serve` HTTP API with an OpenAPI description.
- SDKs for JS/TS and Python; ACP stdio for editors.
- Headless JSON output and a one-shot run mode.
- VS Code, JetBrains, Zed/ACP integration.

### CLI surface to match

OpenCode's CLI is broad. Zero keeps the command line to four commands plus
machine-level lifecycle, because everything else is an action inside the app
(6.1):

- **CLI:** `zero resume`, `zero login`, `zero logout`, `zero doctor`.
- **Machine-level, not a product action:** `zero install`, `zero update`,
  `zero uninstall`, `zero service <start|stop|status>`, shell completion.
- **Everything else** (`run`, `serve`, `pair`, `auth`, `models`, `agent`, `mcp`,
  `export`, `import`, `stats`, `github`) exists as an action, reachable from
  every surface and through the SDK, ACP, and MCP server mode.
- Windows, macOS, Linux, WSL, and ARM64 builds.

### Other parity items

- Image and file attachments, `@` file references, path autocomplete.
- Streaming interrupt and steer.
- Auto-update and version checks.
- Theme and keybinding customisation.
- Localisation of user-facing strings.
- Usage, cost, and token statistics.
- GitHub integration for issues and pull requests.
- Docker deployment.

---

## Part 9: Resolved decisions

Recorded so later work does not re-litigate them.

1. **Mesh tunnel.** WireGuard with an audited implementation (OS kernel where
   available, `wireguard-go` otherwise). We own discovery, traversal, ACLs,
   relay, and clients. Easy defaults: one action up, QR join, LAN discovery.
2. **Control plane.** Decentralized. No central or privileged node; every node
   can serve the replicated, signed state. The mesh exists to keep traffic
   private and to avoid exposing IP addresses, not to manage a fleet. Keep the
   node surface small.
3. **Halcyon authentication.** Ed25519-signed file with a public key pinned in
   user configuration. Passkey and password/Argon2id are explicit fallbacks.
   Plaintext is discouraged and never the default.
4. **Firecrawl.** Not built in and not shipped. Crawling is native and local.
   Users who want Firecrawl add it as an MCP server through the regular MCP
   support.
5. **Android v1.** Remote control only: sessions, prompts, approvals, diffs,
   notifications. No agent runtime on the phone.
6. **Teleportation.** Best-effort kernel checkpoint plus a full workspace
   bundle of files, chunked and content-addressed. No repository assumption:
   no git remote, clone, or target checkout is required, and non-git
   directories work.
7. **Hosting.** Self-hostable and decentralised. No central account, no
   required relay, no vendor service. LAN-only is a first-class mode.
8. **Reuse.** Concept-only from Tailscale, NetBird, OpenCode, DeepSeek
   Harness, Kimi Code, Claude Code, and Tencent. No borrowed packages or code.
9. **Project identity.** A random key in `{project}/.zero/key`; the project ID
   is its hash. Paths are local bindings, not identity. Creation is automatic,
   moves rebind silently, and a detected copy prompts once for a new name and
   immediately creates a new key and binding. The original is untouched.
10. **Credential storage.** OS keychain first, encrypted file second, no
    plaintext. OpenCode's plaintext `auth.json`/SQLite model is explicitly not
    copied.
11. **Conversation control.** `steer`, `follow_up`, `auto`, and `interrupt`
    delivery modes; durable, editable queue.
12. **Monitors.** Background command stdout lines become session events, with
    declarative plugin monitors and strict network and permission bounds.
13. **Modes.** Five modes: `plan` (reads, MCP, and plan artifacts only),
    `manual` (yes/no on everything), `semi-auto` (writes and MCP automatic,
    bash manual, per-class configurable), `auto` (code-based plus AI-based
    regulators, both must allow), and `headless` (queue user-dependent work,
    continue everything else to the goal). Each carries its own prompt and
    harness profile. Enforcement is continuous at every dispatch, including
    mid-turn and mid-generation. An unavailable auto classifier degrades to
    manual, never to allow.
14. **Doctor.** Automatic diagnosis on failure and after updates, a stable
    failure taxonomy, bounded reversible repairs, snapshots before repair,
    trash instead of deletion, and a redacted offline forensic bundle.
15. **Task manager.** One task store with a DAG, atomic compare-and-swap
    transitions, expiring claims with fencing tokens, and journal replay.
    No two workers own the same task.
16. **File manager.** One filesystem access layer with versioned handles,
    ordered per-file and per-subtree locks with fencing, atomic writes, and
    three-way merge or explicit conflict. No silent overwrite, no torn files.
17. **Deadlock avoidance.** Banker's algorithm over declared maximum claims,
    with atomic batch grants, safe-state checks, aging, and fencing.
18. **Scheduling.** Multi-level feedback queues, weighted fair share, provider
    token buckets, rate-limit-aware backoff, cost-aware model routing, and
    durable queues to avoid 429s and wasted tokens.
19. **Todo manager.** A core, always-on, user-facing list separate from
    executable tasks. Only its `tkb` sync is flag-gated.
20. **Feature flags.** Only for Halcyon-linked integrations
    (`halcyon.mode`, `halcyon.todo_sync`, `halcyon.joker`, `halcyon.epb`).
    Everything else is ordinary configuration.
21. **Multi-model orchestration.** One model pool with capability and cost
    grades; route each unit of work to the cheapest model that clears its
    floor; specialist models per subagent role; evidence-based escalation;
    budgets and rate-limit-aware admission control.
22. **Multimodal input and computer use.** Images, documents, audio, and video
    in; a sandboxed desktop with screenshot-action loops; visual verification
    with labeled screenshots and recordings; strict untrusted-content and
    credential rules.
23. **Deletion scope.** The guard targets accidental deletion by agents, not a
    hostile local user. Layers: command and Python guards, shims, `trash`, and a
    backup of every overwritten file; optional OS sandboxing is hardening only.
24. **Halcyon trust.** A pinned-key Ed25519 signature is the proof. The nonce
    and HMAC exchange are removed because a static file cannot answer a
    challenge. Binding is to `projectId`, not path.
25. **Locking.** Banker's algorithm for bounded pools; ordered, wound-wait, and
    isolated-workspace strategies for files; per-resource owner nodes across
    devices.
26. **Workspace trust.** Untrusted folders have inert config, hooks, MCP,
    monitors, and `.halcyon-mode`. Trust is explicit and per project key.
27. **Auto-resume** means both crash resume and usage-limit-reset resume.
28. **Confirmed.** Rust core and one binary, best TUI first (`architecture.md`);
    audited building blocks allowed under the dependency policy (6.0); an
    app-level userspace overlay instead of a system VPN, with a rendezvous node
    role (7.1); isolated workspaces plus three-way merge for parallel file work
    (6.10.8).
29. **Secrets manager.** The agent writes a tag and a placeholder, and declares
    the trigger that may consume the value. A separate host-owned UI asks the
    user directly. Values are encrypted at rest and substituted only into that
    trigger, never into chat, logs, files, config, the kernel, or a teleport
    bundle. There is no `get` API (6.22).
32. **No decorative controls.** An action that does not need explicit
    invocation has no button, no menu entry, and no slash command. It runs
    automatically, is reached by a keybinding, or is shown as state. The
    slash commands and the four CLI commands are listed in 6.1. The daemon has
    its own app.
31. **Commands and actions.** One action registry for every command, slash
    command, and menu item, shared by all surfaces. Each action is slash-first
    or native; both call the same code. Deterministic actions run
    automatically with no model call. The agent invokes actions through
    `actions.run` within policy. The command line keeps only `resume`, `login`,
    `logout`, and `doctor`, plus install, update, uninstall, service, and
    completion (6.1).
30. **Security review.** `/security-review` follows Cloudflare's published
    multi-phase behaviour: an explicit checklist and coverage ledger first, then
    one hunting wave per unit, independent candidate validation, validated
    structured findings, fresh verification, and a report derived from the
    records. It never modifies target source (6.23).

### Open questions

Nothing is blocking. The questions raised during the audit are resolved and
recorded above:

- Marker file name is `.halcyon-mode`.
- Relay is automatic through the user's own approved nodes when a direct path
  fails, never a third party.
- Workspace bundles exclude secret patterns by default and report them.
- The ledger uses per-device append-only logs, unioned on sync.
- `.env` holds resolved values and is git-ignored; the encrypted vault travels
  through teleport as ciphertext; `.env.example` is git-tracked with tags.
- The secrets UI appears in the TUI, desktop, web, and Android apps.
- The TUI is built immediately after the safety core.
- Slices and the test strategy live in `plan.md`.
- Delivery scope and parity order live in `plan.md`; provider terms are in
  6.10.4; local CPU models and consent are in 6.12 and `architecture.md` 13a.

### Definition of done for this document

- `features.md` records the archived system, the research, the installers, the
  target system, the safety and trust model, the mesh and mobile design,
  OpenCode parity, the resolved decisions, and the normative requirement
  catalogue in Part 10 (every requirement has an ID and an acceptance
  criterion).
- `architecture.md` maps every requirement area to a module and records the
  design decisions. `plan.md` maps every area to a milestone with exit gates.
  `tasks.md` maps every requirement to at least one task with a verification.
- No implementation exists yet. Nothing is claimed to work. The next step is
  slice 0 (foundations and the stack decision), then slice 1 and slice 2 with
  tests, not more specification.

---

## Part 10: Requirements catalogue (normative)

Parts 6-8 describe intent. This part makes it testable. Every requirement has a
stable ID, a single normative statement, and an acceptance criterion (`AC`).
IDs never change; a withdrawn requirement is marked withdrawn, not deleted.

- **MUST** is mandatory for the milestone that owns it. **SHOULD** may slip with
  a recorded reason. **MAY** is optional.
- `AC` is what a reviewer can run or observe. Where an AC needs tooling that
  does not exist yet, the task that builds the tooling is named.
- Every requirement names its owning area. `plan.md` maps areas to milestones;
  `tasks.md` maps requirements to tasks; `architecture.md` maps areas to
  modules.
- A feature is not done because the code exists. It is done when its ACs pass
  in CI and the evidence is recorded.

### 10.1 Foundations (`FND`)

- **FND-01 Single native binary.** MUST ship one self-contained binary per
  platform with no Node, Python, JVM, or system runtime prerequisite.
  **AC:** on a clean VM, `zero --version` succeeds before any installer step
  beyond placing the binary.
- **FND-02 Platforms.** MUST support Windows x64/ARM64, macOS x64/ARM64, and
  Linux x64/ARM64. **AC:** CI builds and smoke-runs every target.
- **FND-03 Data directories.** MUST use per-OS data, config, cache, and state
  directories with documented paths. **AC:** a table in the docs matches the
  code constants, and a test asserts each path resolves per platform.
- **FND-04 Schema and migrations.** MUST version every persistent store and
  migrate forward automatically with a backup first. **AC:** a fixture from each
  prior schema version migrates and round-trips.
- **FND-05 Config precedence.** MUST resolve config as defaults, user, trusted
  project, environment, CLI, session, with untrusted project config inert.
  **AC:** a matrix test asserts the winner for every layer pair.
- **FND-06 Structured logging with redaction.** MUST emit structured logs with
  level, component, session, project, and correlation IDs, and MUST redact known
  secret patterns. **AC:** a seeded fake key never appears in any log sink.
- **FND-07 Error taxonomy.** MUST expose stable error codes with one remediation
  line each. **AC:** every thrown error carries a documented code; a test fails
  on an undocumented code.
- **FND-08 Deterministic core.** MUST inject clocks and ID generators so
  schedulers, locks, and leases can be simulated. **AC:** the same seed produces
  identical event ordering across runs.
- **FND-09 Durability.** MUST fsync durable writes and MUST survive a hard kill
  without corrupting the session log or journal. **AC:** kill -9 loop over a
  write-heavy run, then verify logs parse and replay.
- **FND-10 Offline operation.** MUST start, plan, edit, and reason offline when a
  local model is configured; network features MUST degrade with an explicit
  state. **AC:** with networking disabled, startup and file work still pass their
  smoke tests.
- **FND-11 Resource limits.** MUST bound memory, disk, process count, and file
  size for agent-launched work. **AC:** a runaway fixture hits the limit and
  returns a typed error instead of exhausting the host.
- **FND-12 No telemetry.** MUST NOT send usage or crash data off the machine or
  mesh without explicit opt-in. **AC:** a network capture of a normal session
  shows only user-configured provider and mesh traffic.

### 10.2 Actions and surfaces (`ACT`)

- **ACT-01 One registry.** MUST define every command, slash command, and menu
  item as an action in one registry shared by TUI, desktop, web, and Android.
  **AC:** no surface defines a command outside the registry.
- **ACT-02 Action record.** MUST record id, title, description, category,
  aliases, argument schema, required capabilities, mutating flag, deterministic
  flag, policy class, approval requirement, agent-invocable flag, unattended
  flag, idempotency key, and audit metadata.
  **AC:** a schema test rejects an action missing any field.
- **ACT-03 Two forms.** MUST allow an action to be slash-first or implicit; both
  call the same handler. **AC:** invoking `/x` and the implicit path produce
  identical events and audit records.
- **ACT-04 No decorative controls.** MUST NOT render a button, menu entry, or
  slash command for an action that needs no explicit invocation.
  **AC:** a registry lint fails when an implicit action has a UI control.
- **ACT-05 Agent invocation.** MUST expose `actions.list` and `actions.run(id,
  args)` gated by policy. **AC:** an action marked non-invocable cannot be run by
  the agent by any route, including writing the same step manually where the
  action class forbids it.
- **ACT-06 Determinism.** MUST run a deterministic action with no model call when
  inputs are known. **AC:** a deterministic action completes with zero provider
  requests.
- **ACT-07 Idempotency.** MUST accept `clientId + actionId` keys and MUST NOT
  apply the same mutation twice. **AC:** replaying a request yields the original
  result and one effect.
- **ACT-08 Auditing.** MUST audit every action with actor, surface, arguments
  digest, policy verdict, and outcome. **AC:** the audit log reconstructs a
  session's action history.
- **ACT-09 Extension actions.** MUST namespace plugin, skill, and MCP actions and
  MUST refuse shadowing of core action IDs. **AC:** a plugin claiming `mode.set`
  fails registration.
- **ACT-10 CLI surface.** MUST limit the command line to `resume`, `login`,
  `logout`, `doctor`, plus `install`, `update`, `uninstall`, `service`, and
  completion. **AC:** an unknown verb prints the action name instead of running.
- **ACT-11 Daemon app.** MUST provide a separate surface for workers,
  attachments, health, updates, and history. **AC:** worker operations are not
  reachable outside that surface.
- **ACT-12 Keybindings.** MUST map every key through the action registry with
  per-surface defaults, conflict detection, and no hardcoded key checks.
  **AC:** rebinding works for every action on every surface.
- **ACT-13 Discovery.** MUST provide a searchable palette and generated help
  listing only actions available in the current mode. **AC:** denied actions are
  absent or marked with the reason.
- **ACT-14 Shell prefix.** MUST treat a leading `!` as direct shell execution
  subject to the same policy as the shell tool. **AC:** `!rm` is blocked by the
  deletion guard.
- **ACT-15 Mode switching.** MUST switch modes by keybinding (`Shift+Tab` by
  default) with a visible indicator and no slash command. **AC:** the indicator
  updates on every surface within one frame.
- **ACT-16 Local web surface.** MUST serve the same UI from the local core bound
  to loopback behind a one-time token, and MUST NOT open a public listener.
  **AC:** a connection attempt from another host finds no listener, and a reused
  token is refused.

### 10.3 Terminal UI (`TUI`)

- **TUI-01 First paint.** MUST reach an interactive first frame in under 100 ms
  on a reference laptop. **AC:** benchmark gate in CI with a recorded baseline.
- **TUI-02 Frame budget.** MUST compute a typical frame in under 1 ms and MUST
  coalesce frames so token streaming cannot exceed a configured repaint rate.
  **AC:** streaming benchmark records frame compute and paint counts.
- **TUI-03 Diff rendering.** MUST render from front and back buffers, emitting
  only changed runs inside synchronized output where supported.
  **AC:** a golden-frame test on a virtual terminal matches expected cells and
  escape sequences.
- **TUI-04 Text correctness.** MUST handle grapheme clusters, East Asian width,
  emoji, combining marks, tabs, and bidi text, or declare the degradation.
  **AC:** a Unicode corpus renders without cell corruption.
- **TUI-05 Streaming Markdown.** MUST parse and lay out only the tail of a
  streaming message. **AC:** a 10k-message session streams at the same frame cost
  as a short one.
- **TUI-06 Virtualised transcript.** MUST lay out only visible rows.
  **AC:** scrolling cost is independent of history size.
- **TUI-07 Input protocols.** MUST use the Kitty keyboard protocol when
  available, with a bounded probe and declared fallback chords. **AC:** Windows
  ConPTY, tmux, and a legacy terminal each pass the input matrix.
- **TUI-08 Non-blocking loops.** MUST NOT block render or input on I/O.
  **AC:** a stalled provider or disk shows a busy state and keeps input
  responsive.
- **TUI-09 Identity selection.** MUST track selection by stable ID, reject stale
  async results by generation, and preserve selection across refreshes.
  **AC:** an async list refresh cannot change the selected row.
- **TUI-10 Slow-terminal mode.** MUST detect write latency and lower frame rate
  and effects automatically. **AC:** a simulated 40 ms write latency keeps input
  responsive.
- **TUI-11 Images.** SHOULD show inline images through the terminal graphics
  protocol with a textual placeholder otherwise. **AC:** both paths render the
  same artifact reference.
- **TUI-12 Theming.** MUST expose the full color-token system plus a 256-color
  palette. **AC:** every token is documented and overridable.
- **TUI-13 Accessibility.** MUST offer no-animation, high-contrast, and plain
  line-oriented modes, and MUST NOT encode state in color alone.
  **AC:** a screen-reader run completes a session start, prompt, and approval.
- **TUI-14 Secrets modal.** MUST render secret entry in host-owned chrome that
  the agent cannot draw into. **AC:** a test asserting agent output cannot
  produce the modal.
- **TUI-15 Status honesty.** MUST show mode, model, budget state, and pending
  approvals without overstating completion. **AC:** a snapshot test covers each
  state.
- **TUI-16 Handoff.** MUST switch to the daemon app and back without losing
  draft input. **AC:** the draft survives the round trip.

### 10.4 Policy and modes (`POL`)

- **POL-01 Five modes.** MUST implement `plan`, `manual`, `semi-auto`, `auto`,
  and `headless`.
- **POL-02 Action-class matrix.** MUST define one matrix of mode by action class
  (`read`, `write`, `shell_readonly`, `shell_mutating`, `delete`,
  `network_read`, `network_write`, `mcp_read`, `mcp_write`, `subagent`,
  `install`, `computer`, `credential`, `mesh`, `mode_change`).
  **AC:** the matrix is data, tested exhaustively.
- **POL-03 Continuous enforcement.** MUST evaluate at every dispatch, including
  mid-turn, mid-generation, and every kernel host request.
  **AC:** a mode change during a tool batch re-evaluates pending calls and leaves
  running calls to finish with their result reported.
- **POL-04 Order.** MUST evaluate deny, then ask, then allow; the first terminal
  match wins and a hard deny is never overridable.
  **AC:** a conflicting rule set resolves to deny.
- **POL-05 Kernel gating.** MUST route file, shell, network, credential, and mesh
  effects inside the kernel through host requests evaluated against the live
  mode. **AC:** plan mode blocks a Python write even when the code bypasses the
  edit tool.
- **POL-06 No self-escalation.** MUST NOT let an agent change its own mode,
  policy, or protected files. **AC:** an agent attempt returns a typed denial and
  an audit record.
- **POL-07 Inheritance.** MUST make subagents inherit the parent mode and never
  exceed it. **AC:** a subagent in plan mode cannot write.
- **POL-08 Unattended triggers.** MUST run schedules, heartbeats, monitors, and
  MCP events in headless or a restricted profile, never more permissive than the
  session.
- **POL-09 Exact approvals.** MUST bind an approval to the exact action hash and
  an expiry. **AC:** a changed command requires a new approval.
- **POL-10 Regulator isolation.** MUST give the AI regulator only the request,
  policy, and proposed action, never tool or web output.
  **AC:** injected content cannot reach the regulator prompt.
- **POL-11 Fail safe.** MUST degrade the affected class to manual when the auto
  regulator is unavailable. **AC:** a regulator outage blocks rather than
  allows.
- **POL-12 Headless queue.** MUST queue questions, approvals, credentials,
  irreversible actions, and product decisions durably, and continue independent
  work.
- **POL-13 Transitions.** MUST allow plan to semi-auto or auto on approval, and
  any mode to manual immediately; headless must end before an interactive mode
  takes over. **AC:** each transition is tested with in-flight work.
- **POL-14 Persistence.** MUST persist mode per session with a project default
  and MUST survive compaction, teleport, and auto-resume; each dispatch records
  the mode version used.
- **POL-15 Multi-client approvals.** MUST resolve a prompt once, first valid
  decision wins, others see it resolved, stale prompts expire.
- **POL-16 Plan-mode read-only tools.** MUST allow MCP and network tools in plan
  mode only when verified read-only, otherwise ask.
  **AC:** an unverified MCP write tool asks in plan mode.

### 10.5 Deletion safety (`DEL`)

- **DEL-01 Default deny.** MUST deny deletion everywhere except the `trash` tool.
- **DEL-02 Command guard.** MUST parse and block destructive shell commands for
  POSIX shells, PowerShell, and `cmd`, including wrappers such as `sh -c`,
  `env`, `sudo`, and `cmd /c`. **AC:** the guard corpus passes with zero false
  allows on the destructive list.
- **DEL-03 Shims.** SHOULD install PATH and PowerShell function shims to catch
  script-invoked deletions.
- **DEL-04 Python guard.** MUST block `os.remove`, `os.unlink`, `os.rmdir`,
  `os.removedirs`, `os.truncate`, `shutil.rmtree`, `Path.unlink`, `Path.rmdir`,
  and overwrite-by-move, raising a typed error.
- **DEL-05 Backup before overwrite.** MUST snapshot prior content into the undo
  journal before any managed overwrite, truncate, or move-over.
- **DEL-06 Native trash.** MUST use the OS trash (Recycle Bin, `trashItemAtURL`,
  freedesktop trash) with cross-device, read-only, symlink, open-file, and long
  path handling.
- **DEL-07 Protected paths.** MUST refuse trashing the home directory, drive
  roots, `.git`, `.zero`, the audit log and journals, the credential store, and
  system directories.
- **DEL-08 Purge.** MUST make permanent deletion human-only, dry-run, confirmed,
  and audited.
- **DEL-09 Zero-owned cleanup.** MUST limit internal garbage collection to Zero's
  own data directories under a retention policy, logged.
- **DEL-10 Mode mapping.** MUST treat `trash` as a reversible delete class:
  denied in plan, ask in manual, configurable in semi-auto, regulated in auto,
  allow-listed or queued in headless.
- **DEL-11 Limits stated.** MUST document that native extensions, `ctypes`, and
  absolute-path binaries can evade the guard, with the backup journal and OS
  trash as the backstop.
- **DEL-12 Unguarded third parties.** MUST state that third-party processes Zero
  did not launch are outside the guard.

### 10.6 File manager (`FS`)

- **FS-01 One layer.** MUST route every managed read, write, rename, and delete
  through the file manager.
- **FS-02 Versioned handles.** MUST return content hash, size, mtime, and file ID
  on open, and MUST fail writes on a stale version.
- **FS-03 Locks.** MUST support per-file and per-subtree locks with TTL, owner,
  and fencing token, coordinated through the daemon.
- **FS-04 Atomic writes.** MUST write via temp file, fsync, and rename, and
  preserve mode, encoding, BOM, line endings, and symlink targets.
- **FS-05 Consistency.** MUST provide read-your-writes to the owning session and
  watcher events to others.
- **FS-06 Conflict policy.** MUST serialize, three-way merge against a stored
  base, or fail with a precise conflict; never silently overwrite or tear a file.
- **FS-07 Batch transactions.** MUST make multi-file batches all-or-nothing by
  default with a journal, dry-run, and rollback.
- **FS-08 Isolated workspaces.** MUST give parallel agents copy-on-write
  overlays with a three-way merge and precise conflict reporting.
- **FS-09 Identity keys.** MUST key locks and versions by file ID with
  canonicalisation for case-insensitive volumes, Unicode normalisation,
  symlinks, junctions, hardlinks, long paths, reserved names, and UNC paths.
- **FS-10 Cross-device single writer.** MUST hold a single-writer lease over the
  mesh; teleport fences the old owner first.
- **FS-11 Crash recovery.** MUST expire stale locks, replay journals, and send
  deletes to the OS trash.
- **FS-12 Performance.** MUST index lines lazily and apply small edits in
  O(edits), not O(file size).
- **FS-13 Honest scope.** MUST record external changes from bash, builds, git,
  and IDEs through a watcher and raise `stale` on the next managed write.

### 10.7 Edit tool (`EDT`)

- **EDT-01 Handles.** MUST return a handle, version, line count, encoding, and
  newline style without returning file contents.
- **EDT-02 Operations.** MUST support replace, insert, delete, wrap, move, copy,
  rename, write, and patch.
- **EDT-03 Anchors.** MUST use content-addressed anchors (exact text or hash plus
  optional range) and MUST fail closed on drift.
- **EDT-04 Batching.** MUST apply many operations across files in one call.
- **EDT-05 Receipts.** MUST return `{ok, files, firstError}` without file bodies,
  and MUST bound failures to a three-line context window.
- **EDT-06 Concurrency.** MUST verify the version before writing and MUST return
  `stale` on change.
- **EDT-07 Atomicity.** MUST apply batches all-or-nothing by default with
  `continueOnError` opt-in.
- **EDT-08 No deletion.** MUST refuse deletion and route it to `trash`.
- **EDT-09 Reversibility.** MUST journal every batch and support undo.
- **EDT-10 Formatting.** MUST NOT auto-format unless configured.
- **EDT-11 Large files.** MUST edit by range without loading the whole file where
  the platform allows.
- **EDT-12 Context economy.** MUST never echo a full file into the transcript
  unless explicitly requested.

### 10.8 Task manager (`TSK`)

- **TSK-01 One store.** MUST own goals, plan tasks, subagent jobs, background
  commands, monitors, schedules, and MCP tasks.
- **TSK-02 States.** MUST use `queued`, `ready`, `running`, `blocked`,
  `waiting_input`, `done`, `failed`, `cancelled`.
- **TSK-03 DAG.** MUST ready a task only when all dependencies are done and MUST
  reject cycles.
- **TSK-04 Claims.** MUST grant claims with owner, generation, and TTL, and MUST
  reject stale writes by fencing token.
- **TSK-05 Transitions.** MUST compare-and-swap on task version and append every
  change to an event journal.
- **TSK-06 Exclusive ownership.** MUST never hand one task to two workers.
- **TSK-07 Limits.** MUST enforce per-project concurrency, priorities, fairness,
  and backpressure.
- **TSK-08 Recovery.** MUST replay the journal, expire stale leases, and mark
  interrupted work resumable, not failed.
- **TSK-09 User queue.** MUST route blocked-on-user items into the headless user
  queue and keep blocked-on-dependency items idle.
- **TSK-10 Cross-device.** MUST replicate state over the mesh with one writer per
  task.
- **TSK-11 Audit.** MUST record who changed what, when, and with what evidence.
- **TSK-12 Halcyon view.** MUST map `tkb` as a view over this store, not a second
  store.
- **TSK-13 Plan seeding.** MUST seed tasks from an approved plan artifact and the
  agent's progress view from the same store.

### 10.9 Todo manager (`TODO`)

- **TODO-01 Separate store.** MUST keep user todos separate from executable
  tasks.
- **TODO-02 Fields.** MUST store id, title, notes, state (`open`, `doing`,
  `blocked`, `done`, `dropped`), priority, due date, tags, linked task IDs, and
  evidence.
- **TODO-03 Scopes.** MUST support project and session scopes with a merged
  view.
- **TODO-04 Capture.** MUST support fast keyboard-first capture, inline edit,
  bulk select, filters, search, daily review, and stale-item detection on TUI,
  desktop, and Android.
- **TODO-05 Agent tool.** MUST expose add, list, update, complete, block, and
  drop, with versioned journaled changes.
- **TODO-06 Explicit linking.** MUST never silently complete a task when a todo
  completes, or the reverse.
- **TODO-07 Persistence.** MUST survive compaction, teleport, and auto-resume.
- **TODO-08 Reminders.** SHOULD notify on due items with per-item mute.
- **TODO-09 Halcyon sync.** MUST sync with `tkb` only when `halcyon.todo_sync` is
  on and Halcyon mode is active, through an offline queue, idempotent and
  version-checked, with conflicts surfaced as conflict items.
- **TODO-10 Ownership.** MUST require confirmation for the agent to complete or
  drop a user-created item outside an explicit auto rule.
- **TODO-11 Standalone.** MUST work with no flag when Halcyon mode is off.

### 10.10 Lock manager (`LCK`)

- **LCK-01 Resource types.** MUST cover file locks, subtree locks, task claims,
  kernel slots, provider slots, and mesh transfer slots.
- **LCK-02 Banker's pools.** MUST apply Banker's algorithm to bounded countable
  pools with declared maximum claims.
- **LCK-03 Atomic batches.** MUST grant all locks in a batch or none.
- **LCK-04 Starvation.** MUST age waiting requests and MUST preempt only where
  release is safe.
- **LCK-05 File strategy.** MUST use canonical order acquisition, wound-wait for
  priority, timeouts, optimistic versions, and isolated workspaces instead of
  declared maxima for files.
- **LCK-06 Degraded mode.** MUST report when a worker cannot declare a bounded
  maximum and fall back to ordered acquisition with timeouts.
- **LCK-07 Owner nodes.** MUST assign each resource one owner node by
  deterministic election and MUST move ownership by fenced lease handoff.
- **LCK-08 Fencing.** MUST reject writes from a stale token after preemption.
- **LCK-09 External holders.** MUST surface human, IDE, and git holders as
  watcher conflicts, never as locks the manager owns.
- **LCK-10 Partition.** MUST deny new leases in a partitioned minority.
- **LCK-11 Bounded check.** MUST run safety checks off the render and stdin path
  with a bounded cost.
- **LCK-12 Exceeding maxima.** MUST abort the request with a clear error when a
  worker exceeds declared maxima.

### 10.11 Scheduler (`SCH`)

- **SCH-01 Registry.** MUST register every agent and subagent with class,
  priority, deadline, token budget, dependencies, and state.
- **SCH-02 Queues.** MUST use multi-level feedback queues with priority and
  aging, short-task-first within class, round-robin across equal classes, and
  weighted fair share per project.
- **SCH-03 Preemption.** MUST preempt only at safe boundaries; it MUST NOT claim
  to preempt a model call in flight.
- **SCH-04 Admission.** MUST enforce per-provider and per-model concurrency and
  per-credential token buckets, driven by rate-limit headers and `Retry-After`.
- **SCH-05 Backoff.** MUST use exponential backoff with jitter, a circuit breaker
  per provider, and a retry cap, without stalling unrelated providers.
- **SCH-06 Cost routing.** MUST pick the cheapest model that clears the task
  class floor, respect budgets, and bound fan-out.
- **SCH-07 Fairness.** MUST let interactive work preempt background work at safe
  boundaries and MUST prevent starvation.
- **SCH-08 Backpressure.** MUST bound queues and expose an explicit `deferred`
  state instead of unbounded growth.
- **SCH-09 Budgets.** MUST predict cost before dispatch, reserve `max_tokens`,
  reconcile after, and refuse or defer work over a session, project, or daily
  budget with an explanation.
- **SCH-10 Observability.** MUST expose throughput, 429 rate, queue latency,
  preemptions, and cost per completed task.
- **SCH-11 Durability.** MUST persist queues and resume after restart without
  duplicating in-flight calls.
- **SCH-12 Distributed limits.** MUST share one credential's limit across
  devices through the owning node, with a conservative local share offline.
- **SCH-13 No evasion.** MUST NOT rotate accounts to bypass provider limits.
- **SCH-14 Usage windows.** MUST model remaining capacity and reset time for
  subscription windows and schedule a resume.

### 10.12 IPython kernel (`KRN`)

- **KRN-01 Isolation.** MUST run one persistent kernel per root session.
- **KRN-02 Preload.** MUST preload the web tools, `tool_search`, `trash`, and
  Halcyon adapters when active.
- **KRN-03 Persistence.** MUST keep variables, imports, helpers, and handles
  across calls and compaction.
- **KRN-04 Cells.** MUST run `%%bash` cells in a throw-away subshell while
  preserving `%cd` and Python state.
- **KRN-05 Host requests.** MUST route authoritative state and every external
  effect through typed host requests.
- **KRN-06 Restart.** MUST rehydrate from the session log and report in-flight
  work lost rather than silently dropping it.
- **KRN-07 Output.** MUST capture, truncate, stream, and account output bytes
  and tokens.
- **KRN-08 Trust.** MUST document that model code runs with worker permissions
  and MUST NOT claim sandboxing unless the OS sandbox is enabled.
- **KRN-09 No secrets.** MUST NOT expose secret values to the kernel.
- **KRN-10 Protocol.** MUST speak the Jupyter messaging protocol with the
  documented version and HMAC signing.
- **KRN-11 Limits.** MUST bound memory, CPU time, output size, and cell duration.
- **KRN-12 Cancellation.** MUST interrupt a cell at a safe point and report
  partial output.

### 10.13 Sessions (`SES`)

- **SES-01 Log.** MUST store append-only JSONL entries covering messages, model
  changes, thinking level, service tier, compaction, branch summary, custom,
  child usage, label, info, state, status, and git state.
- **SES-02 Operations.** MUST support named, resumed, forked, cloned, and
  tree-structured sessions.
- **SES-03 Compaction.** MUST compact with cut-point rules and extension hooks
  and MUST retain recent messages and kernel state.
- **SES-04 Summaries.** MUST produce branch summaries with goal, constraints,
  progress, decisions, next steps, critical context, and cumulative file
  tracking.
- **SES-05 Context files.** MUST load `AGENTS.md` and `CLAUDE.md` with a
  documented precedence and size cap.
- **SES-06 Leases.** MUST hold a process-safe lease per canonical log path and
  converge concurrent creates on one worker.
- **SES-07 Replay.** MUST use generation and sequence cursors with coherent
  attach snapshots and chunked large snapshots.
- **SES-08 Backpressure.** MUST isolate backpressure per attachment.
- **SES-09 Commands.** MUST journal mutations before dispatch and MUST report
  uncertain side effects instead of replaying them.
- **SES-10 Artifacts.** MUST store per-session artifacts with references from the
  transcript.
- **SES-11 Naming.** MUST auto-name sessions from project and timestamp.
- **SES-12 Portability.** MUST export and import sessions with a versioned
  format.

### 10.14 Providers (`PRV`)

- **PRV-01 Catalogue.** MUST ship a provider catalogue with searchable models,
  context limits, pricing, and capabilities.
- **PRV-02 Custom providers.** MUST support custom base URLs, headers, per-model
  overrides, and Anthropic- and OpenAI-compatible shims.
- **PRV-03 Streaming.** MUST stream responses and MUST retry idempotent failures
  with backoff.
- **PRV-04 Fallback.** MUST support provider fallback chains and service tiers.
- **PRV-05 Local.** MUST support Ollama and LM Studio plus custom local
  endpoints.
- **PRV-06 Console.** MUST support OpenCode Console with `oc_sk_` keys and Go
  usage.
- **PRV-07 Errors.** MUST map provider errors to stable codes with one
  remediation each.
- **PRV-08 Catalog refresh.** MUST refresh the catalogue with a recorded source
  and MUST keep a working offline copy.
- **PRV-09 Auth methods.** MUST support API key, OAuth, and device code where the
  provider documents it.
- **PRV-10 Terms gating.** MUST disable any login flow not documented for
  third-party clients, and MUST record the check date.
- **PRV-11 Measured use.** MUST record model, version, parameters, latency,
  tokens, and outcome for every call.

### 10.15 Model pool and routing (`MDL`)

- **MDL-01 Pool.** MUST register provider, family, version, context, output
  limit, cost (input, output, cache), rate limits, availability, and capability
  grades for coding, reasoning, instruction following, tool use, vision, long
  context, and latency.
- **MDL-02 Class routing.** MUST classify work (plan, edit, review, test,
  research, summarise, visual inspection) and choose the cheapest model that
  clears the floor.
- **MDL-03 Security floor.** MUST set a minimum capability for security-sensitive
  or destructive work and MUST never silently downgrade it.
- **MDL-04 Escalation.** MUST retry on the next tier on failure, timeout,
  refusal, or low confidence, with the failure evidence attached.
- **MDL-05 Draft-review.** SHOULD support cheap drafting with a stronger review.
- **MDL-06 Ensemble.** MUST limit ensembles to high-cost-of-error decisions
  within budget.
- **MDL-07 Roles.** MUST define planner, coder, reviewer, tester, researcher, and
  vision roles with default models.
- **MDL-08 Budgets.** MUST enforce per-task, per-project, and daily budgets with a
  predicted cost before dispatch.
- **MDL-09 Measured routing.** MUST route on recorded success, retries, latency,
  and cost, with minimum sample sizes and an exploration rate.
- **MDL-10 Cache.** MUST keep a stable prefix and account for cache loss when
  switching models.
- **MDL-11 Record.** MUST record the model, version, parameters, and router
  reason for every turn.
- **MDL-12 Overrides.** MUST let user pinning, allowlists, denylists, and privacy
  constraints override the router.
- **MDL-13 Translation.** MUST translate transcripts between provider formats,
  dropping non-portable blocks and recording the change.
- **MDL-14 Deprecation.** MUST re-route on model deprecation with a warning, never
  silently.
- **MDL-15 Freshness.** MUST refresh model data on a schedule with a recorded
  source.

### 10.16 Credentials (`CRT`)

- **CRT-01 Keychain.** MUST store credentials in the OS credential store when
  available.
- **CRT-02 Fallback.** MUST use an encrypted file (AES-256-GCM with a wrapped
  key) when no keychain exists.
- **CRT-03 No plaintext.** MUST NOT persist plaintext credentials anywhere.
- **CRT-04 References.** MUST allow config values to reference secrets instead
  of embedding them.
- **CRT-05 Accounts.** MUST support multiple named accounts per provider with
  list, switch, rename, and sign-out.
- **CRT-06 Redaction.** MUST redact credentials from logs, transcripts, tool
  output, and crash reports, and MUST zeroise buffers.
- **CRT-07 Locking.** MUST lock the store on screen lock and after idle.
- **CRT-08 Import.** MUST import plaintext stores explicitly, warn, and trash the
  old file after success.
- **CRT-09 Unattended.** MUST support a machine-bound unlock (TPM, DPAPI machine
  scope, or `systemd-creds`) or per-session entry on headless hosts.
- **CRT-10 Child environment.** MUST give children a scrubbed environment.
- **CRT-11 Single refresher.** MUST use one refresher per credential under a
  cross-process lock.
- **CRT-12 No printing.** MUST NOT print a secret except through an explicit
  user-only action.

### 10.17 Secrets manager (`SEC`)

- **SEC-01 Tags.** MUST let the agent request a secret by tag and write a
  placeholder (`{{secret:TAG}}`, `Secret("TAG")`) instead of a value.
- **SEC-02 Trigger binding.** MUST require the agent to declare the trigger
  (host, command, env slot, or SDK slot) that may consume the value.
- **SEC-03 Ask the user in the UI.** MUST collect the value in the secrets UI on
  the TUI, desktop, web, and Android, owned by the host and not drawable by the
  agent.
- **SEC-04 Encryption.** MUST store values with AES-256-GCM, a per-secret nonce,
  and associated data binding tag, scope, and project ID; the data key MUST be
  wrapped by the OS store or an Argon2id-derived key.
- **SEC-05 Substitution.** MUST substitute only inside the bound transport
  (header, query, stdin, env slot, SDK slot) and never into chat, receipts, file
  writes, logs, or the kernel.
- **SEC-06 Binding mismatch.** MUST fail closed with `SECRET_BINDING_MISMATCH`
  when the destination differs from the binding.
- **SEC-07 No read API.** MUST NOT expose any tool, action, or kernel call that
  returns a value.
- **SEC-08 Redaction set.** MUST add a resolved value to the session redaction
  set.
- **SEC-09 Audit.** MUST audit request, approval, refusal, substitution,
  rotation, and revocation with tag and binding, never the value.
- **SEC-10 Rotation.** MUST support rotate and revoke with dependent-process
  reload.
- **SEC-11 Teleport.** MUST move the vault as ciphertext and MUST require one
  unlock (passphrase, re-entry, or approved transfer) on the target.
- **SEC-12 `.env`.** MUST write a git-ignored `.env` with resolved values at mode
  0600, a git-tracked `.env.example` with placeholders, and MUST block
  committing a real value.
- **SEC-13 Headless.** MUST queue a secret request in headless mode and continue
  independent work.
- **SEC-14 Scan.** MUST scan files and git history for stored values and offer
  rotation.
- **SEC-15 Mode.** MUST treat `credential` as its own action class: denied in
  plan, ask in manual and semi-auto, regulated in auto, allow-listed or queued in
  headless.
- **SEC-16 No leakage.** MUST NOT persist values in `.zero/`, config, session
  logs, teleport bundles in plaintext, or transcripts.
- **SEC-17 Scope.** MUST scope a secret to project, user, or machine with
  documented precedence.
- **SEC-18 Drift.** MUST detect a changed stored value and report drift rather
  than silently continuing.

### 10.18 Web tools (`WEB`)

- **WEB-01 Search.** MUST search in parallel across keyless engines with
  per-engine adapters and health checks.
- **WEB-02 Fusion.** MUST fuse results by reciprocal rank and deduplicate by
  fuzzy title and canonical host plus path.
- **WEB-03 Filters.** MUST support freshness, include and exclude domains,
  category routing, and required or forbidden substrings.
- **WEB-04 Provenance.** MUST attach result age and the source of the date to
  every result.
- **WEB-05 Resilience.** MUST apply per-engine rate limits, exponential backoff,
  a circuit breaker, and a reserve engine, and MUST bench an engine on CAPTCHA or
  login instead of failing the search.
- **WEB-06 Cache.** MUST cache in SQLite FTS5 with per-category TTLs and a
  cache-age filter.
- **WEB-07 Research.** MUST provide search plus top-N fetch returning one dated
  brief.
- **WEB-08 Fetch.** MUST extract reader-mode Markdown in-house.
- **WEB-09 JS fallback.** MUST fall back to a local headless browser for
  JavaScript-heavy pages, installed on demand with checksum verification.
- **WEB-10 Documents.** MUST read PDF, DOCX, XLSX, PPTX, EPUB, CSV, code, text,
  and archives.
- **WEB-11 Crawl.** MUST run a persistent job store with frontier queue,
  robots.txt, sitemap discovery, depth and page limits, path regexes, domain
  rules, deduplication, concurrency limits, retries, and resumable state.
- **WEB-12 Job states.** MUST expose `queued`, `scraping`, `completed`, `failed`,
  `cancelled`, progress, paging, and a separate robots-blocked errors list.
- **WEB-13 Map.** MUST discover URLs from sitemaps and links without fetching
  every page.
- **WEB-14 Extract.** MUST return structured JSON against a caller schema.
- **WEB-15 Browser.** MUST provide our own DevTools-protocol automation
  (navigate, click, type, wait, evaluate, screenshot, download).
- **WEB-16 SSRF.** MUST block loopback, private, link-local, and metadata ranges,
  pin resolved addresses, re-check redirects, and refuse non-HTTP schemes.
- **WEB-17 Egress.** MUST check outbound requests for secrets and apply the
  network policy per mode.
- **WEB-18 Archives.** MUST reject zip-slip, symlink escape, and decompression
  bombs with byte, count, and depth limits.
- **WEB-19 Untrusted content.** MUST label fetched content as data and MUST NOT
  treat it as instructions.
- **WEB-20 Firecrawl.** MUST NOT ship or bundle Firecrawl; users may add it as an
  MCP server.
- **WEB-21 Budgets.** MUST account per-page and per-crawl cost before starting.

### 10.19 MCP (`MCP`)

- **MCP-01 Core.** MUST implement the `2026-07-28` stateless core with no
  protocol session and no required handshake, and MUST negotiate older
  revisions.
- **MCP-02 Headers.** MUST send `MCP-Protocol-Version`, `Mcp-Method`, and
  `Mcp-Name` for routing and metering.
- **MCP-03 Result type.** MUST honor `resultType` and treat older servers as
  `complete`.
- **MCP-04 Caching.** MUST honor `ttlMs` and `cacheScope` with deterministic
  ordering.
- **MCP-05 Schemas.** MUST validate JSON Schema 2020-12 input and output with
  `$ref` resolution and bounds on composition.
- **MCP-06 Transports.** MUST support stdio and Streamable HTTP, with legacy
  HTTP+SSE only as a documented compatibility shim.
- **MCP-07 MRTR.** MUST retry a call with `inputResponses` after
  `input_required` without relying on held-open streams.
- **MCP-08 Elicitation.** MUST use URL mode for anything sensitive and MUST refuse
  credentials in form mode.
- **MCP-09 Tasks.** MUST poll, update, and cancel tasks, honor TTL and poll
  intervals, and treat task IDs as bearer secrets.
- **MCP-10 Events.** MUST support poll, push, and webhook delivery with cursors,
  no resumption assumption, signature checks, and TTL renewal.
- **MCP-11 Apps.** MUST sandbox `ui://` resources in iframes with a strict CSP
  and block top-level navigation.
- **MCP-12 Extensions.** MUST negotiate skills over MCP and enterprise managed
  authorization and MUST ignore unknown extensions without failing.
- **MCP-13 Auth.** MUST use OAuth 2.1 with PKCE, resource indicators, issuer
  validation, and CIMD primary registration.
- **MCP-14 Security.** MUST pin tool schema hashes, default destructive tools to
  ask, validate output size, enforce timeouts, propagate cancellation, and apply
  SSRF and replay protection.
- **MCP-15 Server mode.** MAY expose tools, sessions, and events over MCP,
  disabled by default.
- **MCP-16 Resources and prompts.** MUST map resources to `@` references and
  prompts to slash commands, and MUST support completions.
- **MCP-17 stdio sandbox.** MUST launch stdio servers with a scrubbed
  environment, per-project approval, resource limits, and the deletion guard.
- **MCP-18 Trust.** MUST keep project servers inert until the folder is trusted.
- **MCP-19 Conformance.** MUST pass conformance fixtures for `2025-11-25` and
  `2026-07-28`.

### 10.20 Trust and threat model (`TRU`)

- **TRU-01 Boundaries.** MUST document the trust boundaries: user, agent,
  kernel, tools, MCP servers, web content, mesh peers, repository config.
- **TRU-02 Workspace trust.** MUST keep config, hooks, monitors, MCP servers,
  skills, instruction files, and `.halcyon-mode` inert until the folder is
  trusted, and MUST limit an untrusted folder to plan-equivalent behaviour.
- **TRU-03 Untrusted data.** MUST label web, MCP, repository, image, and tool
  content as data that never becomes instructions.
- **TRU-04 Audit integrity.** MUST hash-chain the audit log and keep it outside
  agent-writable paths.
- **TRU-05 Protected paths.** MUST protect policy, config, journals, vault, audit,
  and credential files from agent writes.
- **TRU-06 Hardening.** MAY enable OS sandboxing (Landlock or seccomp, Windows
  job objects or AppContainer) without claiming it replaces the guards.
- **TRU-07 No live probing.** MUST NOT test against production, shared, or
  third-party systems during audits or reviews.
- **TRU-08 Secret isolation.** MUST keep credentials out of kernels, subprocess
  environments, transcripts, and teleport bundles.

### 10.21 Doctor (`DOC`)

- **DOC-01 Surfaces.** MUST provide `zero doctor`, `/doctor`, a tool, and a panel.
- **DOC-02 Triggers.** MUST run on demand, on startup failure, after a crash, and
  after an update.
- **DOC-03 Diagnosis.** MUST check versions, config, project key and binding,
  supervisor and workers, kernel and environment, providers and auth, network and
  mesh, ports, disk, locks, journals, MCP handshakes, and logs.
- **DOC-04 Taxonomy.** MUST define stable failure codes with one playbook each,
  including at least `KERNEL_BOOT`, `DAEMON_STALE`, `AUTH_EXPIRED`,
  `JOURNAL_CORRUPT`, `DISK_FULL`, `PORT_CONFLICT`, `LOCK_STALE`,
  `MESH_UNREACHABLE`, `MCP_HANDSHAKE`, `PROJECT_KEY_MISSING`.
- **DOC-05 Recovery.** MUST dry-run, snapshot, repair reversibly, use trash, roll
  back on failure, and never force-kill unrelated processes.
- **DOC-06 Autonomy.** MUST apply safe fixes automatically and require
  confirmation for risky ones, recording evidence and outcome.
- **DOC-07 Forensics.** MUST produce an incident timeline and a redacted offline
  support bundle.
- **DOC-08 Agent API.** MUST expose `diagnose`, `plan`, and `apply` and MUST
  require the agent to report unresolved failures.
- **DOC-09 Independence.** MUST run with the daemon, kernel, and mesh dead.
- **DOC-10 Policy.** MUST never be more permissive than the current mode.
- **DOC-11 Tests.** MUST have a fault-injection test per failure code.

### 10.22 Security review (`SR`)

- **SR-01 Mode gate.** MUST run guidance mode rather than a full audit unless the
  user asks for an audit, a full review, or report artifacts.
- **SR-02 Checklist first.** MUST produce the trust-boundary summary and the
  coverage ledger before hunting, and MUST validate the ledger before assignment.
- **SR-03 Ledger.** MUST record one unit per surface, boundary, subsystem, and
  applicable attack class with canonical references, starting paths, selected and
  excluded companions with reasons, status, owner, reviewed paths, checks, and
  fingerprints.
- **SR-04 Phases.** MUST run reconnaissance, coverage-led hunting waves,
  independent validation, structured output, independent record verification, and
  reporting, in order.
- **SR-05 Evidence bar.** MUST reject a candidate that names no lower-trust
  principal, crossed boundary, or concrete result.
- **SR-06 Structured output.** MUST write `findings.json` and
  `coverage-ledger.json` and MUST validate both.
- **SR-07 Severity.** MUST assign severity only to confirmed records and MUST NOT
  exceed demonstrated impact.
- **SR-08 No mutation.** MUST NOT modify target source; fixes are proposals.
- **SR-09 Sandbox.** MUST run target code only in the OS sandbox with no external
  network, an allowlisted empty environment, a read-only target, scratch-only
  writes, and resource limits; otherwise it MUST NOT run target code.
- **SR-10 Write isolation.** MUST give each agent its own scratch and MUST allow
  promotion only by trusted parent code with path, symlink, type, and size
  checks.
- **SR-11 Prior runs.** MUST re-verify carried confirmations and MUST turn
  changed, blocked, and deferred units into current work; `out_of_scope` never
  means covered.
- **SR-12 Budget.** MUST reserve critic and validation agents and MUST report an
  incomplete run instead of thinning evidence.
- **SR-13 Profiles.** MUST implement `quick`, `standard`, and `deep`, and MUST
  label scoped runs as partial.
- **SR-14 Reports.** MUST derive `REPORT.md`, `FINDINGS-DETAIL.md`, and
  `NEEDS-VALIDATION.md` from final records only.
- **SR-15 Zero integration.** MUST make each ledger unit a task, write output
  under `.zero/audits/run-N/`, and keep results offline.
- **SR-16 Immutable bar.** MUST NOT let project configuration relax the evidence
  bar or the phases.
- **SR-17 Feed the loop.** MAY propose a bounded fix and regression test per
  confirmed finding, promoted only with fresh evidence.

### 10.23 Halcyon (`HAL`)

- **HAL-01 Trigger.** MUST activate only from a `.halcyon-mode` file found in the
  working directory, an ancestor, or an immediate child, nearest wins, with
  same-distance conflicts disabling the mode with a reason.
- **HAL-02 Hidden when absent.** MUST register nothing when the file is absent.
- **HAL-03 Verification.** MUST verify an Ed25519 signature over canonical bytes
  against a key pinned in user configuration, with passkey and Argon2id as
  explicit fallbacks.
- **HAL-04 Signing.** MUST provide keygen, sign, pin, unpin, rotate, revoke, and
  verify, with keys in the OS store or hardware.
- **HAL-05 Binding.** MUST bind the file to `projectId` with an issued-at time and
  optional expiry, and MUST NOT bind to a path.
- **HAL-06 Token.** MUST issue a short-lived in-memory capability token bound to
  file hash, project, process, and build, invalidated on change, expiry, restart,
  or revoke.
- **HAL-07 Adapters.** MUST detect `tkb`, `joker`, and `epb` at runtime, refuse
  vendor binding at build time, and degrade missing binaries to disabled tools
  with installation guidance.
- **HAL-08 Behaviour.** MUST encode the mode's workflow natively (record gaps
  with `tkb add`, run gates only through `joker`, route endpoints through `epb`,
  require `tkb check` and a handover before finishing), never by reading
  Halcyon's instructions.
- **HAL-09 No faux.** MUST refuse stand-in backends for missing endpoints.
- **HAL-10 Flags.** MUST gate only `halcyon.mode`, `halcyon.todo_sync`,
  `halcyon.joker`, and `halcyon.epb`, and MUST NOT let project config enable
  them.
- **HAL-11 Sync.** MUST sync todos bidirectionally with `tkb` only when enabled,
  idempotent and version-checked, with conflicts visible.
- **HAL-12 Trust.** MUST stay inert in an untrusted workspace even when signed.
- **HAL-13 Versioning.** MUST negotiate adapter versions and degrade features a
  CLI lacks.

### 10.24 Mesh (`MESH`)

- **MESH-01 Overlay.** MUST run an app-level userspace overlay (WireGuard
  protocol) with no TUN device, no admin rights, and no `VpnService`.
- **MESH-02 Decentralized.** MUST have no privileged node; registry, ACLs, names,
  and state MUST be signed, versioned, and replicated.
- **MESH-03 LAN.** MUST form a mesh over authenticated mDNS with no account and
  no service.
- **MESH-04 Traversal.** MUST use STUN-style discovery, UDP hole punching, and a
  TCP/443 fallback.
- **MESH-05 Relay.** MUST relay only ciphertext and only through approved nodes.
- **MESH-06 Exposure.** MUST default-deny inbound and MUST NOT expose listeners;
  direct paths expose endpoints only to the peer.
- **MESH-07 Easy defaults.** MUST create identity, start the mesh, and show a QR
  from one action, and MUST join by QR or short code.
- **MESH-08 Identity.** MUST use an Ed25519 device identity with explicit
  approval, short-lived single-use join tokens, rotation, and revocation.
- **MESH-09 Root of trust.** MUST sign membership with an owner root key, or a
  threshold of delegates, so a stolen device cannot evict others.
- **MESH-10 Rendezvous.** MUST state that cross-network connectivity needs at
  least one reachable node and MUST fail with that explanation.
- **MESH-11 Names.** MUST resolve stable device names inside the mesh only.
- **MESH-12 Offline.** MUST work LAN-only with no account, service, or relay.
- **MESH-13 Presence.** MUST expose only online state and reachability, with no
  fleet orchestration.
- **MESH-14 Cost.** MUST respect battery and metered links and MUST report
  sleeping devices as offline.
- **MESH-15 Audit.** MUST audit joins, approvals, rotations, revocations, and
  relays.

### 10.25 Teleport (`TEL`)

- **TEL-01 Preflight.** MUST check target capabilities, disk, model access,
  policy, and required tools before starting.
- **TEL-02 Quiesce.** MUST finish or checkpoint in-flight work, stop new input,
  and snapshot the draft.
- **TEL-03 Snapshot.** MUST include transcript, entries, kernel state, artifacts,
  goals, schedules, heartbeats, permissions, tool state, usage ledger, and a
  workspace manifest.
- **TEL-04 Bundle.** MUST move real files with type, size, mode, symlink target,
  and content hash; payloads MUST be content-addressed, chunked, resumable, and
  deduplicated; `.git` MUST be optional data.
- **TEL-05 Secrets.** MUST exclude secret patterns by default, report every
  exclusion, carry the vault as ciphertext, and require one unlock on the target.
- **TEL-06 Transfer.** MUST be end-to-end encrypted, resumable, and retained on
  the source until the target verifies.
- **TEL-07 Restore.** MUST recreate directories, files, modes, and symlinks,
  replay the transcript, restore the kernel, and rebind schedules and children.
- **TEL-08 Conflicts.** MUST stage into a new directory or reconcile explicitly
  and MUST NOT overwrite silently.
- **TEL-09 Verify.** MUST check every file hash and the manifest hash before
  marking complete.
- **TEL-10 Fence.** MUST remove the source write lease before granting the target
  lease, with a generation counter.
- **TEL-11 Resume.** MUST reattach clients, continue the turn, and verify.
- **TEL-12 Portability.** MUST rebuild unpicklable or OS-specific state from the
  log, remap absolute paths, and tell the model the directory changed.
- **TEL-13 Unreachable source.** MUST support a forced takeover with a
  generation bump, and the returning source MUST become read-only and preserve
  divergent edits.
- **TEL-14 Honest limits.** MUST report processes, PTYs, and sockets that do not
  move, and MUST NOT claim completion on a failed transfer.

### 10.26 Android (`AND`)

- **AND-01 Scope.** MUST be remote control only in v1.
- **AND-02 Pairing.** MUST pair by QR or one-time code with biometric unlock and
  no public endpoint.
- **AND-03 Control.** MUST list sessions, show a live transcript, send prompts,
  steer, queue, cancel, approve or deny, and view diffs.
- **AND-04 Approvals.** MUST bind approvals to the action hash with expiry, hide
  codes on the lock screen, and require biometrics to raise the mode.
- **AND-05 Notifications.** MUST notify completion, failures, and approval
  requests, with a foreground service or UnifiedPush and no silent Google
  dependency.
- **AND-06 Resilience.** MUST queue offline input and reconnect with a cursor.
- **AND-07 Share.** MUST accept shared text, images, and links.
- **AND-08 Secrets.** MUST support the secrets prompt with `FLAG_SECURE`.
- **AND-09 Networking.** MUST use the userspace mesh with no `VpnService`
  eviction.
- **AND-10 Resources.** SHOULD report relay versus direct and estimate data use.
- **AND-11 Sleep.** MUST show a sleeping or offline host accurately.

### 10.27 Conversation control and monitors (`MON`)

- **MON-01 Queue.** MUST queue messages typed during a turn, persist them, and
  show them in the composer across compaction, teleport, and resume.
- **MON-02 Delivery.** MUST support `steer`, `follow_up`, `auto`, and
  `interrupt`.
- **MON-03 Boundaries.** MUST apply steering at the next safe boundary and MUST
  NOT rewrite an executing tool call.
- **MON-04 Management.** MUST support edit, reorder, cancel, send now, and take
  back.
- **MON-05 Limits.** MUST bound the queue and MUST reject new items with a clear
  message rather than dropping old ones.
- **MON-06 Monitors.** MUST stream each stdout line as an event, coalesce bursts,
  and send stderr to logs only.
- **MON-07 Sources.** MUST support log tail, CI or PR polling, directory watch,
  WebSocket feeds, and long-running scripts.
- **MON-08 Lifecycle.** MUST start manually, at session start, or on skill
  invoke, and MUST stop with the session.
- **MON-09 Declarative.** MUST support plugin monitors declared with name,
  command, description, and `when`.
- **MON-10 Safety.** MUST require shell approval, apply allowlists, sandbox
  where possible, deny private and metadata addresses, and cap output.
- **MON-11 Distinctions.** MUST distinguish background task, monitor, MCP task,
  and MCP event.
- **MON-12 Restart.** MUST restart monitors after teleport or resume only with
  confirmation.
- **MON-13 Cost.** MUST coalesce and threshold events so idle noise costs no
  tokens.
- **MON-14 Muting.** MUST allow per-monitor mute on every surface.

### 10.28 Usage and cost (`USG`)

- **USG-01 Ledger.** MUST record per session, device, model, provider, and tool:
  input, output, cache read, cache write, cost, wall time, retries, and subagent
  share.
- **USG-02 Local first.** MUST keep an append-only local ledger per device and
  MUST merge by union.
- **USG-03 Budgets.** MUST support warn and stop budgets per project, device, or
  day.
- **USG-04 Visibility.** MUST show usage in the TUI, desktop, and Android.
- **USG-05 Audit.** MUST feed `/cost-audit` from the ledger.
- **USG-06 Export.** MUST export CSV or JSON on demand and MUST NOT send
  telemetry.
- **USG-07 Windows.** MUST track subscription usage windows and reset times.
- **USG-08 Attribution.** MUST attribute child and subagent usage to the parent.

### 10.29 Auto-resume (`AR`)

- **AR-01 Journal.** MUST journal every state transition needed to resume after
  crash, reboot, disconnect, or teleport.
- **AR-02 Policy.** MUST resume automatically on daemon restart, prompt when the
  device changed, bound attempts with backoff, and refuse over budget.
- **AR-03 Cursor.** MUST reconnect with a generation and sequence cursor and
  replay or snapshot.
- **AR-04 Idempotency.** MUST NOT replay uncertain side effects and MUST surface
  them.
- **AR-05 Children.** MUST resume subagents, goals, heartbeats, and schedules with
  the root.
- **AR-06 Usage reset.** MUST pause at a safe boundary on a usage or rate-limit
  window and resume when it resets, within budget and mode.
- **AR-07 Visibility.** MUST show the reason, reset time, and a cancel or switch
  action while waiting.
- **AR-08 No evasion.** MUST NOT bypass limits by rotating accounts.

### 10.30 Self-improvement (`SI`)

- **SI-01 Loop.** MUST execute, verify in the real environment, capture the
  trajectory and decision record, distil one bounded change, evaluate on a
  held-out set and the original failure, promote or discard, and re-enter.
- **SI-02 Verification.** MUST NOT accept self-report as evidence.
- **SI-03 Record.** MUST persist diagnosis, revision, evidence, and outcome.
- **SI-04 Scope.** MUST limit a change to one skill, prompt, tool description, or
  routing rule.
- **SI-05 Evaluator.** MUST version the evaluator and MUST prevent a candidate
  from modifying its own acceptance test or holdout.
- **SI-06 Immutable core.** MUST forbid changes to deletion policy, mode policy,
  protected paths, audit, evaluator, credential handling, and promotion rules.
- **SI-07 Human gate.** MUST require approval to promote anything influenced by
  untrusted content.
- **SI-08 Isolation.** MUST NOT run concurrently with the task it measures.
- **SI-09 Rollback.** MUST make every promoted change diffable and reversible.
- **SI-10 Cost audit.** MUST analyse spend, propose bounded changes, apply only
  reversible ones with `--apply`, measure the next window, and roll back on
  regression.

### 10.31 Multimodal and computer use (`MM`)

- **MM-01 Inputs.** MUST accept text, images, documents, audio, video, code, and
  attachments from paste, drag and drop, `@` references, clipboard, and the
  Android share sheet.
- **MM-02 Blocks.** MUST store typed content blocks with per-modality token
  accounting and must keep originals for later re-read.
- **MM-03 Preprocessing.** MUST downscale, crop, tile, OCR, sample frames, and
  transcribe as needed, with originals preserved.
- **MM-04 Redaction.** MUST attempt secret and PII redaction before egress and
  MUST describe it as best effort.
- **MM-05 Targets.** MUST support a sandboxed target (VM, container, virtual
  display) and MUST treat the live host desktop as a higher-risk class.
- **MM-06 Action loop.** MUST screenshot, identify elements, act, and verify, with
  deterministic waits and retries.
- **MM-07 Takeover.** MUST pause the agent before human takeover.
- **MM-08 Verification.** MUST produce labeled screenshots, chaptered
  recordings, and pass or fail assertions, and MUST flag shortcuts.
- **MM-09 Artifacts.** MUST store outputs per project and expose them on desktop
  and Android.
- **MM-10 Safety.** MUST treat images and frames as untrusted, sandbox the
  desktop, allowlist the network, deny host filesystem by default in the sandbox
  target, and pause for CAPTCHA and MFA.
- **MM-11 Modes.** MUST apply the five modes to computer actions.
- **MM-12 Remote.** MUST let Android send media and watch live and MUST keep
  traffic on the mesh.
- **MM-13 Local models.** MUST use only CPU-capable local models, with explicit
  consent naming licence, disk, memory, and purpose.
- **MM-14 Routing.** MUST route a non-vision model's image to a vision model or
  an OCR path instead of ignoring it.

### 10.32 Installers and release (`INST`)

- **INST-01 Channels.** MUST support `stable` and `beta` channels with
  `ZERO_VERSION` and `ZERO_RELEASE_CHANNEL` overrides.
- **INST-02 Authenticity.** MUST verify a release manifest signed with an
  Ed25519 key embedded in the installer.
- **INST-03 No runtime prerequisite.** MUST NOT require Node.
- **INST-04 Safety.** MUST use an install lock, restore the terminal on trap, and
  clean temporary directories.
- **INST-05 Non-interactive.** MUST run without a TTY and in CI without hanging.
- **INST-06 PATH.** MUST update the user PATH and explain manual steps when it
  cannot.
- **INST-07 Kernel bootstrap.** MUST install `uv`, Python, and `ipykernel` on
  request with checksum verification and an offline mode.
- **INST-08 Lifecycle.** MUST support install, update (atomic, signed,
  rollback), and uninstall that trashes user data after confirmation.
- **INST-09 Services.** MUST install systemd, Windows service, and launchd units.
- **INST-10 Offline upgrade.** MUST support upgrading from a local signed
  package.
- **INST-11 Artifacts.** MUST publish per-platform artifacts and an SBOM with
  each release.
- **INST-12 Uninstall.** MUST leave no orphaned service, PATH entry, or data
  without explicit consent.

### 10.33 Observability and audit (`OBS`)

- **OBS-01 Logs.** MUST emit component-tagged structured logs with correlation
  IDs.
- **OBS-02 Audit.** MUST record mode changes, approvals, deletions, actions,
  credential and secret use, MCP calls, sign-ins, mesh events, and teleports.
- **OBS-03 Metrics.** MUST expose local counters for queue depth, latency, 429s,
  retries, and cost.
- **OBS-04 Tracing.** SHOULD trace a turn end to end locally.
- **OBS-05 Redaction.** MUST redact secrets and personal data in every sink.
- **OBS-06 Retention.** MUST apply documented retention and MUST use trash for
  expired data.
- **OBS-07 Support bundle.** MUST produce a redacted offline bundle.
- **OBS-08 Self-hosted only.** MUST keep all telemetry local to the device or
  mesh.

### 10.34 Test and quality gates (`TST`)

- **TST-01 Slice gates.** MUST require per-slice acceptance criteria and a
  passing verification command.
- **TST-02 Determinism.** MUST simulate lock, task, and scheduler interleavings
  and MUST model-check Banker's safety.
- **TST-03 Fuzzing.** MUST fuzz the shell guard parser, protocol decoder, config
  parser, and archive extraction.
- **TST-04 Policy matrix.** MUST test every mode and action class, including
  mid-turn switches, subagents, and kernel host requests.
- **TST-05 Network.** MUST test mesh and teleport under loss, latency,
  partition, and NAT types.
- **TST-06 Fault injection.** MUST inject every documented failure code.
- **TST-07 Performance.** MUST gate startup, frame, attach, memory, and
  session-size budgets.
- **TST-08 Security suites.** MUST run SSRF, zip-slip, prompt-injection, and
  secret-leak suites.
- **TST-09 TUI goldens.** MUST compare rendered frames against snapshots on a
  virtual terminal.
- **TST-10 Conformance.** MUST run MCP and protocol conformance fixtures.
- **TST-11 Honesty.** MUST fail a release that claims a feature without a passing
  AC.

### 10.35 Parity and non-goals (`PAR`)

- **PAR-01 Mapping.** MUST map every Part 1, 2, and 8 item to keep, changed,
  dropped with a reason, or later.
- **PAR-02 V1 scope.** MUST follow the parity table in `plan.md`.
- **PAR-03 Non-goals.** MUST NOT implement a system VPN, an agent runtime on
  Android, a bundled browser engine, plaintext credential storage, free-tier
  bridging, or client-identity spoofing.
- **PAR-04 Maintenance.** MUST update traceability when a requirement changes
  state.

### 10.37 Projects (`PRJ`)

- **PRJ-01 Identity.** MUST identify a project by a random key in `.zero/key`
  with `projectId = hash(key)`; paths MUST be local bindings, not identity.
- **PRJ-02 Creation.** MUST create `.zero/` and the key automatically on first
  use, name the project from the directory with a numeric suffix on collision,
  and add `.zero/` to `.gitignore` when a repository exists, reporting the edit.
- **PRJ-03 Root detection.** MUST attach to the nearest `.zero/`, else the git
  root, else the working directory, stopping at home or the filesystem root.
- **PRJ-04 Moves.** MUST rebind a moved project silently when the key is
  unchanged and no concurrent copy exists.
- **PRJ-05 Copies.** MUST detect the same key at two paths with independent
  histories, ask once for a new name, mint a new key and binding, record
  `copiedFrom`, and leave the original untouched; non-interactive runs use the
  prefilled name.
- **PRJ-06 Explicit sharing.** MUST offer shared identity only through the
  deliberate `/link` action, never in the copy prompt, and MUST make `/link`
  non-agent-invocable.
- **PRJ-07 Replaced key.** MUST ask whether to adopt or restore when a path's key
  changes and MUST never discard history silently.
- **PRJ-08 One decision per pair.** MUST store the answer so a key pair is never
  asked twice.
- **PRJ-09 Layout.** MUST keep `project.json`, `key`, `config`, `plan`, `tasks`,
  `todos`, `journal`, `artifacts`, `vault`, and `audits` in `.zero/`, with no
  plaintext secret values.
- **PRJ-10 Migration.** MUST migrate legacy `.pi` and keyless `.zero/` layouts
  once, automatically, and log what changed.
- **PRJ-11 Sync.** MUST replicate keys over the mesh so the same key is the same
  project on every device at whatever path each device uses.
- **PRJ-12 Recovery.** MUST provide recovery actions for init, list, show, bind,
  move, rekey, and forget, and MUST keep them out of the agent's reach.

### 10.38 Tool registry and search (`TOOL`)

- **TOOL-01 Metadata.** MUST record name, description, argument names and
  descriptions, tags, examples, risk class, cost class, scope, and deferred flag
  for every tool.
- **TOOL-02 Core set.** MUST load `ipython`, `tool_search`, `trash`,
  `web_search`, and `web_fetch` every turn and defer the rest.
- **TOOL-03 Search.** MUST rank by BM25 with optional regex and optional
  embeddings over names, descriptions, arguments, tags, and examples, and MUST
  return the best three to five with full schemas loaded.
- **TOOL-04 Context activation.** MUST surface candidates from file extension,
  working directory, git state, language, task keywords, and recent use, as
  advisory only.
- **TOOL-05 Thresholds.** MUST load all definitions below a configurable share of
  the context window and switch to progressive discovery above it.
- **TOOL-06 Lifetime.** MUST keep discovered tools until compaction and
  rediscover on demand.
- **TOOL-07 Cache safety.** MUST append discovered tools after the stable prefix.
- **TOOL-08 Ranking trust.** MUST prefer native tools on ties and MUST resist
  name or description stuffing by a server.
- **TOOL-09 Policy awareness.** MUST NOT surface a tool denied in the current
  mode.
- **TOOL-10 Telemetry.** MUST record surfaced, chosen, rejected, and failed tools
  for tuning.
- **TOOL-11 Hygiene.** MUST flag near-duplicate names and ambiguous descriptions
  at registry build time.
- **TOOL-12 Dual route.** MUST enforce identical policy whether a tool is called
  over the protocol or imported inside the kernel.

### 10.39 Goals, heartbeats, schedules, autonomy (`AUT`)

- **AUT-01 Goals.** MUST keep an objective across turns with token, time, and
  continuation accounting until complete, paused, or cleared.
- **AUT-02 Heartbeats.** MUST support user heartbeats and agent heartbeats with
  status, pause, resume, clear, and follow-up delivery.
- **AUT-03 Schedules.** MUST support one-off and cron schedules with claimed
  ticks, coalesced missed ticks, and persistence per session.
- **AUT-04 Autonomous runs.** MUST continue until quality gates pass or turn,
  token, or time limits are reached, returning bounded output and not re-running
  a gate on an unchanged workspace.
- **AUT-05 Limits.** MUST enforce default token, time, and step limits for every
  autonomous or headless run.
- **AUT-06 Attribution.** MUST attribute usage and artifacts to the goal or
  schedule that caused them.
- **AUT-07 Mode safety.** MUST run unattended work in headless or a restricted
  profile, never in a more permissive mode than the session.
- **AUT-08 Cancellation.** MUST cancel a run, its children, and its queued work
  together.
- **AUT-09 Visibility.** MUST show every run's state, spend, and next tick on
  every surface.

### 10.36 Traceability

| Area | Module (see `architecture.md`) | Milestone (`plan.md`) |
|---|---|---|
| FND | `zero-types`, `zero-store`, `zero-cli` | M0 |
| ACT | `zero-actions`, `zero-tui`, `zero-daemon-app` | M1, M3 |
| TUI | `zero-tui` | M3 |
| POL | `zero-policy` | M2 |
| DEL | `zero-policy`, `zero-fs` | M2 |
| FS, EDT | `zero-fs` | M4 |
| TSK, TODO, LCK, SCH | `zero-tasks`, `zero-sched` | M4 |
| KRN | `zero-kernel` | M4 |
| SES, MON | `zero-agent`, `zero-store` | M1, M6 |
| PRV, MDL | `zero-model` | M1, M7 |
| CRT, SEC | `zero-secrets` | M5 |
| WEB | `zero-web` | M6 |
| MCP | `zero-mcp` | M6 |
| TRU | `zero-policy` | M2 |
| DOC | `zero-doctor` | M6 |
| SR | `zero-review` | M6 |
| HAL | `zero-halcyon` | M7 |
| MESH, TEL | `zero-mesh` | M8 |
| AND | `android/` | M9 |
| USG, AR | `zero-store`, `zero-sched` | M7 |
| SI | `zero-agent`, `zero-review` | M8 |
| MM | `zero-mm` | M9 |
| INST, OBS, TST | `zero-cli`, `zero-types`, `tests/` | M0, M10 |
| PRJ | `zero-agent`, `zero-store` | M5 |
| TOOL | `zero-agent` (registry), `zero-kernel` | M4 |
| AUT | `zero-agent`, `zero-sched` | M4, M6 |
| PAR | docs | continuous |

Part 10 is the normative source. If `architecture.md`, `plan.md`, or
`tasks.md` disagree with a requirement here, this part wins and the other
documents are corrected.
