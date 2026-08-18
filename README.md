<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/brand/zero-mark.svg">
    <img alt="Zero mark" src="assets/brand/zero-mark-black.svg" width="120" style="max-width: 100%;">
  </picture>
</p>

<h3 align="center">
Zero: A Self-Improving RLM Agent
</h3>

<p align="center">
  <a href="packages/coding-agent/docs/index.md">Documentation</a> &bull;
  <a href="https://github.com/PrimeIntellect-ai/verifiers">Verifiers</a> &bull;
  <a href="https://github.com/PrimeIntellect-ai/prime-rl">PRIME-RL</a> &bull;
  <a href="https://github.com/badlogic/pi-mono">pi-mono</a>
</p>

<p align="center">
  <a href="https://github.com/Ruthvik-Anne/zero/actions/workflows/ci.yml">
    <img src="https://github.com/Ruthvik-Anne/zero/actions/workflows/ci.yml/badge.svg" alt="CI" />
  </a>
  <a href="https://github.com/Ruthvik-Anne/zero/actions/workflows/build-binaries.yml">
    <img src="https://github.com/Ruthvik-Anne/zero/actions/workflows/build-binaries.yml/badge.svg" alt="Build Binaries" />
  </a>
</p>

> This is a personal fork of [PrimeIntellect-ai/prime-agent](https://github.com/PrimeIntellect-ai/prime-agent), rebranded. See [Acknowledgements](#acknowledgements).

Zero is an open-source coding and research agent for general and long-running work. It is designed around two core abstractions:

- The **[Recursive Language Model (RLM)](https://www.primeintellect.ai/blog/rlm)** treats context as variables (*prompt-as-a-variable*) and tools like recursive subagents as function calls (*programmatic tool /sub-agent calling*) inside a persistent REPL.
- The **[Continual Harness](https://arxiv.org/abs/2605.09998)** stores supplemental prompts, memories, skill descriptions, and reusable subagent specifications as durable state that Zero can refine through small, evidence-backed updates, local to the session by default.

Zero combines a persistent Python control environment with durable harness state, so useful working context and reusable operating patterns can outlive a single chat window.

- **Everything is programmatic:** persistent IPython is the built-in model tool; file operations, shell commands, tool use, subagents, and context management happen through code.
- **Subagents are built in:** `rlm(...)` spawns real child agents for parallel or background work and returns their results programmatically.
- **The harness can improve:** `/refine` reviews the current trajectory and can apply small, evidence-backed updates to supplemental harness state. It never rewrites the immutable base system prompt, and recorded snapshots support rollback.
- **Skills are executable:** skills are importable Python packages, and the built-in skill creator can turn recurring workflows into project or personal skills.
- **Sessions run in the background:** daemon-backed agents keep running when the terminal disconnects and can be reattached later.
- **Agents communicate directly:** running agents can exchange messages and orchestrate one another without routing everything through the user.
- **Long tasks keep moving:** automatic compaction, persistent goals, heartbeats, schedules, autonomous mode, and retained subagents preserve progress across turns and terminal sessions.

## Getting Started

Releases are published as [GitHub Releases](https://github.com/Ruthvik-Anne/zero/releases) on this repo (see [Creating a release](#creating-a-release) below) — no separate download host, CDN, or `gh` CLI required.

```bash
curl -fsSL https://raw.githubusercontent.com/Ruthvik-Anne/zero/main/install.sh | sh
```

```powershell
irm https://raw.githubusercontent.com/Ruthvik-Anne/zero/main/install.ps1 | iex
```

Start Zero from the repository or directory you want it to work in:

```bash
cd /path/to/project
zero
```

On first launch, run `/login` to choose a subscription or API-key provider. Zero works in the current directory and can run commands and modify files there. Use a disposable clone, clean worktree, or another checkpoint you can inspect and restore.

> [!WARNING]
> Zero executes model-generated Python and project commands with your user permissions. Its worker and kernel processes improve lifecycle isolation and recovery; they are **not** a security sandbox. Review changes and use trusted repositories, instructions, skills, and extensions only. Run untrusted code or instructions in an external sandbox or restricted environment.

Useful commands:

```bash
zero agents                   # Browse running, idle, and saved sessions
zero attach <agent>           # Reattach to a running session
zero --resume [path|id]       # Browse sessions or resume one directly
zero status                   # Inspect background service state
zero doctor [--fix]           # Inspect or repair background services
zero update [--force]         # Update Zero
zero shutdown [--force]       # Stop every agent, worker, and background service
```

## Built for Long-Running Work
Zero is built for long-running work, especially for evaluations in research. These features are available in the TUI, and when run autonomously.

- **Continual Harness:** `/refine` can persist focused, reviewable lessons as supplemental prompts, memories, reusable skill descriptions, or subagent specifications, with recorded refinement history. It does not replace packaging and reviewing new executable skills.
- **Direct agent-to-agent communication:** running agents and retained subagents can discover one another, exchange messages, and steer active work.
- **Daemon-backed continuity:** active sessions, IPython state, schedules, and subagents keep running when the terminal detaches and can be reattached later.
- **Heartbeats and schedules:** `/heartbeat`, `rlm_heartbeat`, and `zero schedule` can re-enter a session periodically or at a specific time.
- **Persistent goals:** `/goal` keeps an objective and its progress active across turns until it is completed, paused, or cleared.
- **Bounded autonomous mode:** `/autonomous` continues within configured turn, token, and time budgets and can run user-defined quality gates. A passed gate checks only what that gate verifies; reaching a limit does not imply task success.

## Documentation

- [Quickstart](packages/coding-agent/docs/quickstart.md) — install, authenticate, and run a first session
- [Usage and CLI reference](packages/coding-agent/docs/usage.md) — commands, sessions, autonomous limits, and output modes
- [Long-running and background agents](packages/coding-agent/docs/long-running-agents.md) — detach and reattach, goals, heartbeats, and schedules
- [RLM programming model](packages/coding-agent/docs/rlm.md) — persistent IPython, subagents, skills, and the trust model
- [JSON mode](packages/coding-agent/docs/json.md) and [RPC mode](packages/coding-agent/docs/rpc.md) — headless automation and integrations
- [Skills](packages/coding-agent/docs/skills.md) — install and create reusable capabilities
- [Provider setup](packages/coding-agent/docs/providers.md) — subscription and API-key providers
- [Architecture overview](packages/coding-agent/docs/architecture.md) — daemon, worker, kernel, and persistence boundaries
- [Development](packages/coding-agent/docs/development.md) — build and run from source

## Creating a Release

Releases run through `.github/workflows/build-binaries.yml` — no CDN, bucket, or npm publish required:

- **Push to `main`** publishes/refreshes the floating `beta` release (a prerelease, force-moved to the latest `main` commit on every push).
- **Push a `vX.Y.Z` tag** (or run the workflow manually via `workflow_dispatch` with a `release_tag` input) publishes a production release at that version.

Either way the workflow builds all four packages, packs them with `npm run release:pack` (see `scripts/pack-zero-release.mjs` — it rewrites the coding-agent tarball's internal `@zero-agent/*` dependencies to relative `file:` references so the four tarballs install correctly as long as they sit in the same directory, which is exactly how a GitHub Release download drops them), and attaches `zero-<version>.tgz`, `zero-ai-<version>.tgz`, `zero-core-<version>.tgz`, `zero-tui-<version>.tgz`, and `SHA256SUMS` to the release. `install.sh` (see [Getting Started](#option-2-install-a-published-release)) downloads and verifies those same four tarballs.

To cut a production release by hand instead of tagging:

```bash
gh workflow run build-binaries.yml -f release_tag=v0.7.3
```

## Contributing

This is a personal fork without an organized contribution process — feel free to open an issue or PR if something's broken, but there's no roadmap or review SLA. Read [CONTRIBUTING.md](CONTRIBUTING.md) if you want the fuller process this was forked from, and the [security policy](SECURITY.md) for how upstream handles vulnerability reports.

## Acknowledgements

This is a personal, rebranded fork of [PrimeIntellect-ai/prime-agent](https://github.com/PrimeIntellect-ai/prime-agent) — all credit for the original design and implementation goes to Prime Intellect and its contributors. Their agent and TUI is in turn built on top of [`pi`](https://github.com/earendil-works/pi); we thank the authors of `pi` for their valuable work too.

## License

Zero is released under the [MIT License](LICENSE), inherited from the upstream project this was forked from.
