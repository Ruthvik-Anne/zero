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
  <a href="https://github.com/PrimeIntellect-ai/prime-agent/actions/workflows/ci.yml">
    <img src="https://github.com/PrimeIntellect-ai/prime-agent/actions/workflows/ci.yml/badge.svg" alt="CI" />
  </a>
  <a href="https://github.com/PrimeIntellect-ai/prime-agent/actions/workflows/build-binaries.yml">
    <img src="https://github.com/PrimeIntellect-ai/prime-agent/actions/workflows/build-binaries.yml/badge.svg" alt="Build Binaries" />
  </a>
</p>

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

Install the latest stable release on macOS or Linux by piping `install.sh` to `sh` from your release host (the script reads its download location from `ZERO_DOWNLOAD_BASE_URL`, configured per distribution):

```bash
curl -fsSL <your-release-host>/install.sh | sh
```

The installer downloads a versioned release, verifies its SHA-256 checksum, installs the `zero` command, and can prepare the IPython runtime used by the agent.

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
zero --resume <path|id>       # Resume a saved session
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

## Acknowledgements

Our agent and TUI is built on top of [`pi`](https://github.com/earendil-works/pi). We thank the authors of `pi` for their valuable work.

## License

Zero is fully open source and released under the [MIT License](LICENSE).
