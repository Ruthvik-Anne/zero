# Trust boundaries and workspace trust

## Boundaries

Authority increases upward; trust in content decreases downward.

| Layer | Authority | Trust of its content |
|---|---|---|
| User | full | trusted |
| Agent | delegated, never self-escalating | — |
| Kernel / shell | host requests only, no ambient authority | untrusted code |
| Native tools | permit-gated, policy-evaluated | — |
| MCP servers | permit-gated, untrusted output | untrusted |
| Web content | data only | untrusted |
| Mesh peers | signed membership, untrusted payloads | untrusted |
| Repository config | inert until trusted | untrusted |

Tool output, web pages, repository text, images, and MCP results are data, never
instructions. They are labelled at the boundary and cannot reach the AI
regulator (only the request, policy, and action do).

## Workspace trust

Trust is explicit, per project key, and revocable. `TrustStore` records who
trusted it and when, and when it was revoked. Until trusted, the project
contributes nothing:

- `.zero/hooks.json`, `.zero/monitors.json`, `.zero/mcp.json`,
  `.zero/skills.json` are not loaded;
- `AGENTS.md` / `CLAUDE.md` are not loaded;
- `.halcyon-mode` is ignored;
- policy runs plan-equivalent (no writes, deletes, mutating shell, or installs)
  regardless of the configured mode.

Revocation takes effect immediately and is durable. Re-trusting is an explicit
user action.

## Protected files

Policy, trust, config, journals, vault, audit, and credential files are refused
for agent writes with `zero.pol.self_escalation` or `zero.del.protected`, and the
attempt is audited. The audit log is hash-chained and lives under the Zero data
root, outside agent-writable project paths.

## Audit integrity

Each audit record hashes `(seq, ts, actor, kind, payload, prev)`. Verification
reports the first broken record, so an edited payload, a deleted middle record,
or a reordered chain is detected at the link that broke. A tampered log refuses
to open (`zero.tru.tamper`).

## What the sandbox does not do

An optional OS sandbox (Landlock/seccomp, job objects/AppContainer) hardens the
kernel and shell but is not claimed to replace these guards. See
`docs/decisions/0001-sandbox.md`.
