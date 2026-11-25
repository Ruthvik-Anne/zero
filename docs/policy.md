# Policy and modes

The evaluator is `zero_policy::Policy`, the only source of permits. A tool or
kernel effect runs only with a `Permit` minted by `PolicyEngine::authorize`.

## Matrix

One table: five modes × fifteen action classes (`zero_policy::MATRIX`). The
exhaustive test compares every cell against the golden rows; changing a default
requires changing the test.

| Class | plan | manual | semi-auto | auto | headless |
|---|---|---|---|---|---|
| read | allow | allow | allow | allow | allow |
| write | deny | ask | allow | allow | allow |
| shell_readonly | allow | ask | ask | allow | allow |
| shell_mutating | deny | ask | ask | allow | ask |
| delete (trash) | deny | ask | ask | allow | ask |
| network_read | allow | ask | ask | allow | allow |
| network_write | deny | ask | ask | allow | ask |
| mcp_read | allow* | ask | allow | allow | allow |
| mcp_write | ask | ask | allow | allow | allow |
| subagent | ask | ask | ask | allow | allow |
| install | deny | ask | ask | allow | ask |
| computer | deny | ask | ask | ask | deny |
| credential | deny | ask | ask | ask | ask |
| mesh | ask | ask | ask | allow | ask |
| mode_change | deny | deny | deny | deny | deny |

\* plan-mode MCP/network calls require a user-verified read-only tool; an
unverified tool asks (POL-16).

## Order

1. **Hard deny**, never overridable: agent mode change, protected paths,
   subagent escalation beyond its parent, and plan-equivalent policy for an
   untrusted project.
2. **Exact approval** may lift an `ask` to `allow`; it never lifts a `deny`.
3. **Ask rules**: unverified tool in plan mode, irreversible work in
   plan/manual/semi-auto/headless.
4. **Matrix or per-project override**.

An `ask` in headless mode sets `queue: true`: the item goes to the durable user
queue instead of stalling unrelated work.

## Permits and audit

`Permit` has private fields and no public constructor. The agent's tool registry
only exposes `call_with_permit`, which checks the hash and class. Denials, asks,
and allows are appended to the hash-chained audit log with rule, reason, action
hash, and policy version.

## Regulators

Auto mode requires both:
- the deterministic code regulator: protected paths, raw deletes, inline
  secrets, credential use, network allowlists, cost ceiling, recursion depth,
  tool schema changes;
- the AI regulator, which sees only the user request, the policy summary, and
  the action — never tool, web, or MCP output.

If the AI regulator is absent or errors, the outcome is `Unavailable`, which the
caller treats as `ask` (manual). It never degrades to allow.

## Transitions and persistence

- plan → semi-auto/auto requires `plan_approved`;
- any mode → manual is immediate;
- headless must be ended (`end_headless`) before another interactive mode takes
  over;
- everything else is a typed `zero.pol.transition_invalid`.

The mode is written as a `state` entry (`policy.mode`) so it survives
compaction, reopen, teleport, and resume. Running calls are preserved across a
transition; pending calls are re-evaluated.
