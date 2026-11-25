# Tasks and todos

Two stores with different owners: executable tasks and user todos. Neither
completes the other.

## Task store

One store owns plan tasks, subagent jobs, background commands, monitors,
schedules, and MCP tasks.

### States and transitions

`queued → ready → running → done`, with `blocked`, `waiting_input`, `failed`,
and `cancelled`. Every change is a compare-and-swap on the task version; a stale
version is `zero.fs.conflict`. The journal is the source of truth: each event is
fsynced before the in-memory state changes, and reopening replays it. A
dependency addition is journaled too.

### DAG

A task becomes `ready` only when every dependency is `done`. Cycle detection is
depth-first and reports the full loop; a rejected edge is not applied. Plan
seeding builds the whole graph first and seeds nothing if the plan is cyclic.

### Claims and fencing

A claim carries owner, generation, TTL, and a fence. One task has one claim.
Expiry returns the task to `ready`; the generation keeps increasing, so a stale
claim cannot complete the task (`zero.fs.stale`). Completion records evidence.

### Limits and fairness

Per-project running concurrency is bounded. Ready tasks are ordered by priority
then creation sequence, and the claim rotation starts at the next project so one
project cannot starve another. The 200-task fixture dispatches every task exactly
once inside the limits.

### User queue

A blocked-on-user task moves to `waiting_input` and pushes a durable item onto
the headless user queue. Blocked-on-dependency tasks go to `blocked` and keep no
worker. Independent work continues.

### Plan seeding

Approving a plan seeds its tasks exactly once. A second approval returns the
same task ids, and the progress view is derived from the same store.

## Todo store

Todos are separate from tasks and carry: id, title, notes, state (`open`,
`doing`, `blocked`, `done`, `dropped`), priority, due date, tags, linked task
ids, evidence, scope, creator, and version.

- Project and session scopes have a merged, ordered view with no duplicates.
- Every mutation is versioned and journaled; replay reconstructs the store.
- The agent may not complete or drop a user-created todo without confirmation
  (`zero.todo.confirmation`) or an explicit auto rule.
- Linking is explicit, and completing a todo never changes a task (nor the
  reverse).
- Stale detection is due-date based; the daily review lists stale and due-soon
  items.

### Capture

`TodoCapture` is keyboard-only: characters build a title, Enter creates, Tab
cycles All/Open/Done/Stale, `/` toggles search, arrows move, toggle selects,
select-all and bulk complete act on the selection, and review returns stale
items. There is no mouse path by construction.

## Agent tool

`TodoTool::call` accepts `add`, `list`, `update`, `complete`, `block`, and `drop`
as versioned operations and goes through the same ownership rule.
