# Actions and keys

Every command, slash command, palette entry, and keybinding is one record in
`zero_actions::ActionRegistry`. The TUI, daemon app, desktop, web, Android, and
the agent all resolve the same record.

## Record

Required: `id` (`area.action`), `title`, `description`, `category`, `arguments`
(JSON Schema object), `mutating`, `deterministic`, `policy_class`, `approval`,
`agent_invocable`, `unattended`, `idempotency`, `audit`, `implicit`,
`ui_control`. A missing field fails registration.

## Forms

- `/id args` is the slash form.
- An implicit action is invoked by its id alone.
- Both build the same `ActionEvent` (action id, surface, actor, argument digest)
  and go through one handler.

`!command` is the shell prefix. It becomes a `shell.prefix` invocation, runs the
POSIX and (on Windows) PowerShell deletion guard, then policy, then the journal.
`!rm` is blocked with `zero.del.blocked`.

## Policy and idempotency

Execution needs a permit from `PolicyEngine`; an agent invocation is refused for
records with `agent_invocable: false`, and an unattended trigger is refused
unless `unattended: true`. Every mutating action journals `clientId + actionId +
argument digest` before dispatch; a replay returns the recorded result with one
effect. Audit rows carry actor, surface, argument digest, form, verdict, and
outcome, so a session's actions can be reconstructed.

## Extensions

Extension actions must be namespaced (`ext.<name>.<action>` or `ext:<name>.…`).
An extension claiming a core id fails with `zero.pol.denied`; an unnamespaced id
fails with `zero.fnd.invalid_input`.

## Keys

Defaults per surface: `Shift+Tab` cycles mode, `Ctrl+P` opens the palette, `F1`
shows help, `Ctrl+B` opens the daemon app. Binding a chord already owned by a
different action is a typed conflict; any action can be rebound and the old chord
is removed.

## Lint

`cargo run -p zero-actions --bin actions-lint` fails when an implicit action has
a UI control, an id is unnamespaced, or a record is incomplete. CI runs it.
