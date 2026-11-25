# Monitors

`zero-agent::monitor` is the monitor engine (MON-06, MON-11, MON-13, MON-14;
T-MON-02) and `zero-agent::monitor_defs` is the declarative layer (MON-07,
MON-08, MON-09, MON-10; T-MON-03). A monitor is a long-running child process
whose stdout is streamed as events and whose stderr goes only to logs.

A monitor event is a distinct type from a background-task event, an MCP task, or
an MCP event; [`MonitorEvent`] carries `monitor_id` and never shares a queue with
those sources. The engine owns no timer and no ambient runtime: the caller
starts it, drains it, and stops it.

## Engine model

| Call | Effect |
|---|---|
| `MonitorEngine::start(spec, now_ms)` | Spawns the child, starts the stdout and stderr readers, returns a `MonitorHandle { id, status, pid }`. Duplicate ids are refused. |
| `drain(now_ms)` | Polls every child, flushes coalesced stdout bursts, and returns at most `max_events_per_drain` events. `now_ms` stamps events and drives the optional timeout. |
| `stop(id, now_ms)` | Kills and reaps the child, joins the readers, discards buffered stdout, and marks the monitor `Stopped`. Idempotent. |
| `mute(id, true/false)` | Stops or resumes stdout events without touching the child (MON-14). |
| `status(id)` / `handle(id)` / `stats(id)` | Current state, handle, and counters. |

Statuses are `Starting`, `Running`, `Stopped`, and `Failed`. `start` spawns
synchronously, so it returns a handle in `Running`; `Starting` exists for the
declarative surface. A natural exit is `Stopped` on success and `Failed` on a
non-zero exit. A timeout is `Failed` with `stats.timed_out`.

## Spec and no shell by default

```text
MonitorSpec {
  id, name, command,
  args: Vec<String>,
  cwd: Option<PathBuf>,
  env: BTreeMap<String, String>,
  description: Option<String>,
  max_output_bytes: Option<usize>,
}
```

`command` is an executable and `args` is passed verbatim. The engine never wraps
the command in `sh -c`, `cmd /c`, or PowerShell. A caller that needs a shell must
name it explicitly, so every metacharacter stays visible to the policy layer.
Stdin is null; stdout and stderr are piped. `max_output_bytes` is an optional
per-monitor override of the engine's per-line cap; `None` uses
`with_line_cap`.

## Event and coalescing rules

stdout lines are buffered per monitor and emitted as one `MonitorEvent` when any
of these is true:

1. the burst window (`BurstWindow.window_ms`, default 250 ms) has elapsed since
   the first buffered line arrived;
2. the buffer reached `max_lines` (default 64);
3. the buffer reached `max_bytes` (default 16 KiB);
4. the stdout reader reached EOF, or the monitor is `Stopped`/`Failed`.

A burst of 100 short lines in a few milliseconds is therefore emitted as one or
two events, not 100; with `max_lines` above 100 it is exactly one. A monitor
that prints nothing produces no event at all, so idle noise costs no tokens
(MON-13).

Rules and edges:

- Lines are emitted in arrival order. A line is popped once and never returned
  by a second `drain`.
- A burst larger than `max_lines` or `max_bytes` is split: one event carries up
  to the cap, the rest stays buffered, and `truncated` is true. No line is
  dropped for reaching a burst cap.
- A single line longer than `max_bytes` is still emitted alone, so the event
  always makes progress.
- `truncated` also covers a line cut at the per-line cap.
- `line_count` is the number of lines in this event (`lines.len()`).
- The window is measured on a monotonic clock from the first buffered line; it
  does not depend on `drain` being called at a particular time. `now_ms` is the
  caller's clock for `at_ms` and for the optional timeout.
- `drain` returns at most `max_events_per_drain` events (default 16). Further
  ready events stay buffered for the next call; the per-drain cap never drops a
  line.
- A monitor may be muted; its stdout is still read and discarded (so the child
  cannot block on a full pipe) and counted in `stats.dropped_on_mute`.

## stderr and logs

stderr is never an event. A reader applies the same per-line cap, then pushes the
line into a bounded queue (`with_stderr_queue`, default 256 lines) whose writer
thread calls the `LogSink`.

- When the sink is slower than the child, the queue drops its oldest line and
  increments `stats.stderr_dropped`. The engine never blocks on the sink.
- `MemoryLogSink` is the default bounded in-memory sink (256 lines). It also
  drops its oldest line and counts the drop (`MemoryLogSink::dropped`).
- Closing the engine sets the queue closed and wakes the writer. A writer already
  blocked inside a stalled sink is detached, not joined: `stop` must not wait on
  a slow sink.
- No redaction happens here. Production passes the FND-07 redacting logger as
  the sink; monitors only cap and count.

## Environment scrubbing

A child inherits the parent environment merged with `spec.env`, then scrubbed.
Names containing `KEY`, `TOKEN`, `SECRET`, `PASSWORD`, or `CREDENTIAL` are
removed, except `SSH_AUTH_SOCK` and `GPG_AGENT_INFO`. The match is on the
uppercased substring, so `MONKEY` is removed too.

The policy is duplicated locally from `zero-secrets::scrubbed_env` because
`zero-agent` sits above `zero-secrets` in the dependency graph and must not
depend upward on it (CRT-04). Keep the two marker lists in sync.

## Declarative monitors

A plugin or project can declare monitors as data. `load_manifest` validates a
JSON document into a `MonitorRegistry`; `start_for` starts the definitions that
match a trigger through the engine. Declarations are untrusted input: every
definition passes `check` before anything is spawned.

### Schema

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

| Field | Required | Meaning |
|---|---|---|
| `schema_version` | no (default 1) | Only `1` is accepted; anything else is `SchemaVersion`. |
| `name` | yes | Unique, case-insensitive monitor name; also the engine id. |
| `command` | yes | Executable, never a shell string. |
| `args` | no | Passed verbatim. |
| `description` | yes | Non-empty human-readable purpose. |
| `when` | yes | `manual`, `session_start`, or `skill:<name>`. |
| `source` | no | Defaults to `{"kind":"script"}`. |
| `requires_shell` | no (default false) | Declares that the command is a shell or needs one. |
| `max_output_bytes` | no | Per-line output cap; may not exceed the policy cap. |

Unknown JSON fields at either level are ignored, so a newer producer can add a
field without breaking an older reader. Bounds are applied before validation:
`MonitorManifestLimits { max_bytes, max_monitors }` (defaults 256 KiB and 64).
Errors are typed: `Serialization` for malformed JSON, `SchemaVersion` for an
unsupported version, `LimitExceeded` for a bound, `AlreadyExists` for a
duplicate name, `ConfigInvalid` for a semantic failure.

### Triggers (MON-08)

| `when` | Starts on |
|---|---|
| `manual` | An explicit `start_for(MonitorWhenKey::Manual, ...)`. |
| `session_start` | `start_for(MonitorWhenKey::SessionStart, ...)` when a session opens. |
| `skill:<name>` | `start_for(MonitorWhenKey::SkillInvoke("<name>"), ...)`; names compare ignoring ASCII case. |

`MonitorRegistry::for_trigger` returns the matching definitions in manifest
order. `start_for` is idempotent while a monitor with the same name is running:
a second trigger reports `AlreadyExists` in `skipped` and starts nothing. A
name the engine still retains as `Stopped`/`Failed` is also skipped; restarting
after an exit requires confirmation (T-MON-04). `stop_all(engine)` stops every
monitor with the session and is idempotent.

`start_for_report` returns `MonitorTriggerReport { started, skipped }`. A
definition refused by policy, already running, or failing to spawn is recorded
as a typed `MonitorRefusal { name, code, message }`; it never aborts the rest of
the trigger. `start_for` returns just the handles.

### Sources (MON-07)

| Kind | Target | Semantics |
|---|---|---|
| `script` | none | A long-running or self-terminating command. |
| `log_tail` (`log`) | absolute file path | The command tails that file. |
| `directory_watch` (`directory`) | absolute directory path | The command watches that directory. |
| `ci_poll` (`ci`) | `http`/`https` URL | The command polls a CI or PR endpoint. |
| `websocket` (`ws`, `web_socket`) | `wss` URL | The command consumes a WebSocket feed. |

The command is the implementation for every source, so a plugin can bring its
own watcher. The validated target is passed to the child as
`ZERO_MONITOR_SOURCE_TARGET` and the kind as `ZERO_MONITOR_SOURCE_KIND`. The
engine embeds no `tail`, directory watcher, HTTP client, or WebSocket client and
never polls on its own. Declaring a source never grants a capability: the
policy below decides whether the target is reachable.

### Policy and allowlists (MON-10)

`MonitorPolicy` is deny-by-default:

```text
MonitorPolicy {
  allowed_commands: Vec<String>,   // default: empty (denies every command)
  allow_shell: bool,               // default: false
  allow_network: bool,             // default: false
  max_output_bytes: usize,         // default: 8 KiB; zero is invalid
  allow_local_targets: bool,       // default: false
  allowed_roots: Vec<PathBuf>,     // default: empty
}
```

`check(definition, policy)` runs before any spawn:

- **Command.** The command basename must appear in `allowed_commands`; an empty
  allowlist denies everything. A definition with `requires_shell` is refused
  unless `allow_shell` is true. The engine still never invokes a shell unless
  the definition names one as its command.
- **Network.** `ci_poll` and `websocket` sources need `allow_network`. Schemes
  are `http`/`https` for polling and `wss` for WebSocket; `ws` is refused.
  Embedded userinfo (`https://user:token@host`) is refused. Loopback, private,
  link-local, shared/CGNAT, unspecified, this-network, broadcast, IPv6
  loopback/unspecified/link-local/unique-local, and cloud metadata destinations
  are refused: IP literals are parsed (including `[::1]`, bare decimal, and
  hex IPv4), and the obvious names `localhost`, `*.localhost`, `*.local`,
  `metadata.google.internal`, and `instance-data*` are refused.
- **Local targets.** `log_tail` and `directory_watch` need
  `allow_local_targets`, an absolute path, and a path inside one of
  `allowed_roots`. Relative paths, Windows UNC paths, and `//`-rooted paths are
  refused. When both the target and root exist, canonical paths must also agree,
  so a symlink cannot escape a root; parents that climb above a root are
  refused lexically.
- **Output.** The effective cap is the definition's `max_output_bytes` or
  `policy.max_output_bytes`, and it is written into the engine spec. A
  definition declaring more than the policy allows is refused with
  `LimitExceeded`, never silently truncated. The engine's per-line cap then
  applies the value to stdout and stderr.

Policy limitations: the policy is a capability check, not an OS sandbox.
`allowed_commands` matches the command basename exactly (case-sensitive on
every platform, so a differently-cased Windows path is refused rather than
admitted). The policy performs no DNS resolution, so a public name that resolves
to a private address is not detected; it does not inspect a shell command's
contents; it does not create a process group, filesystem namespace, or network
namespace; and two checks are not atomic with a later spawn (a path can change
between `check` and `start`). Keep local roots narrow and prefer commands that
make only their own outbound connections.

## Lifecycle, timeout, and mute

- **Stop.** `stop` calls `kill`, waits (`reap`), joins both readers, and drops
  the pending stdout with a counted `dropped_on_stop`. Nothing is emitted after
  an explicit stop, including a final buffer.
- **Timeout.** `with_timeout_ms(Some(ms))` measures the caller's `now_ms` from
  `start`. When the budget is reached, the child is killed and reaped, marked
  `Failed` with `timed_out`, and its final buffered lines are emitted once.
- **Natural exit.** The child is reaped by `try_wait`. Success marks `Stopped`
  and a non-zero or signal exit marks `Failed`; the final buffer is emitted once.
- **Mute.** Muting clears the current buffer into `dropped_on_mute`, drops all
  later stdout, and leaves stderr flowing to the log sink. The process keeps
  running. Unmuting resumes events from the next line.
- **Drop.** Dropping the engine stops every monitor the same way as `stop`, so a
  test cannot leave a child behind.

## Restart policy (MON-12, MON-11; T-MON-04)

A monitor that was running when a session paused, teleported, or the daemon
restarted is **not** restarted on its own. `zero-agent::monitor_restart`
separates the durable record from the decision: `plan_restart` (the `plan`
function) decides, and `apply_restart` (the `apply` function) starts only the
confirmed decisions.

### Journal

`MonitorJournal { schema_version, records }` is written as JSON to a caller-
chosen path. `MonitorJournal::load` treats a missing file as an empty journal and
rejects malformed JSON (`Serialization`), a future `schema_version`
(`SchemaVersion`), and a record that is not a monitor (`ConfigInvalid`, MON-11).
`save` writes a sibling `*.json.tmp`, syncs it, and renames it over the journal,
so a crash never leaves a partial document. Records are bounded by
`DEFAULT_JOURNAL_MAX_RECORDS` (128); the oldest are dropped first.

```text
MonitorRecord {
  kind,                    // only Monitor belongs here (MON-11)
  name,
  status,                  // Starting | Running | Stopped | Failed
  was_running,             // live when the record was written
  stopped_by_user,         // permanent veto
  started_at_ms,
  stopped_at_ms: Option<i64>,
  session_id,
}
```

| Helper | Written when | `was_running` | `stopped_by_user` |
|---|---|---|---|
| `record_start(name, session, at)` | A start (first start or a confirmed restart) | true | false |
| `record_session_stop(name, at)` | A session closes a running monitor (MON-08) | true | false |
| `record_stop(name, at)` | The user stops the monitor | false | true |
| `record_exit(name, status, at)` | The child exits or fails | false | false |

A record's **boundary** is `stopped_at_ms` when present, otherwise
`started_at_ms`. A confirmation must be strictly newer than the boundary.

### Decisions

`plan_restart(records, cause, confirmations, now_ms, max_confirmation_age_ms)`
returns `RestartPlan { decisions, to_restart, skipped }`. A record is a candidate
only when `was_running` is true and its status is `Starting`, `Running`, or
`Stopped`. `Failed` is never a candidate, even with a confirmation: retrying a
failed child is an explicit start, not a resume.

**The default is Skip.** A candidate still restarts only when a matching
`RestartRequest { monitor, cause, user_confirmed, confirmation_at_ms }` exists.
No cause implicitly restarts; `ResumeCause::restarts_implicitly()` is always
false.

| Condition | Result |
|---|---|
| `was_running == false` | Skip: not running when the journal was written |
| `stopped_by_user == true` | Skip: stopped by the user (outranks any confirmation) |
| status `Failed` | Skip: a failed monitor needs an explicit start |
| no confirmation for this monitor | Skip: `no confirmation` |
| `user_confirmed == false` | Skip: confirmation was not explicit |
| cause differs from the resume cause | Skip: confirmation was for a different cause |
| `confirmation_at_ms` is `None` | Skip: confirmation has no timestamp |
| `confirmation_at_ms > now_ms` | Skip: confirmation is newer than now |
| `now_ms - confirmation_at_ms > max_confirmation_age_ms` | Skip: confirmation is stale |
| `confirmation_at_ms <= boundary` | Skip: confirmation predates the stop/resume boundary |
| all of the above pass | `Restart` |

`SessionResume`, `Teleport`, and `DaemonRestart` use the same row: teleport never
restarts without confirmation (MON-12). A confirmation for another monitor, or
for another cause, never applies. An old confirmation cannot be reused after a
newer stop because it is no longer newer than the boundary, and it also ages out
of `max_confirmation_age_ms`.

MCP tasks and MCP events are not monitors (MON-11). A journal containing one is
refused on load/save, and `plan` drops such a record before making any decision,
so it never appears in `decisions`, `to_restart`, or `skipped`.

### Apply and report

`apply_restart(plan, engine, definitions, journal, now_ms)` starts only
`RestartDecision::Restart` entries. `definitions` are already-built
`MonitorSpec` values (expand an admitted `MonitorDefinition` with `to_spec`
under your `MonitorPolicy`), so a restart never widens a policy. A name the
engine still retains after an exit is released with `MonitorEngine::forget`
only here, as part of a confirmed restart; a monitor that is already live is
reported as `AlreadyExists` instead of being started twice. Each successful
start is written back with the record's `session_id`, so the next resume sees it
as running.

`RestartReport { restarted, skipped, failed }` mirrors the plan's skips and
reports a start that failed (for example a missing executable as `Unavailable`)
once. A failed start is never retried silently, and it is not journaled as
running.

## Caps

| Cap | Default | Behaviour |
|---|---|---|
| Per line | 8 KiB (`DEFAULT_LINE_CAP_BYTES`) | Cut on a character boundary, then ` ...[truncated]`. stderr gets the same cap. A monitor may override it with `MonitorSpec.max_output_bytes`. |
| Per burst lines | 64 | Split; the remainder stays buffered; `truncated` is set. |
| Per burst bytes | 16 KiB | Same split rule; one line is always emitted. |
| Per drain events | 16 | Extra ready events stay buffered. |
| stdout queue | 4,096 lines | Drop oldest, counted in `dropped_stdout`. |
| stderr queue | 256 lines | Drop oldest, counted in `stderr_dropped`. |
| Memory log tail | 256 lines | Drop oldest, counted by `MemoryLogSink::dropped`. |

Counters are exposed by `stats(id)`: `stdout_lines`, `stderr_lines`,
`truncated_lines`, `dropped_stdout`, `dropped_on_mute`, `dropped_on_stop`,
`split_bursts`, `stderr_dropped`, `pending_lines`, and `buffered_bytes`.

## Windows child-process caveats

- `kill` is `TerminateProcess`; only the direct child is killed. There is no
  process group, so a monitor that spawns grandchildren can outlive `stop`.
- `.cmd` and `.bat` are not executables to `CreateProcess`; pass `cmd` with
  `/c` explicitly, and accept that the shell is then visible to policy.
- After the child is reaped its pid may be reused by another process; the engine
  only reports the pid while the child is live.
- Pipes are anonymous `Stdio::piped` handles; there is no pty, so a monitor that
  expects a terminal should be run with an explicit pty helper instead.

## Test evidence

Command (run from the repository root):

```text
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-agent monitor -j 1
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-agent --all-targets -j 1 -- -D warnings
```

The engine suite has 15 tests: 5 unit tests in `monitor::tests` and 10 in
`tests/monitors.rs`. The integration tests spawn the test binary itself as the
child with `ZERO_MONITOR_HELPER=1`; the helper test is a no-op otherwise.

T-MON-03 adds 17 tests in `monitor_defs::tests`, so `cargo test -p zero-agent monitor`
runs 32 tests (22 unit and 10 integration). T-MON-04 adds 18 tests in
`monitor_restart::tests`, so the same command now runs 50 tests (40 unit and 10
integration). The declarative start tests spawn the same test binary with
`--exact monitor_defs::tests::monitor_defs_helper_process`; that helper is a
no-op unless `--exact` is present, so the default suite does not spawn a child.
The restart tests use `--exact monitor_restart::tests::monitor_restart_helper_process`
with the same no-op guard.

| Test | Proves |
|---|---|
| `monitor_defs::tests::monitor_defs_helper_process` | The child side; a no-op unless spawned with `--exact`. |
| `monitor_helper_process` | The child side; a no-op unless `ZERO_MONITOR_HELPER=1`. |
| `monitor_defs::tests::manifest_parses_and_ignores_unknown_fields` | Unknown manifest and definition fields are ignored; defaults and sources parse. |
| `monitor_defs::tests::manifest_rejects_duplicate_names_ignoring_case` | `Deploy` and `deploy` collide (`AlreadyExists`). |
| `monitor_defs::tests::manifest_reports_malformed_json_with_a_typed_error` | Bad JSON is `Serialization`; a future schema is `SchemaVersion`. |
| `monitor_defs::tests::manifest_rejects_empty_command_description_and_when` | Empty command/description and an unknown `when` are typed errors. |
| `monitor_defs::tests::manifest_bounds_size_and_monitor_count` | Byte and count bounds are `LimitExceeded`. |
| `monitor_defs::tests::manifest_validates_local_paths_and_urls` | Relative and UNC paths are refused; `ws` is refused; an absolute path loads. |
| `monitor_defs::tests::load_file_reads_a_bounded_manifest` | `load_file` reads a file and enforces the size bound; a missing file is `NotFound`. |
| `monitor_defs::tests::for_trigger_matches_manual_session_and_skill_ignoring_case` | Exact trigger matching; skill names ignore ASCII case. |
| `monitor_defs::tests::skill_invoked_plugin_monitor_starts_only_for_that_skill` | **Done criterion:** a `when: skill:deploy` monitor starts on `DEPLOY` and not on `review`; a repeat trigger is idempotent; `stop_all` stops it. |
| `monitor_defs::tests::declarative_output_cap_reaches_the_engine` | A declared cap reaches the engine spec and truncates at that cap. |
| `monitor_defs::tests::policy_deny_defaults_refuse_commands_and_shells` | Empty allowlist denies; unlisted commands and unapproved shells are refused; basenames match. |
| `monitor_defs::tests::policy_refuses_private_metadata_and_insecure_urls` | Loopback/private/link-local/metadata/userinfo/insecure-scheme URLs are refused; public `https`/`wss` pass. |
| `monitor_defs::tests::policy_refuses_local_targets_outside_allowed_roots` | Local targets need the flag, an absolute path, and an allowed root. |
| `monitor_defs::tests::policy_refuses_a_definition_above_the_output_cap` | A declared cap above the policy is `LimitExceeded`; zero caps are invalid. |
| `monitor_defs::tests::a_refused_definition_is_reported_and_others_still_start` | A policy refusal is reported and the remaining definitions still start. |
| `monitor_defs::tests::stop_all_stops_every_monitor_and_is_idempotent` | `stop_all` stops every monitor, is repeatable, and a re-trigger is refused, not silently respawned. |
| `monitor_restart::tests::monitor_restart_helper_process` | The child side; a no-op unless spawned with `--exact`. |
| `monitor_restart::tests::journal_round_trips_atomically` | Records round-trip; `save` leaves no `.tmp`; a user stop and a start keep their boundary. |
| `monitor_restart::tests::journal_missing_file_loads_as_empty` | A missing journal is empty, not an error. |
| `monitor_restart::tests::journal_trims_to_its_bound` | The journal keeps at most 128 records and drops the oldest; the bound survives save/load. |
| `monitor_restart::tests::journal_rejects_corrupt_unsupported_and_non_monitor_records` | Bad JSON is `Serialization`, a future version is `SchemaVersion`, and an MCP task is `ConfigInvalid` on load/save (MON-11). |
| `monitor_restart::tests::running_monitor_without_a_confirmation_is_skipped` | **Done criterion:** a running monitor with no confirmation is skipped (`no confirmation`). |
| `monitor_restart::tests::a_fresh_confirmation_restarts_exactly_that_monitor` | One fresh confirmation restarts one monitor and no other. |
| `monitor_restart::tests::stale_wrong_monitor_and_out_of_order_confirmations_are_skipped` | Stale, future, boundary-predating, and ghost-token confirmations are skipped with reasons. |
| `monitor_restart::tests::a_confirmation_for_another_cause_is_skipped` | A confirmation given for a different resume cause does not apply. |
| `monitor_restart::tests::a_user_stop_is_never_restarted` | A user stop outranks a fresh confirmation. |
| `monitor_restart::tests::a_failed_monitor_is_not_restarted_even_with_a_confirmation` | `Failed` is never a candidate. |
| `monitor_restart::tests::a_monitor_that_was_not_running_is_not_a_candidate` | `was_running == false` is not restarted. |
| `monitor_restart::tests::teleport_follows_the_same_confirmation_rule` | Teleport skips without confirmation and restarts with one. |
| `monitor_restart::tests::non_monitor_kinds_never_appear_in_a_plan` | MCP task/event records are dropped from `decisions`, `to_restart`, and `skipped`. |
| `monitor_restart::tests::apply_starts_only_confirmed_monitors_and_journals` | `apply` starts the confirmed monitor, journals its new start with the session, and leaves the other stopped. |
| `monitor_restart::tests::two_monitors_with_one_confirmation_restart_only_one` | **Done criterion:** two monitors, one confirmation, only one restarts. |
| `monitor_restart::tests::a_failed_start_is_reported_and_not_retried` | A failed start lands in `failed` (`Unavailable`) and is not journaled as running. |
| `monitor_restart::tests::apply_does_not_start_a_live_monitor_twice` | A live monitor is reported as `AlreadyExists`; the engine still has one instance. |
| `monitor::tests::secret_variables_are_scrubbed_but_agent_sockets_are_kept` | Marker policy and the two exemptions. |
| `monitor::tests::memory_sink_drops_the_oldest_line_and_counts_it` | The default tail is bounded and counted. |
| `monitor::tests::truncation_never_splits_a_character` | A byte cap cuts a UTF-8 string on a boundary. |
| `monitor::tests::a_long_line_is_cut_at_the_cap_with_a_marker` | The per-line marker. |
| `monitor::tests::a_burst_window_always_makes_progress` | Zero caps are clamped. |
| `monitor_burst_of_one_hundred_lines_coalesces_without_loss` | 100 stdout lines in a few ms become fewer than 25 events, all 100 appear once in order, no stderr becomes an event, and 5 stderr lines reach the sink. |
| `monitor_environment_is_scrubbed_for_secret_markers` | `OPENAI_API_KEY` is absent in the child; `SSH_AUTH_SOCK` is kept. |
| `monitor_mute_drops_output_and_unmute_resumes` | A muted monitor emits nothing and keeps reading; unmute resumes; drops are counted. |
| `monitor_stop_kills_reaps_and_silences` | Stop reaps the child, reaches EOF, and no event follows. |
| `monitor_overlong_line_is_truncated_with_a_marker` | A 20 KB line is capped at 8 KiB with the marker. |
| `monitor_stalled_sink_drops_the_oldest_stderr_with_a_counter` | A stalled sink drops oldest stderr with a count; stderr stays out of events. |
| `monitor_per_drain_cap_keeps_the_rest_buffered` | Two events per drain, all 30 lines preserved in order. |
| `monitor_idle_emits_nothing` | A quiet monitor produces no events over a window (MON-13). |
| `monitor_timeout_kills_reaps_and_flushes_once` | The timeout marks `Failed`, flushes final stdout once, and repeats no line. |
