# Autonomy

## Goals (AUT-01)

A goal stores its objective, state (`active`, `paused`, `cleared`), token, step,
and time accounting. It is written as a session `state` entry (`autonomy.goal`),
which compaction retains; `load_goal` reads the latest value from the visible
transcript, so a goal and its accounting survive compaction, resume, and reopen.

## Heartbeats (AUT-02)

User and agent heartbeats have an interval and next time. `pause` stops due
ticks, `resume` restarts from now, and `tick` coalesces a long gap into one
heartbeat.

## Schedules (AUT-03)

One-off and five-field cron schedules (minute, hour, day, month, weekday; `*`,
numbers, ranges, lists, `*/n`). A due tick is claimed with owner and generation;
a second claim is refused. Missed intervals coalesce into the stored due tick,
and completion schedules the next tick after now rather than replaying the
missed ones.

## Limits and cancellation (AUT-04)

Token, step, and wall-time limits are checked on every accounted step; the first
exceeded limit returns `zero.fnd.limit_exceeded` with the kind in the message and
the run stops. `CancelScope` cancels recursively: cancelling a parent cancels
children and grandchildren sharing its registry.
