# Locks and pools

## Banker's pools (`zero_sched::banker`)

Bounded countable pools: kernel, provider, transfer, subagent, browser, desktop.
Each worker declares maxima before dispatch. A request is granted only when a
safe completion sequence exists for every declared worker — the simulated
completion is deterministic and costs at most `workers × pools` steps. A grant is
atomic across every pool in the request; a partial grant cannot occur.

- A request above the worker's remaining maximum aborts with
  `zero.lck.maxima` (never silently clamps).
- An unsafe request waits; waiting requests age and are promoted oldest/highest
  priority first when safe.
- Preemption is only allowed at a safe boundary; the victim's fence advances, so
  its stale grant is rejected with `zero.fs.stale`.
- A worker that cannot declare maxima is reported as degraded with the reason,
  and uses ordered acquisition with a hard timeout instead (below).

## File strategy (`zero_fs::locks`)

Files use canonical-order acquisition, never declared maxima:

- `canonical_order` sorts by the resolved identity path, so two callers listing
  the same files in any order acquire in the same order.
- Wound-wait: a higher-priority requester preempts a lower-priority holder; an
  equal or higher priority holder (or a protected critical section) makes the
  request wait with `Locked` or `Timeout`. The caller retries; no thread blocks
  inside the manager.
- A failed batch releases everything acquired so far, preserving all-or-nothing.
- Timeouts are deadlines: an expired wait is `zero.fnd.timeout`.
- Optimistic versions are the file manager's stale-handle rejection; isolated
  workspaces are the copy-on-write overlays.

The 10,000-interleaving simulation runs four workers with random priorities and
file orders; every ordering completes without a deadlock.

## Ownership (`zero_sched::election`)

Each resource has one owner: a stable hash over the sorted membership, or an
explicit handoff override. A handoff increments the generation and fence;
the old lease is rejected as stale. A minority partition (`reachable × 2 ≤
members`) denies new leases with `zero.lck.no_quorum`; existing leases remain
readable but no new ownership is granted.

## Degraded status

`Banker::degraded_workers()` returns `(worker, reason)` pairs for status display.
The reason names the fallback: ordered acquisition with timeouts.
`acquire_ordered` sorts the requested resources, grants all-or-none, and fails
with `Locked` or `Timeout`; a bounded worker cannot use this path.
