# Scheduler

## MLFQ (`zero_sched::mlfq`)

Classes are interactive, background, and batch. Every job records class, project,
priority, estimate, and submission time. Selection:

1. highest effective priority (`priority + age / aging_ms`);
2. ties cycle classes round-robin from the last class served;
3. within a class, shortest estimated task first;
4. ties go to the project with the lowest served/weight, then arrival order.

Aging is tested under a continuous high-priority flood: a low-priority job is
served within ten ticks. Weighted fair share is tested with a 3:1 weight.
Interactive jobs preempt background work at the next selection, never inside a
running call.

## Admission (`zero_sched::admission`)

Per-provider and per-model concurrency plus per-credential token buckets. A full
destination returns `Deferred { reason, retry_at }`; queues stay bounded. A 429
with `Retry-After` zeroes the bucket and blocks that credential until the reset.
Credentials are keyed and never rotated to evade a limit.

## Budgets (`zero_sched::budget`)

Cost is predicted and reserved before dispatch against session, project, and
daily limits. Over-budget work is deferred with the reason and reserves nothing.
Reconciliation replaces the reservation with the measured cost; an 80% warning is
reported.

## Backoff and breakers (`zero_sched::backoff`)

Exponential backoff with deterministic jitter and a retry cap. A circuit breaker
per provider opens after its threshold and half-opens after the cooldown; another
provider is unaffected.

## Usage windows (`zero_sched::usage`)

A window has capacity, used count, and a reset time. Exhausting it pauses work
with a reset time; the scheduled resume reports capacity after the reset and does
not replay effects.

## Durable queue (`zero_sched::queue`)

Calls are enqueued idempotently by key and claimed with a generation. The claim is
journaled before dispatch. After a restart, in-flight calls become `uncertain`
and are never dispatched again; the kill-test proves one dispatch per call across
a hard kill.
