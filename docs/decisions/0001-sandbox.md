# 0001 — Sandbox prototype for the kernel and shell

Status: **accepted for the spike; optional hardening, not a guard replacement.**
Date: 2026-11-25. Requirements: TRU-03, TRU-06.

## Question

Which OS primitive confines Zero's kernel and shell, and what does a working
prototype prove?

## Options

| Option | Platform | Confines | Gap |
|---|---|---|---|
| Landlock | Linux ≥5.13 | filesystem writes, some IPC | no network; ABI-dependent |
| seccomp-bpf | Linux | syscalls | allowlists are brittle for Python |
| Job object | Windows | memory, CPU, process count, kill-on-close | no filesystem confinement |
| AppContainer | Windows | filesystem, network, capabilities | COM/ACL setup; heavier |

## Decision

- **Linux:** Landlock for filesystem writes, with seccomp as a later second
  layer. The probe applies a ruleset that handles write/create/delete access and
  adds no allow rules, then proves a write fails while a read succeeds.
- **Windows:** job objects for resource limits and lifecycle (the prototype sets
  a 64 MiB process-memory cap and kill-on-close and terminates the job), with
  AppContainer as the file/network confinement target. AppContainer is not
  prototyped here because it requires capability SIDs and ACLs on every target
  path; that work belongs with the kernel bootstrap (M4).
- The sandbox is **optional and additive**. The evaluator, deletion guard, trash,
  and audit remain the enforcement; the sandbox is defence in depth.

## Prototypes

| Prototype | Code | Evidence |
|---|---|---|
| Windows job object | `zero_policy::sandbox::windows::prototype` | `cargo test -p zero-policy --test sandbox_windows` — child assigned to a job with a 64 MiB cap and kill-on-close, then terminated |
| Linux Landlock | `zero_policy::sandbox::linux::confine_writes`, `zero-sandbox-probe` | `cargo test -p zero-policy --test sandbox_linux` — writes denied, reads succeed; skipped with ABI reason if the kernel lacks Landlock |

The Linux test runs in hosted CI on `ubuntu-latest`; the Windows test runs on
both Windows targets.

## Consequences

- The kernel bootstrap must detect the platform primitive and degrade with an
  explicit state when it is unavailable; it must never claim confinement that is
  not applied.
- Resource limits from job objects are independent of the `Governor` accounting
  in `zero-types`; both are kept.
- Sandbox failures fail closed for the affected feature but do not replace the
  policy verdict.
