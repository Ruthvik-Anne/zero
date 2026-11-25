# M2 evidence

Commands were run from the repository root on 2026-11-25. Windows is the host;
Linux-only tests were run in WSL Ubuntu (`CARGO_TARGET_DIR=/tmp/zero-target`).
Per-task mapping is the M2 closure table in [`tasks.md`](../tasks.md).

## Aggregate

```text
$ cargo test --workspace
223 passed, 0 failed

$ cargo clippy --workspace --all-targets -- -D warnings
Finished (no warnings)

$ cargo run -p xtask -- check-docs
traceability: 478 requirements, 276 tasks, 38 areas — OK
architecture: 24 crates, 23 edges — OK
```

### Linux (WSL Ubuntu)

```text
$ cd /mnt/c/Users/ruthvikanne/Code/zero
$ CARGO_TARGET_DIR=/tmp/zero-target cargo test -p zero-policy -p zero-fs
zero-fs:  17 passed
zero-policy: 44 passed
python_guard: 1 passed   (10 deletion calls raise DeletionBlocked)
shims_unix:  1 passed    (Makefile `rm -rf` blocked by the PATH shim)
sandbox_linux: 1 passed  (Landlock denies writes, reads succeed)
```

### Windows sandbox prototype

```text
$ cargo test -p zero-policy --test sandbox_windows
windows_job_object_prototype_confines_a_child ... ok
```

## Highlights

- The matrix is 75 cells checked against golden rows; plan denies writes,
  deletes, mutating shell, installs, and mode changes.
- The evaluator is the only permit issuer. `Permit` fields are private and the
  tool registry exposes `call_with_permit`; a permit is bound to one action hash.
  The bypass suite covers tool dispatch, kernel writes, self-escalation,
  protected policy files, subagent escalation, untrusted projects, and headless
  irreversible work.
- A mode change mid-batch re-evaluates pending calls and leaves the running call
  to finish with its result reported; every decision records the policy version.
- Approvals bind the exact action hash and an expiry; a mutated command is
  refused, the first decision wins, and the decision is durable.
- Deletion: 33 destructive cases across three shells have zero false allows;
  wrappers are unwrapped up to depth 4; Python raises `DeletionBlocked` for all
  ten listed calls; PowerShell and Makefile shims both block.
- File safety: native trash with read-only, open-file, symlink, long-path, and
  cross-device fixtures; byte-exact overwrite undo; plan-bound human purge with
  an audit row; retention only inside the Zero data root.
- Trust: hooks, monitors, MCP servers, skills, instructions, and `.halcyon-mode`
  are inert until explicit trust, and revocation is durable.
- Audit: hash-chained; editing a payload or deleting a middle record is detected
  at the broken link, and a tampered log refuses to open.
- Sandbox: Windows job object (64 MiB cap, kill-on-close) and Linux Landlock
  (writes denied, reads allowed) both pass in their native environments.

## Platform portability defects found and fixed during M2

The Linux run exposed that protected-path classification used the host's path
rules, so Windows-style fixture paths did not classify on Linux. Classification
is now parameterized by the target platform: Windows and Unix paths are split,
normalized, and compared explicitly, independent of the host. The cross-platform
tests run on both operating systems.
