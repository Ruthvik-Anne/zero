# Kernel

## Jupyter client (`zero_kernel::jupyter`)

A real `ipykernel` child is started with a generated connection file (five free
ports, HMAC-SHA256 key). The client speaks the Jupyter wire format:

```
[identities…] <IDS|MSG> signature header parent metadata content [buffers…]
```

- Signing covers the four JSON frames; verification rejects a tampered frame with
  `zero.tru.tamper`.
- Shell uses a DEALER socket; iopub uses a SUB socket subscribed to all topics.
- Execution sends `execute_request`, collects iopub `stream`,
  `execute_result`/`display_data`, and `error` messages until `status: idle`, then
  reads the shell `execute_reply`.
- Output is capped (default 1 MiB; overflow appends a truncation marker).
- A duration timeout kills the kernel, records the cell in `last_lost`, and
  returns the partial output; the next call restarts and rehydrates.

## Restart and rehydrate (KRN-03)

Successful cell code is kept in the session history. `restart` (and the implicit
restart before a call after a timeout) starts a fresh kernel on the same
connection and replays the history; the in-flight lost cell is reported, not
replayed. `execute_after_restart` reports how many cells were replayed.

## Host requests (KRN-02)

`KernelHost` performs reads, writes, deletes, and shell commands only through
`zero_policy` host requests. Plan mode denies writes, deletes, and shell before
the effect runs; there is no ambient authority in the kernel bridge.

## Limits (KRN-04)

- Output cap per execution.
- Duration timeout with partial output.
- A preloaded subprocess guard allows at most eight concurrent children;
  a spawn flood hits `PermissionError` and the kernel stays usable.
- Memory/CPU/disk accounting belongs to `zero_types::limits` and the OS sandbox
  spike; the kernel does not claim more than it enforces.

## Preload and persistence (KRN-05)

The bootstrap defines the `zero` namespace (`trash`, `web_search`,
`tool_search` adapters) that raise a typed permission error until a host bridge is
installed. `%cd` persists across cells; `%%bash` runs in its own process, so its
exports do not leak into Python (checked on Unix in CI).
