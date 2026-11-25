# M10 evidence

M10 is release hardening: installers, observability, test gates, performance
budgets, documentation, and the parity audit. All tasks are implemented; the
closing hosted run is recorded at the end.

## Install and packaging (`zero-cli`)

| Task | Evidence |
|---|---|
| T-INST-01 Packaging | Signed release manifest + SBOM, six-target naming, embedded-key verification, strict JSON (10 tests). |
| T-INST-02 Windows installer | PowerShell 5.1 non-admin installer: checksum-first, lock/stale recovery, staged rename, user PATH only; local end-to-end 39 assertions; `installer (windows)` CI job. |
| T-INST-03 Unix installer | POSIX `sh` installer: non-admin prefix, checksum, PID lock, atomic install, traps, one-time PATH append; WSL end-to-end; `installer (unix)` CI jobs on ubuntu + macOS. |
| T-INST-04 Update and rollback | Signed/hash-verified update, atomic per-file swap, health check, byte-for-byte rollback (17 tests). |
| T-INST-05 Service units | systemd/Windows/launchd rendering + validation; scripted start/stop/status lifecycle (19 tests). |
| T-INST-06 Kernel bootstrap | Checksummed cache/offline bootstrap, tamper refusal, idempotent install, probe (16 tests). |
| T-INST-07 Uninstall | Scoped plan, fingerprinted confirmation TTL, service+PATH cleanup, trash data, orphan check (9 tests). |

## Observability (`zero-store`, `zero-fs`)

| Task | Evidence |
|---|---|
| T-OBS-01 Metrics | Closed metric set, bucket percentiles, bounded labels, dashboard, atomic snapshot (12 tests). |
| T-OBS-02 Tracing | Validated span tree; scripted turn covers provider/tool/frame; append-only JSONL and deterministic render (12 tests). |
| T-OBS-03 Retention | Age/quota sweep through `TrashService`, keep_min, dry-run/idempotence, protected paths (14 tests). |

## Test, performance, docs, parity

| Task | Evidence |
|---|---|
| T-TST-05 Network impairment | Seeded loss/latency/partition scenarios through the resilience layer; NAT matrix external gate (15 tests). |
| T-TST-06 Fault injection | One fault per stable code (75/75); check-bound fixtures; inject/triage/playbook assertions (5 tests). |
| T-TST-07 Security suites | 7 prompt-injection fixtures with unchanged policy; 5-sink leakage redaction; external SSRF/zip-slip gate (12 tests). |
| T-TST-08 Conformance gate | Both MCP revisions (13 exchanges) + protocol goldens (8 frames, `.bin` siblings); typed gate (8 tests). |
| T-PERF-01 Performance budgets | Five dimensions (startup/frame/attach/memory/session size), recorded and enforced by `bench --check` (9 tests). |
| T-DOCS-01 Documentation set | Install/configure/troubleshooting pages + repaired index; link and docs tests pass; stubs marked planned. |
| T-PAR-03 Parity audit | 133 Part 1/2/8 items assessed (31 implemented, 61 partial, 40 deferred, 1 out-of-scope, 0 unassessed); `xtask check-parity` in CI. |

## Still open

None for M10. Follow-ups documented: archive build/upload + real release key
replacement, host installer wiring for `zero install/update/uninstall`, and
OS-level installer VM matrices beyond the current CI jobs.

## Hosted run

Run [45722626227](https://github.com/Ruthvik-Anne/zero/actions/runs/45722626227)
on `1801d291`: **all 13 jobs successful**, including `installer (windows)` and
`installer (unix)` on ubuntu and macOS, both keychain jobs, six Rust targets,
protocol readers, and the docs/traceability job.
