# M9 evidence

M9 covers the desktop/web/Android surfaces and multimodal/computer-use work.
All tasks are implemented; the closing hosted run is recorded at the end.

## Multimodal (`zero-mm`)

| Task | Evidence |
|---|---|
| T-MM-01 Inputs and blocks | `cargo test -p zero-mm`: 27 route fixtures, typed blocks, `@file/@image/@url/@name`, per-modality accounting (30 tests). |
| T-MM-02 Preprocessing | Content-addressed originals + verified `read_full`, deterministic downscale/tile/audio/video plans, injectable processors (52 tests). |
| T-MM-03 Sandboxed computer use | Exact host:port allowlist, no host mounts/device access; host-path/network/device/mount/clipboard escapes blocked and recorded (90 tests). |
| T-MM-04 Live computer use | Risk matrix; manual asks every live action incl. screenshots; plan denies; destructive always asks (73 tests). |
| T-MM-05 Recordings | Labeled BLAKE3 screenshots, chapters, assertions, shortcut flags; passing and failing flows publish artifacts + failure ids (60 tests). |
| T-MM-06 Local CPU models | Consent prompt with licence/disk/memory/purpose; decline leaves the modality unavailable with an explanation (40 tests). |

## Desktop and web (`zero-daemon-app`)

| Task | Evidence |
|---|---|
| T-WEBUI-01 Web app | Loopback-only bind validation, single-use expiring token, inline page/actions JSON, origin rules (19 tests). |
| T-DSK-01 Desktop shell | System-only webview (bundled refused), loopback bind, shared action registry, token-free launch line (38 tests). |
| T-DSK-02 Shared UI states | One palette/mode/approval/secret model rendered per surface; scripted TUI-vs-JSON parity (28 tests). |

## Android

| Task | Evidence |
|---|---|
| T-AND-01 Pairing | QR/short-code offer, single-use device-bound pairing, biometric gate; a stolen code cannot pair (52 tests). |
| T-AND-02 Session control | Mesh seam; full list/open/transcript/prompt/steer/queue/diff/cancel flow with cursor/error handling (64 tests). |
| T-AND-03 Approvals and secrets | Digest/nonce/device-bound approvals, replay rejection, locked view hiding, FLAG_SECURE (`cargo test -p zero-policy mobile_approval`, 15 tests). |
| T-AND-04 Notifications and offline | Persisted offline queue, exactly-once flush after airplane mode, cursor reconnect, redacted notifications (`cargo test -p zero-agent mobile_offline`, 18 tests). |
| T-AND-05 Share and resources | Share intake/sheet, direct/relay reporting, no VPN change, scripted session delivery (`cargo test -p zero-daemon-app share`, 20 matches). |

## Still open

None for M9. Non-Kotlin host-side policy is implemented; the Android app UI
(Kotlin, `BiometricPrompt`, FGS/UnifiedPush, Intent decoding, mesh client
implementation) remains platform application work, documented in
`docs/android.md`.

## Hosted run

Run [45722626227](https://github.com/Ruthvik-Anne/zero/actions/runs/45722626227)
on `1801d291`: **all 12 jobs successful**, including all six Rust targets, both
keychain jobs, both installer jobs, protocol readers, and docs.
