# Secrets vault

## Format (SEC-01, SEC-02)

`Vault` stores AES-256-GCM ciphertext in `index.json`; the index carries only
tag, scope, project binding, nonce, ciphertext, and timestamps. AAD binds the
tag, scope, and project, so editing any of them in the index fails with
`zero.tru.tamper`. Scope precedence is project > session > user; a binding for a
different project is drift and is refused (`zero.pol.denied`); expired bindings
fail with `zero.pol.approval_expired`. Rotation re-encrypts the value.

## Placeholders and substitution (SEC-03, SEC-04)

`{{secret:TAG}}` and `Secret("TAG")` are parsed into handles. `SecretHandle` has
no display of the value; its `redacted()` form is `[secret:TAG]`. `substitute`
returns the value only for header, query, stdin, and env/SDK destinations; the
chat destination always returns the redacted handle. Values therefore never
enter the transcript, receipts, files, logs, or the kernel.

## Prompts (SEC-05)

`request_secret` is the only constructor and marks the prompt host-issued; the
agent has no route to it. One `SecretPrompt` renders through `view()` as a
`SecretPromptView` carrying the prompt id, tag, reason, and a masked field of
bullets (`•`), never a value or any part of one. `zero-daemon-app` renders the
TUI surface through the host modal (`SecretPromptFrame::Tui`); desktop, web, and
Android consume the masked controller payload (`SecretPromptFrame::Controller`).
Only the TUI widget exists in-tree; the other clients consume the host payload.
A forged or deserialized prompt is refused with `zero.pol.denied`, and agent text
cannot open the modal.

## Audit and `.env` (SEC-06, SEC-07)

Audit rows record the tag and destination, never a value. `.env` must be
git-ignored when a repository exists; `.env.example` is created; the pre-commit
guard refuses a staged line with a value of eight or more characters.

## Scan and rotate (SEC-08)

`scan_file` and `scan_git_history` (`git log -p --all`) report credential-shaped
findings by file and line without echoing the value. `rotation_offer` returns one
entry per affected file, and `Vault::rotate` re-encrypts the current value.

## Leakage suite (SEC-09)

`assert_no_leak` checks transcript, kernel, config, logs, teleport bundle, and
crash reports for a value and fails naming the leaking sink.

## Headless queue (SEC-10)

`request_secret_headless` pushes a `Credential` item onto the durable policy
queue and returns its id, so independent work continues while the user is asked.

## Sign-in flows (SEC-11)

Two real flows ship. OpenCode Console uses device authorization against
`{server}/auth/device/code` and `{server}/auth/device/token` for the
`opencode-cli` client; `poll_device_token` handles `authorization_pending`,
`slow_down`, and expiry. ChatGPT uses system-browser OAuth 2.0 with PKCE S256 on
a `127.0.0.1` loopback callback, the
`https://auth.openai.com/api/accounts/authorize` and
`/api/accounts/oauth/token` endpoints, the `dynamic_agent_client` registration
(the first sign-in receives an issued client id on the callback), the
`https://api.openai.com/v1` resource, the `chatgpt.tokens.use.direct` scope, and
`ext_agent_host_id`. A callback with a wrong `state` is refused.

`TermsRegistry` records what each provider documents for third-party clients and
is consulted before any network request: `DeviceSignIn::begin` checks the device
method and `ChatGptSignIn::begin` checks OAuth, so an undocumented provider fails
with `zero.fnd.unavailable` and no request is sent. opencode and chatgpt are
enabled; claude and github-copilot are disabled with the reason and the check
date 2026-11-24. Tokens are written to the encrypted credential store by
`store_tokens`, reloaded by `load_tokens`, and rotated by `refresh`; they never
enter config. Tests use loopback listeners and scripted transports, so no live
provider credentials are needed in CI.
