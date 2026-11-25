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

## Prompts (SEC-05, partial)

`request_secret` is the only constructor and marks the prompt host-issued; the
agent has no route to it. `render_masked` renders the tag, a masked entry, and
the reason for TUI, desktop, web, and Android surfaces. The surface widgets are
not wired to this model yet.

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

## Sign-in flows (SEC-11, partial)

`SignInFlow` records the provider, method, whether the flow is documented for
third-party clients, and the date it was checked. An undocumented flow is
disabled with the reason and the date; a documented flow stores tokens only in
the credential store. The live OpenCode Console OAuth and ChatGPT device flow
are not implemented.
