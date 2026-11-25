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

## Audit and `.env` (SEC-06, SEC-07)

Audit rows record the tag and destination, never a value. `.env` must be
git-ignored when a repository exists; `.env.example` is created; the pre-commit
guard refuses a staged line with a value of eight or more characters.

## Leakage suite (SEC-09)

`assert_no_leak` checks transcript, kernel, config, logs, teleport bundle, and
crash reports for a value and fails naming the leaking sink.

## Open

The host prompt model across all surfaces (SEC-05), git-history scan (SEC-08),
headless secret queue (SEC-10), and the sign-in/terms flows (SEC-11) remain open.
