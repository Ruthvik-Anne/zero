---
name: vault
description: Discover which credential names are already stored in this project's local vault. Use before asking the user for a secret you might already have, or to check what a placeholder token's name refers to.
---

# Vault

The credential vault stores secrets the user types in response to an
`ask_user.ask(type="credential", ...)` prompt (see the ask-user skill). The
plaintext never reaches you — you only ever see an opaque
`zero-cred://<name>/<hex>` placeholder token, and only immediately after the
user answers that prompt. This skill lets you check which credential *names*
already exist, so you don't ask for one twice.

```python
result = await vault.list()
result["names"]  # e.g. ["stripe_api_key", "db_password"]
```

## API

- `await vault.list()` — returns `{"names": [str, ...]}`. Names only — never
  values, never placeholder tokens.

## Rules

- There is no way to fetch a credential's value or placeholder from here.
  A placeholder token is only ever handed to you as the direct return value
  of the `ask_user.ask` call that just stored it.
- Use a placeholder token exactly as returned — pass it as-is into a `bash`
  command or `ipython` cell (e.g. as part of a header value or environment
  variable). The host resolves it to the real secret immediately before the
  command actually runs; it is never resolved anywhere you can observe.
- A token only resolves for the credential name it was issued for, and only
  within the session that issued it. Don't construct or guess a token string
  yourself — it won't work, and the command will just see the literal
  placeholder text.

## Output scrubbing is best-effort, not a guarantee

The host also tries to catch a resolved secret if it gets echoed back into a
command's OWN output (e.g. printed, or a variable that already holds the real
value getting interpolated into a later `rlm.run` call) and replace it with
its placeholder before it reaches you or gets persisted. This is
**exact-substring matching only**: it cannot catch a secret that's been
transformed first — base64/hex-encoded, reversed, split across multiple
writes, re-cased, etc. Never assume a value is safe to transform, log, or
pass along just because it came from a placeholder token — treat any value
that traces back to a credential as sensitive for the rest of the session.
