# Credentials

## Store

`zero_secrets::EncryptedStore` is the fallback when no OS keychain is available:
AES-256-GCM over a JSON payload with a random 256-bit data key. The data key is
wrapped either by Argon2id from a passphrase or by a machine-bound key file
(mode 0600) for unattended daemon start. The envelope records the KDF, salt,
wrapped key, and data nonce; no plaintext secret is ever written. A wrong
passphrase or a tampered ciphertext fails with `zero.tru.tamper`.

The `Keychain` trait is the OS-store seam (get/set/delete); an in-memory backend
is used by tests. Real Windows Credential Manager, macOS Keychain, and libsecret
adapters are not yet implemented — that task is open.

## Accounts

Named accounts are independent per provider: `set`, `get`, `accounts`, `active`,
`switch`, `rename`, `sign_out`, and `set_active_secret`. Switching keeps every
token; sign-out removes only the named account.

## Children and refresh

`scrubbed_env` removes credential-bearing variables (KEY, TOKEN, SECRET,
PASSWORD, CREDENTIAL) from a child environment, keeping `PATH` and the SSH/GPG
agent sockets. `RefreshLock` is a cross-process `create_new` lock, so one
refresher wins and the loser proceeds without refreshing.

## Import

`import_plaintext` reads an explicit JSON map (`provider/account` → value),
stores each value encrypted, and moves the old file to the OS trash.
