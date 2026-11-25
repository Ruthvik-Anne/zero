# Credentials

## Backend selection

`KeychainChoice::select(data_dir)` probes the platform store and picks a backend:

| OS | Backend | Notes |
|---|---|---|
| Windows | Windows Credential Manager | native, no daemon |
| macOS | Keychain Services | native; may prompt in a headless session |
| Linux / other Unix | Secret Service over D-Bus | pure-Rust `zbus` client via `keyring` 4; needs a session bus and a provider such as gnome-keyring |
| anything unavailable | AES-256-GCM encrypted file | headless hosts; machine-bound key file for unattended start |

The probe writes, reads, and deletes a credential under a unique account name,
so an initialized-but-unusable store (locked keyring, missing D-Bus name) is
treated as unavailable rather than failing later.

`keyring` 4.2 requires Rust 1.88; the workspace MSRV was raised from 1.85 to
1.88 for it.

## Platform tests

`cargo test -p zero-secrets keychain::` runs four tests:

- `native_store_round_trips_on_windows_and_linux` — a real `set`/`get`/`delete`
  through Credential Manager or Secret Service. It skips only when the store is
  genuinely absent, unless `ZERO_REQUIRE_KEYCHAIN=1`, which turns absence into a
  failure.
- `selection_falls_back_to_the_encrypted_file` — forced fallback, no plaintext
  on disk, machine-bound envelope.
- `encrypted_keychain_persists_across_reopen` — passphrase file round trip.
- `the_choice_routes_each_operation_to_its_backend` — routing through the enum.

CI has a dedicated `keychain` job on `windows-latest` and `ubuntu-latest` with
`ZERO_REQUIRE_KEYCHAIN=1`. The Linux job installs `gnome-keyring` and runs under
`dbus-run-session` with an unlocked login keyring, then checks `secret-tool`
before the test, so the Secret Service path is exercised for real instead of
being skipped. The six-target matrix still compiles every platform; macOS skips
the native test because hosted runners can raise a Keychain prompt.

## Encrypted fallback

`EncryptedStore` is AES-256-GCM over a JSON payload with a random 256-bit data
key. The data key is wrapped by Argon2id from a passphrase, or by a machine-bound
key file (mode 0600) for unattended daemon start. The envelope records the KDF,
salt, wrapped key, and data nonce; no plaintext secret is ever written. A wrong
passphrase or a tampered ciphertext fails with `zero.tru.tamper`.

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

## Open

TPM/DPAPI-scoped key wrapping is not implemented; unattended unlock uses the
machine-bound key file described above.
