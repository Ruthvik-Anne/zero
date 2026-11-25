# M5 evidence

M5 covers projects, credentials, and secrets. The project, credential, and
secrets slices are implemented; two secrets tasks are explicitly partial (see
the status column), and the tables below name the exact test for each closed
task.

## Projects — T-PRJ-01..06 (done)

| Task | Evidence |
|---|---|
| T-PRJ-01 | `project::tests::creation_names_the_project_and_writes_the_layout_and_gitignore`: key file, `projectId = hash(key)`, layout, gitignore edit. |
| T-PRJ-02 | Same test plus duplicate-name suffix; `find_root` prefers `.zero`, then git, then the working directory. |
| T-PRJ-03 | `moving_a_project_keeps_identity_and_rebinds_silently`, `a_copy_prompts_once_and_gets_a_new_key_with_copied_from`; non-interactive copy uses the prefilled name; original key/history untouched. |
| T-PRJ-04 | `a_replaced_key_asks_and_can_be_adopted_or_restored` (adopt); `recovery_actions_are_user_only_and_link_is_absent_from_the_prompt`. |
| T-PRJ-05 | `legacy_layouts_migrate_once_and_are_logged`: `.pi` key migration, archive, log, idempotent second open. |
| T-PRJ-06 | `mesh_bindings_share_one_identity_at_different_paths`: replicated identity, independent local paths. |

Hosted run [45552439438](https://github.com/Ruthvik-Anne/zero/actions/runs/45552439438)
on `f176c8f1`: all jobs successful.

## Credentials — T-CRT-01..06 (done)

| Task | Evidence |
|---|---|
| T-CRT-01 | `keychain::tests::native_store_round_trips_on_windows_and_linux` writes, reads, and deletes a real credential through Windows Credential Manager / Secret Service. Dedicated CI jobs set `ZERO_REQUIRE_KEYCHAIN=1` so the native path cannot silently skip; Linux runs under `dbus-run-session` with an unlocked `gnome-keyring`. |
| T-CRT-02 | `credentials::tests::the_no_keychain_store_never_writes_a_plaintext_secret`: AES-256-GCM with a wrapped key; Argon2id passphrase mode; wrong passphrase and tampering fail with `zero.tru.tamper`. |
| T-CRT-03 | `accounts_are_independent_and_switchable`: two accounts, switch, rename, sign-out; switching keeps both tokens. |
| T-CRT-04 | `child_env_is_scrubbed_and_one_refresher_wins`: no credential variables in a child environment; exactly one refresher wins the cross-process lock. |
| T-CRT-05 | `plaintext_import_stores_values_and_trashes_the_old_file`; redaction coverage lives in the log/redaction suite. |
| T-CRT-06 | Machine-bound key file (mode 0600) reopens unattended without a passphrase; TPM/DPAPI is the documented next backend. |

Platform coverage for T-CRT-01:

| OS | Backend | Test |
|---|---|---|
| Windows | Credential Manager | native round trip, required locally and in CI |
| Linux | Secret Service (pure-Rust zbus) | native round trip under gnome-keyring, required in CI; falls back to the encrypted file when no Secret Service exists |
| macOS | Keychain Services | compiled on the macOS matrix targets; the native test skips because hosted runners can raise a prompt |

Hosted run [45553755580](https://github.com/Ruthvik-Anne/zero/actions/runs/45553755580)
on `6a154c75`: all jobs successful.

## Secrets — T-SEC-01..11

| Task | Status | Evidence |
|---|---|---|
| T-SEC-01 | done | `vault::tests::the_index_has_no_values_and_aad_tampering_is_detected`: index without values, AAD tamper fails. |
| T-SEC-02 | done | `scopes_precedence_binding_drift_and_expiry`: project > session > user, drift refused, expiry. |
| T-SEC-03 | done | `placeholders_resolve_only_in_transport_and_chat_is_redacted`: parser plus value-free handle. |
| T-SEC-04 | done | Same test: only header/query/stdin/env destinations receive values; chat is redacted. |
| T-SEC-05 | doing | `flows::tests::secret_prompts_are_host_issued_and_masked`: one host-issued request model with per-surface masked rendering. The TUI/desktop/web/android widgets are not wired to it yet. |
| T-SEC-06 | done | `audit_rows_and_env_rules_carry_no_values`: audit rows carry tags and destinations only. |
| T-SEC-07 | done | Same test: `.env` must be ignored, `.env.example` is created, and the pre-commit guard refuses value lines. |
| T-SEC-08 | done | `flows::tests::scanning_finds_keys_in_files_and_git_history_with_a_rotation_offer`: file scan, `git log -p` scan, and one rotation offer per file; `Vault::rotate` re-encrypts. |
| T-SEC-09 | done | `leakage_suite_covers_every_sink`: transcript, kernel, config, logs, teleport, crash. |
| T-SEC-10 | done | `flows::tests::the_headless_queue_queues_a_secret_and_work_continues`: a credential request lands in the durable headless queue and other work continues. |
| T-SEC-11 | doing | `flows::tests::an_undocumented_sign_in_flow_is_disabled_with_the_reason`: documented/undocumented gates, tokens land only in the credential store. Live OpenCode Console OAuth and ChatGPT device flow are not implemented. |

Hosted run [45555110780](https://github.com/Ruthvik-Anne/zero/actions/runs/45555110780)
on `7008692b`: all jobs successful.

## Still open

- T-SEC-05 UI wiring on each surface.
- T-SEC-11 live OAuth/device flows.
- TPM/DPAPI unattended key wrapping (T-CRT-06 currently uses a machine-bound key file).
