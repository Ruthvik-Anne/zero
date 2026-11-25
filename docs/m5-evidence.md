# M5 evidence (in progress)

Only the project group is closed so far.

## Projects — T-PRJ-01..06 (done)

| Task | Evidence |
|---|---|
| T-PRJ-01 | `project::tests::creation_names_the_project_and_writes_the_layout_and_gitignore`: key file, `projectId = hash(key)`, layout, gitignore edit. |
| T-PRJ-02 | Same test plus duplicate-name suffix; `find_root` prefers `.zero`, then git, then the working directory. |
| T-PRJ-03 | `moving_a_project_keeps_identity_and_rebinds_silently`, `a_copy_prompts_once_and_gets_a_new_key_with_copied_from`; non-interactive copy uses the prefilled name; original key/history untouched. |
| T-PRJ-04 | `a_replaced_key_asks_and_can_be_adopted_or_restored` (adopt); `recovery_actions_are_user_only_and_link_is_absent_from_the_prompt`. |
| T-PRJ-05 | `legacy_layouts_migrate_once_and_are_logged`: `.pi` key migration, archive, log, idempotent second open. |
| T-PRJ-06 | `mesh_bindings_share_one_identity_at_different_paths`: replicated identity, independent local paths. |

## Still open in M5

T-CRT-01..06, T-SEC-01..11.
