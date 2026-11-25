# M4 evidence (in progress)

M4 is not closed. This page records the completed task groups so far.

## File manager — T-FS-01..T-FS-08 (done)

| Task | Evidence |
|---|---|
| T-FS-01 | `manager::tests::a_handle_records_hash_size_mtime_id_encoding_and_lines`; stale write refused with `zero.fs.stale` and the external bytes preserved. |
| T-FS-02 | `manager::tests::atomic_writes_preserve_bytes_mode_and_symlinks`: UTF-8 BOM, UTF-16LE BOM, CRLF/LF, binary, executable mode, symlink write-through, read-only refusal. Temp + fsync + atomic replace (`MoveFileExW` on Windows). |
| T-FS-03 | `locks::tests`: two claimants conflict; tree covers descendants not siblings; hardlinks share a resource; an expired holder is fenced out (`zero.fs.stale`). |
| T-FS-04 | `batch::tests`: a failing op restores every file; dry-run changes nothing; success commits (removal via trash); recovery rolls back a `begin` journal. |
| T-FS-05 | `overlay::tests`: disjoint edits merge, same-line edits conflict at the precise line, one-sided changes are taken, creation collisions conflict. |
| T-FS-06 | `identity::tests`: hardlinks and symlinks share an id; NFC/case spellings agree; Windows volume+index and Unix dev+ino. |
| T-FS-07 | `manager::tests::the_watcher_reports_external_changes`; the stale-write test is the bash-edit conflict case. |
| T-FS-08 | Lock expiry + fencing (`locks`), journal replay (`batch::recover`), deletes routed to trash (`manager::delete`). |

## Edit tool — T-EDT-01..T-EDT-06 (done)

| Task | Evidence |
|---|---|
| T-EDT-01 | `edit::tests::every_text_operation_has_a_fixture`: replace, insert, delete, wrap, move, copy, write, patch; rename is a file-level op with its own test. |
| T-EDT-02 | `a_drifted_anchor_refuses_instead_of_editing`: text and line-hash anchors fail closed with `zero.edt.anchor_drift`. |
| T-EDT-03 | `receipts_are_bounded_and_never_echo_the_file`: ≤3 context lines, <1 KiB, no body echoed. |
| T-EDT-04 | `a_fifty_file_batch_undoes_byte_exactly`: 50 files restored, manifest removed so undo cannot replay. |
| T-EDT-05 | `range_edits_on_a_one_gigabyte_file_are_o_edits`: 100 edits read 0 base bytes; the line index is lazy and cached; save is exact. |
| T-EDT-06 | `deleting_files_is_refused_with_a_task_suggestion`: `zero.del.blocked` with the trash suggestion. |

## Still open in M4

T-TSK-01..07, T-TODO-01..04, T-LCK-01..04, T-SCH-01..07, T-TOOL-01..06,
T-KRN-01..05, T-AUT-01..04. No M4 task outside FS/EDT is marked done.

## Commands

```text
cargo test -p zero-fs             44 passed
cargo clippy --workspace --all-targets -- -D warnings   clean
cargo run -p xtask -- check-docs  OK
```

Hosted matrix run [45538950771](https://github.com/Ruthvik-Anne/zero/actions/runs/45538950771)
on `ci/m0-m1-verification` (`49ef2a6e`): all eight jobs successful, including the
1 GiB range-edit test on Linux, macOS, and Windows, and the trash/atomic-write
fixtures on every platform. A CI-only gap was caught here: six new error codes
were not yet in `docs/errors.md`; the generated page is now committed and the
`error::tests::documented_codes_match_the_enum_exactly` gate passes.
