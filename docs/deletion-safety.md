# Deletion safety

Zero treats deletion as accidental-harm prevention, not defence against a
hostile local attacker (A6). Three layers:

1. **One guard, three command languages.** `zero_policy::delete` parses POSIX,
   PowerShell, and cmd commands, unwraps `sudo`, `env`, `nohup`, `nice`,
   `sh -c`, `bash -lc`, `cmd /c`, and PowerShell `-Command`, and blocks
   destructive commands and inline Python deletion calls. The destructive corpus
   has zero false allows.
2. **Shims.** Generated PATH shims (`rm`, `rmdir`, `unlink`, `shred`), PowerShell
   functions (`Remove-Item`, `del`, `erase`, `rd`, `rmdir`, `ri`, `rm`), and cmd
   `.bat` shims forward to `zero-guard`. This catches deletions from Makefiles,
   npm scripts, and CI. Evidence: a PowerShell shim blocks `Remove-Item`; the
   hosted Linux run blocks a Makefile `rm -rf` through the PATH shim.
3. **Python audit hook.** `python/zero_guard` raises `DeletionBlocked` for
   `os.remove`, `os.unlink`, `os.rmdir`, `os.removedirs`, `os.truncate`,
   `shutil.rmtree`, `Path.unlink`, `Path.rmdir`, and overwrite-by-move.

The only sanctioned deletion is the `trash` tool, which uses the OS facility
(Recycle Bin, `trashItemAtURL`, freedesktop trash). Every managed overwrite
snapshots prior bytes into the overwrite journal first, and undo restores them
byte-exactly.

## Protected paths

Refused with a reason: the home directory itself, filesystem roots, system
directories, any `.git`, any `.zero`, Zero's own data and config roots, the audit
log, journals, the credential store, and policy/trust files.

## Purge

Permanent deletion is human-only: a dry-run plan, an exact plan digest, the
literal phrase `PURGE`, and an audit record. The agent has no action class for
purge, no route to the confirmation function, and cannot construct the token.

## Retention

Zero's garbage collection examines only its own data root, never follows
symlinks, refuses canonical paths outside the root, and moves expired files to
the trash. It is the only exemption from protected-path refusal, and it is
logged.

## Limits (stated honestly, DEL-11, DEL-12)

- Native extensions, `ctypes` calls, and absolute-path binaries can evade the
  Python audit hook and the command parser. The overwrite journal and the OS
  trash are the backstop; the guard is not a sandbox.
- Third-party processes Zero did not launch are outside the guard entirely.
- A shell command is "read-only" only when the parser can prove it; otherwise it
  is treated as mutating.
- Approvals bind the exact command bytes; an edited command needs a new approval.
