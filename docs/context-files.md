# Context files

`zero-agent::context` loads exactly one project instruction file per session.

## Precedence

1. Walk from the project root down to the working directory.
2. In a directory, `AGENTS.md` wins; `CLAUDE.md` in the same directory is skipped.
3. The nearest instruction file wins: a nested `AGENTS.md` or `CLAUDE.md`
   replaces the root file for work under that subtree.
4. If the working directory is outside the project root, only that directory is
   consulted.

The result is one file, not a concatenation. `tests` cover a root `AGENTS.md`
against a same-directory `CLAUDE.md`, a nested `AGENTS.md`, a nested
`CLAUDE.md`, and a nested directory with no instruction file.

## Size caps

| Cap | Value | Behaviour |
|---|---|---|
| Per file | 32 KiB | Truncated on a UTF-8 character boundary, then `[context file truncated at 32 KiB]`. |
| Bundle | 128 KiB | Further files are truncated to the remaining room; the marker is added. |

Truncation never splits a multi-byte character; the test writes `é` repeated and
asserts the result is still valid UTF-8 at a character boundary.

## Trust

File content is project data, not instructions from the user. It is framed with
`zero_types::UNTRUSTED_CONTENT_BANNER` when inserted into a prompt, and an
untrusted project's file is not loaded at all (TRU-02, M2).
