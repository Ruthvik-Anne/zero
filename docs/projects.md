# Projects

## Identity

A project is a random key in `.zero/key`. `projectId = blake3(key)`. Paths are
bindings in a per-user registry, not identity: moving the folder keeps the key
and the project; copying the folder gives a new key and a `copiedFrom` link.

## Creation and root detection

`find_root` walks from the working directory to the nearest `.zero`, else the
nearest git root, else the working directory, stopping at home or the filesystem
root. First use creates `.zero/`, a key, `project.json`, the layout, and appends
`.zero/` to `.gitignore` when a repository exists (the edit is reported).
Names come from the directory with a numeric suffix on collision.

## Moves and copies

- One key at one live path is the normal case.
- If the registered path no longer exists, the move rebinds silently.
- If the same key is live at two paths, an interactive open returns a copy prompt
  with a prefilled name; non-interactive runs use that name. Answering mints a new
  key, updates `project.json` with `copiedFrom`, and leaves the original
  untouched.
- A path whose stored binding names a different project returns `KeyReplaced`;
  adopt keeps the new identity (history file preserved), restore rewrites the
  previous key when a backup exists. Nothing is discarded silently.

## Layout and migration

`.zero/` holds `project.json`, `key`, `config`, `plan`, `tasks`, `todos`,
`journal/`, `artifacts/`, `vault/`, and `audits/`. A legacy `.pi/key` migrates
once (key copied, `.pi` archived, logged); a keyless `.zero` gets a minted key
and a log line. A second open does not migrate again.

## Sharing and recovery

`/link` is a user-only action (`project.link`, `agent_invocable: false`) and is
never offered in the copy prompt. Recovery actions (`init`, `list`, `show`,
`bind`, `move`, `rekey`, `forget`) are likewise user-only.

## Mesh

`BindingRegistry::merge_remote` replicates project identity and name; each device
keeps its own local path binding, so the same key is the same project at whatever
path each device uses.
