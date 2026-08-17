> Zero can help you create resource packages. Ask it to bundle your extensions, skills, prompt templates, or themes.

# Zero Packages

Zero packages bundle extensions, skills, prompt templates, and themes so you can share them through npm or git. For compatibility with the inherited extension ecosystem, a package declares resources in `package.json` under the `pi` key, or uses conventional directories.

## Table of Contents

- [Install and Manage](#install-and-manage)
- [Package Sources](#package-sources)
- [Creating a Zero Package](#creating-a-zero-package)
- [Package Structure](#package-structure)
- [Dependencies](#dependencies)
- [Package Filtering](#package-filtering)
- [Enable and Disable Resources](#enable-and-disable-resources)
- [Scope and Deduplication](#scope-and-deduplication)

## Install and Manage

> **Security:** Zero packages run with full system access. Extensions execute arbitrary code, and skills can instruct the model to perform any action including running executables. Review source code before installing third-party packages.

```bash
zero package install npm:@foo/bar@1.0.0
zero package install git:github.com/user/repo@v1
zero package install https://github.com/user/repo  # raw URLs work too
zero package install /absolute/path/to/package
zero package install ./relative/path/to/package

zero package remove npm:@foo/bar
zero package list                  # show installed packages from settings
zero package update                # update all non-pinned packages
zero package update npm:@foo/bar   # update one package
zero update                        # update Zero
zero update --force                # reinstall Zero even if current
```

By default, `package install` and `package remove` write to global settings (`~/.zero/agent/settings.json`). Use `--local` to write to project settings (`.zero/agent/settings.json`) instead. Project settings can be shared with your team, and Zero installs any missing packages automatically on startup.

To try a package without installing it, use `--extension` or `-e`. This installs to a temporary directory for the current run only:

```bash
zero -e npm:@foo/bar
zero -e git:github.com/user/repo
```

## Package Sources

Zero accepts three source types in settings and `zero package install`.

### npm

```
npm:@scope/pkg@1.2.3
npm:pkg
```

- Versioned specs are pinned and skipped by `zero package update`.
- Global installs use `npm install -g`.
- Project installs go under `.zero/agent/npm/`.
- Set `npmCommand` in `settings.json` to pin npm package lookup and install operations to a specific wrapper command such as `mise` or `asdf`.

Example:

```json
{
  "npmCommand": ["mise", "exec", "node@20", "--", "npm"]
}
```

### git

```
git:github.com/user/repo@v1
git:git@github.com:user/repo@v1
https://github.com/user/repo@v1
ssh://git@github.com/user/repo@v1
```

- Without `git:` prefix, only protocol URLs are accepted (`https://`, `http://`, `ssh://`, `git://`).
- With `git:` prefix, shorthand formats are accepted, including `github.com/user/repo` and `git@github.com:user/repo`.
- HTTPS and SSH URLs are both supported.
- SSH URLs use your configured SSH keys automatically (respects `~/.ssh/config`).
- For non-interactive runs (for example CI), you can set `GIT_TERMINAL_PROMPT=0` to disable credential prompts and set `GIT_SSH_COMMAND` (for example `ssh -o BatchMode=yes -o ConnectTimeout=5`) to fail fast.
- Refs pin the package and skip `zero package update`.
- Cloned to `~/.zero/agent/git/<host>/<path>` (global) or `.zero/agent/git/<host>/<path>` (project).
- Runs `npm install` after clone or pull if `package.json` exists.

**SSH examples:**
```bash
# git@host:path shorthand (requires git: prefix)
zero package install git:git@github.com:user/repo

# ssh:// protocol format
zero package install ssh://git@github.com/user/repo

# With version ref
zero package install git:git@github.com:user/repo@v1.0.0
```

### Local Paths

```
/absolute/path/to/package
./relative/path/to/package
```

Local paths point to files or directories on disk and are added to settings without copying. Relative paths are resolved against the settings file they appear in. If the path is a file, it loads as a single extension. If it is a directory, Zero loads resources using package rules.

## Creating a Zero Package

Add a `pi` manifest to `package.json` or use conventional directories. Include the `pi-package` keyword for discoverability.

```json
{
  "name": "my-package",
  "keywords": ["pi-package"],
  "pi": {
    "extensions": ["./extensions"],
    "skills": ["./skills"],
    "prompts": ["./prompts"],
    "themes": ["./themes"]
  }
}
```

Paths are relative to the package root. Arrays support glob patterns and `!exclusions`.

### Gallery Metadata

The inherited `pi-package` keyword and optional `video` or `image` fields remain available as package metadata:

```json
{
  "name": "my-package",
  "keywords": ["pi-package"],
  "pi": {
    "extensions": ["./extensions"],
    "video": "https://example.com/demo.mp4",
    "image": "https://example.com/screenshot.png"
  }
}
```

- **video**: URL for an MP4 preview.
- **image**: URL for a PNG, JPEG, GIF, or WebP preview.

If both are set, video takes precedence.

## Package Structure

### Convention Directories

If no `pi` manifest is present, Zero auto-discovers resources from these directories:

- `extensions/` loads `.ts` and `.js` files
- `skills/` recursively finds `SKILL.md` folders and loads top-level `.md` files as skills
- `prompts/` loads `.md` files
- `themes/` loads `.json` files

## Dependencies

Third party runtime dependencies belong in `dependencies` in `package.json`. Dependencies that do not register extensions, skills, prompt templates, or themes also belong in `dependencies`. When Zero installs a package from npm or git, it runs `npm install`, so those dependencies are installed automatically.

Zero bundles core packages for extensions and skills. If you import any of them, list them in `peerDependencies` with a `"*"` range and do not bundle them: `@zero-agent/ai`, `@zero-agent/agent-core`, `@zero-agent/coding-agent`, `@zero-agent/tui`, `typebox`.

Other resource packages must be bundled in your tarball. Add them to `dependencies` and `bundledDependencies`, then reference their resources through `node_modules/` paths. Zero loads packages with separate module roots, so separate installs do not collide or share modules.

Example:

```json
{
  "dependencies": {
    "shitty-extensions": "^1.0.1"
  },
  "bundledDependencies": ["shitty-extensions"],
  "pi": {
    "extensions": ["extensions", "node_modules/shitty-extensions/extensions"],
    "skills": ["skills", "node_modules/shitty-extensions/skills"]
  }
}
```

## Package Filtering

Filter what a package loads using the object form in settings:

```json
{
  "packages": [
    "npm:simple-pkg",
    {
      "source": "npm:my-package",
      "extensions": ["extensions/*.ts", "!extensions/legacy.ts"],
      "skills": [],
      "prompts": ["prompts/review.md"],
      "themes": ["+themes/legacy.json"]
    }
  ]
}
```

`+path` and `-path` are exact paths relative to the package root.

- Omit a key to load all of that type.
- Use `[]` to load none of that type.
- `!pattern` excludes matches.
- `+path` force-includes an exact path.
- `-path` force-excludes an exact path.
- Filters layer on top of the manifest. They narrow down what is already allowed.

## Enable and Disable Resources

Use `zero config` to enable or disable extensions, skills, prompt templates, and themes from installed packages and local directories. This works for both global (`~/.zero/agent`) and project (`.zero/agent/`) scopes.

## Scope and Deduplication

Packages can appear in both global and project settings. If the same package appears in both, the project entry wins. Identity is determined by:

- npm: package name
- git: repository URL without ref
- local: resolved absolute path
