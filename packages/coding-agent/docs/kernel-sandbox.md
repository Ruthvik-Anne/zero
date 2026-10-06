# Enforced IPython kernel sandbox

All `KernelManager` launches require Linux bubblewrap and libseccomp. On Windows,
the native Node backend launches the Linux supervisor through `wsl.exe -d Ubuntu
--exec`; WSL alone is not the sandbox. Unsupported platforms or failed isolation
setup produce an error. There is no environment flag permitting an unsandboxed
kernel. The legacy forkserver is disabled, including direct `forkKernel` calls.

## Runtime configuration

- `ZERO_KERNEL_WSL_DISTRO`: WSL distribution used by a Windows backend; default `Ubuntu`.
- `ZERO_KERNEL_SANDBOX_PYTHON`: absolute Linux interpreter path, or a `~/` path in
  that distribution. Default `~/.local/share/zero/kernel-sandbox/bin/python`.
- `KernelManagerOptions.python` takes precedence. `ZERO_KERNEL_PYTHON` is also
  honored when the sandbox-specific setting is absent. Windows interpreters are
  rejected, never translated into an unsandboxed launch.
- `cwd` grants that workspace read/write access. Native drive paths are mapped to
	the selected distribution with `wslpath`; no `/mnt/<drive>` layout is assumed.
	UNC workspaces are rejected. Missing/unmounted drives fail with an actionable error.
- Explicit `KernelManagerOptions.env` entries are forwarded. The inherited host
	environment is not. Sandbox-owned `PATH`, `HOME`, `TMPDIR` and Python isolation
	settings cannot be overridden. Explicit RLM state-directory grants are mounted
	read/write; the broader agent/config directory is never inferred or mounted.

The trusted Linux runtime must contain `ipykernel`, `pyzmq`, `dill`, `zero-runtime`
and the Python skill packages needed by the session. On Linux, normal kernel
bootstrap and editable Python-skill synchronization run before sandbox launch;
trusted skill source directories are then mounted read-only. On Windows, the
configured WSL interpreter is validated for the runtime, default packages, and
requested skills before launch. The runtime must live outside the writable workspace.

For an existing user-level `uv` installation, provision inside WSL, without sudo:

```sh
~/.local/bin/uv venv ~/.local/share/zero/kernel-sandbox --python /usr/bin/python3
~/.local/bin/uv pip install --python ~/.local/share/zero/kernel-sandbox/bin/python \
  ipykernel pyzmq dill zero-runtime
```

Bubblewrap, libseccomp and functioning unprivileged namespaces are prerequisites.
Zero does not install privileged packages, change AppArmor/sysctl configuration,
or degrade to a plain WSL/native kernel when they are unavailable. The Windows
bootstrap selects a Linux runtime rather than building a Windows venv; the
bootstrap CLI verifies an actual isolated launch before reporting success.

## Boundary

Bubblewrap constructs a new mount root from read-only `/usr`, the selected venv
and its Python base runtime. It creates separate user, PID, IPC and network
namespaces, drops capabilities, sets no-new-privileges, and loads a mandatory
seccomp filter. The mount root is read-only; the granted workspace and private
in-memory `/home` and `/tmp` are writable. Host `/etc`, `/run`, other home files,
Windows drives outside the workspace, and WSL interop sockets are absent.

Existing workspace `.git`, `.zero`, `.ssh`, `.aws`, `.azure`, `.config`, `.gnupg`
directories are covered by empty read-only mounts. Existing `auth.json`,
`settings.json`, `credentials`, `.npmrc`, `.pypirc`, `.netrc`, `.env`, `.env.*`,
`*.pem` and `*.key` files are covered by read-only null-file mounts. The configured
agent directory is excluded even when it has a custom name inside the workspace.
Protected symlink mountpoints cause startup to fail. Other symlinks cannot resolve
to host paths that were not mounted.

The seccomp filter denies Unix-domain sockets (including abstract sockets), packet
sockets, VSOCK, raw IPv4/IPv6 sockets, namespace switching, mount operations,
ptrace/process-memory access, BPF, keyctl, io_uring, and related escape surfaces.
IP sockets can only reach the sandbox's own loopback namespace. Network-local
NETLINK is permitted for libc interface discovery; anonymous socketpairs remain
available for Python/ZeroMQ internals. Descendant processes inherit the boundary.

## Jupyter transport and lifecycle

The supervisor passes only stdio to an isolated relay, which launches IPython in
the same namespace. Jupyter TCP stays entirely inside that namespace. The relay
transports multipart frames as bounded base64 JSON lines over stdio, with separate
shell/control/IOPub channels. Existing streaming, interrupts and comm-based host
requests continue through these channels. Host messages remain HMAC-SHA256 signed;
the host verifies incoming signatures before dispatching messages.

There is no host TCP listener, network proxy, or host ZMQ socket mounted into the
sandbox. Prewarm and restart use this same launch path. Closing host stdin makes
the Linux supervisor terminate bubblewrap; its PID namespace terminates descendants.
Asynchronous kill/dispose/restart wait for supervisor exit, with an explicit error
if cleanup does not complete.

Snapshots are serialized/deserialized inside the sandbox. Restore suspends native
host-request dispatch until the trusted runtime bootstrap has replaced restored
live handles, so pickle reducers cannot invoke privileged host handlers. The host transfers only
bytes to/from the configured snapshot files; the session/artifact directory is not
mounted. Snapshot payloads are capped at 512000 bytes for this bounded relay.
Existing larger snapshots are rejected. Snapshots are skipped when active host
vault credentials are present, rather than sending credential plaintext into the
kernel for the previous snapshot exclusion check. A pickle reducer runs inside
the same sandbox during restore, never in the Node host.

## Authority and limits

This is the kernel/process boundary, not a sandbox for the native backend.
Registered native host-request handlers execute outside it and must enforce their
own authorization, path, network and credential policies. A handler can deliberately
return sensitive data or perform an external operation; kernel isolation does not
revoke that capability. No native tool dispatcher or SDK/session authority code is
changed by this implementation.

The workspace is an explicit data grant: arbitrary secrets in unrecognized files
there remain readable. Protected mounts are built at launch; credentials newly
created by a trusted host under other workspace paths are not automatically hidden.
Keep credential stores outside the granted workspace. This does not impose CPU,
memory, process-count or workspace-disk quotas, and it is not a VM/kernel-exploit
defense. The trusted runtime itself must not contain operator secrets.

The Linux launch path is implemented but Windows-to-WSL is the runtime-verified
configuration for this change. Existing `dist/` artifacts require the normal
release build before they include these source changes.

## Verification

From `packages/coding-agent`:

```sh
npx tsx ../../node_modules/vitest/dist/cli.js --run test/kernel-sandbox.test.ts
npx tsgo -p tsconfig.build.json --noEmit --incremental false
```

The integration tests use synthetic fixtures and a local listener, with no model
or paid provider calls. They exercise missing prerequisites, forkserver rejection,
prewarm, execution/streaming, forbidden reads/writes, no-new-privileges/seccomp,
raw/Unix/VSOCK and external/host-loopback networking, subprocess inheritance,
restart, hostile snapshot restore, and descendant cleanup.

## Design references

- [Claude Code sandboxing](https://code.claude.com/docs/en/sandboxing): Linux/WSL
  filesystem/network isolation. Zero intentionally denies network rather than
  implementing Claude Code's configurable network proxy.
- [Codex Linux sandbox source](https://github.com/openai/codex/tree/main/codex-rs/linux-sandbox):
  bubblewrap and seccomp/no-new-privileges as the process boundary.
- [Bubblewrap source](https://github.com/containers/bubblewrap/blob/main/bubblewrap.c):
  mount allowlists, namespace flags, seccomp FD, lifecycle and privilege handling.
- [libseccomp rule API](https://github.com/seccomp/libseccomp/blob/main/doc/man/man3/seccomp_rule_add.3).
- [PyZMQ socket API](https://pyzmq.readthedocs.io/en/stable/api/zmq.html):
  multipart frames, pollers and socket/context cleanup.
