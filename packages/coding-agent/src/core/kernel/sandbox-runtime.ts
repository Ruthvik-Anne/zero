// Kept inline so source, dist and bundled launches use the identical boundary.
export const SANDBOX_RELAY = String.raw`
import base64, json, os, subprocess, sys, time
try:
    import zmq, ipykernel, dill, rlm
except ImportError as error:
    raise RuntimeError('Sandbox runtime prerequisite missing: ' + str(error)) from error
config = json.loads(sys.stdin.buffer.readline())
if 'host_net' in config:
    for namespace in ('net', 'pid'):
        if os.readlink('/proc/self/ns/' + namespace) == config['host_' + namespace]:
            raise RuntimeError('Sandbox failed to isolate ' + namespace + ' namespace')
    with open('/proc/self/status') as f:
        status = dict(line.split(':', 1) for line in f if ':' in line)
    if status['NoNewPrivs'].strip() != '1' or status['Seccomp'].strip() != '2' or int(status['CapEff'].strip(), 16) != 0:
        raise RuntimeError('Sandbox privilege/seccomp enforcement is missing')
connection_file = os.path.join(config.get('scratch', '/tmp'), 'connection.json')
os.umask(0o077)
os.makedirs(config.get('kernelHome', '/home/kernel'), exist_ok=True)
connection = config['connection']
with open(connection_file, 'w') as f:
    json.dump(connection, f)
kernel = subprocess.Popen([sys.executable, '-I', '-m', 'ipykernel_launcher', '-f', connection_file], stdin=subprocess.DEVNULL, stdout=sys.stderr, stderr=sys.stderr, close_fds=True)
ctx = zmq.Context()
sockets = {}
poller = zmq.Poller()
try:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if kernel.poll() is not None:
            raise RuntimeError('isolated kernel exited during startup')
        try:
            with open(connection_file) as f:
                connection = json.load(f)
        except (OSError, ValueError):
            time.sleep(0.025)
            continue
        if all(connection[k] > 0 for k in ('shell_port', 'control_port', 'iopub_port')):
            break
        time.sleep(0.025)
    else:
        raise RuntimeError('isolated kernel did not resolve ports')
    for name, kind in [('shell', zmq.DEALER), ('control', zmq.DEALER), ('iopub', zmq.SUB)]:
        s = ctx.socket(kind)
        s.setsockopt(zmq.LINGER, 0)
        s.setsockopt(zmq.MAXMSGSIZE, 32 * 1024 * 1024)
        if name == 'iopub':
            s.setsockopt(zmq.SUBSCRIBE, b'')
        s.connect('tcp://127.0.0.1:' + str(connection[name + '_port']))
        sockets[name] = s
        poller.register(s, zmq.POLLIN)
    poller.register(0, zmq.POLLIN)
    time.sleep(0.1)
    print(json.dumps({'ready': connection}), flush=True)
    pending = b''
    while kernel.poll() is None:
        events = dict(poller.poll(100))
        if 0 in events:
            data = os.read(0, 65536)
            if not data:
                break
            pending += data
            if len(pending) > 32 * 1024 * 1024:
                raise RuntimeError('relay input exceeded limit')
            while b'\n' in pending:
                line, pending = pending.split(b'\n', 1)
                msg = json.loads(line)
                if msg.get('close'):
                    sys.exit(0)
                channel = msg['channel']
                if channel not in ('shell', 'control'):
                    raise RuntimeError('invalid relay channel')
                sockets[channel].send_multipart([base64.b64decode(f, validate=True) for f in msg['frames']])
        for name, s in sockets.items():
            if s in events:
                frames = s.recv_multipart()
                if sum(map(len, frames)) > 24 * 1024 * 1024:
                    raise RuntimeError('relay output exceeded limit')
                print(json.dumps({'channel': name, 'frames': [base64.b64encode(f).decode('ascii') for f in frames]}), flush=True)
finally:
    kernel.kill() if kernel.poll() is None else None
    kernel.wait()
    ctx.destroy(linger=0)
`;

export const SANDBOX_LAUNCHER = String.raw`
import ctypes, json, os, re, select, shutil, signal, subprocess, sys
config = json.loads(sys.stdin.buffer.readline())
python = os.path.expanduser(config.get('python') or '~/.local/share/zero/kernel-sandbox/bin/python')
if not os.path.isabs(python) or not os.path.isfile(python):
    raise RuntimeError('Sandbox prerequisite missing: Linux Python at ' + python + '. Provision a Linux venv with ipykernel, pyzmq, dill and zero-runtime; set ZERO_KERNEL_SANDBOX_PYTHON. Native Windows Python is not supported.')
bwrap = shutil.which('bwrap', path='/usr/bin:/bin')
if not bwrap:
    raise RuntimeError('Sandbox prerequisite missing: bubblewrap. No unsandboxed fallback.')
def host_path(value):
    if not config.get('windowsPaths'):
        return value
    try:
        return subprocess.check_output(['/usr/bin/wslpath', '-a', value], text=True).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise RuntimeError('Could not translate Windows path in the selected WSL distribution: ' + value + '. Ensure wslpath is installed and the drive is mounted.') from error
workspace = os.path.realpath(host_path(config['workspace']))
def is_broad_root(path):
    home = os.path.realpath(os.path.expanduser('~'))
    if path in ('/', '/home', '/mnt', '/root') or path == home or home.startswith(path + '/'):
        return True
    lowered = path.lower()
    return bool(re.fullmatch(r'/mnt/[a-z]', lowered) or re.fullmatch(r'/mnt/[a-z]/users/[^/]+', lowered) or re.fullmatch(r'/home/[^/]+', path))
if is_broad_root(workspace) or not os.path.isdir(workspace):
    raise RuntimeError('Sandbox requires a specific existing workspace directory, not a drive, user profile, or home directory')
protected = os.path.realpath(host_path(config['protectedPath']))
if workspace == protected or workspace.startswith(protected + '/'):
    raise RuntimeError('Agent configuration cannot be granted as a workspace')
runtime = os.path.realpath(os.path.dirname(os.path.dirname(python)))
if runtime == '/usr':
    runtime = None
elif not os.path.isfile(os.path.join(runtime, 'pyvenv.cfg')):
    raise RuntimeError('Sandbox Python must be /usr/bin/python or a Linux venv')
if runtime and (workspace == runtime or runtime.startswith(workspace + '/')):
    raise RuntimeError('Sandbox runtime must be outside the writable workspace')
supervisor_env = {'PATH': '/usr/bin:/bin', 'HOME': '/home/kernel', 'TMPDIR': '/tmp', 'LANG': 'C.UTF-8', 'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1', 'NO_COLOR': '1'}
kernel_env = dict(supervisor_env)
path_env_keys = {'RLM_GLOBAL_HARNESS_STATE_DIR', 'RLM_SESSION_DIR', 'RLM_HARNESS_STATE_DIR'}
for key, value in config.get('env', {}).items():
    if not isinstance(key, str) or not key or '=' in key or '\0' in key or not isinstance(value, str) or '\0' in value:
        raise RuntimeError('Invalid explicit kernel environment entry')
    if key not in ('PATH', 'HOME', 'TMPDIR', 'PYTHONNOUSERSITE', 'PYTHONDONTWRITEBYTECODE'):
        if key in path_env_keys:
            value = host_path(value)
        kernel_env[key] = value
# libseccomp resolves native syscall numbers and kills foreign-architecture calls.
# https://github.com/seccomp/libseccomp/blob/main/doc/man/man3/seccomp_rule_add.3
lib = ctypes.CDLL('libseccomp.so.2')
lib.seccomp_init.argtypes = [ctypes.c_uint32]
lib.seccomp_init.restype = ctypes.c_void_p
lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
class Compare(ctypes.Structure):
    _fields_ = [('arg', ctypes.c_uint), ('op', ctypes.c_int), ('a', ctypes.c_uint64), ('b', ctypes.c_uint64)]
lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint, ctypes.POINTER(Compare)]
lib.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]
lib.seccomp_release.argtypes = [ctypes.c_void_p]
ctx = lib.seccomp_init(0x7fff0000)
if not ctx:
    raise RuntimeError('seccomp_init failed')
def deny(name, comparisons=()):
    nr = lib.seccomp_syscall_resolve_name(name.encode())
    if nr < 0 or lib.seccomp_rule_add_array(ctx, 0x50001, nr, len(comparisons), (Compare * len(comparisons))(*comparisons)) != 0:
        raise RuntimeError('seccomp rule failed: ' + name)
for name in ('ptrace', 'process_vm_readv', 'process_vm_writev', 'mount', 'umount2', 'pivot_root', 'setns', 'unshare', 'bpf', 'keyctl', 'open_by_handle_at', 'io_uring_setup', 'perf_event_open'):
    deny(name)
SCMP_CMP_NE = 1
SCMP_CMP_EQ = 4
SCMP_CMP_MASKED_EQ = 7
# libseccomp rejects several comparisons on one argument, and ALLOW rules are refused,
# so socket families are denied by value. Sockets remain inside the empty network
# namespace; these families can reach the host, other namespaces, or hardware.
for family in (1, 9, 17, 21, 23, 26, 29, 30, 31, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44):
    deny('socket', [Compare(0, SCMP_CMP_EQ, family, 0)])
for family in (2, 10):
    deny('socket', [Compare(0, SCMP_CMP_EQ, family, 0), Compare(1, SCMP_CMP_MASKED_EQ, 15, 3)]) # IPv4/IPv6 SOCK_RAW, including flags
fd = os.memfd_create('zero-seccomp', 0)
if lib.seccomp_export_bpf(ctx, fd) != 0:
    raise RuntimeError('seccomp export failed')
lib.seccomp_release(ctx)
os.lseek(fd, 0, os.SEEK_SET)
args = [bwrap, '--unshare-all', '--unshare-user', '--unshare-net', '--unshare-pid', '--die-with-parent', '--new-session', '--cap-drop', 'ALL', '--clearenv', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--tmpfs', '/home', '--dir', '/home/kernel', '--dir', '/run', '--bind', workspace, workspace]
if runtime:
    args += ['--ro-bind', runtime, runtime]
    base = subprocess.check_output([python, '-I', '-c', 'import sys; print(sys.base_prefix)'], env=supervisor_env, text=True).strip()
    if base != '/usr':
        if not os.path.isabs(base) or base == '/' or workspace == base or base.startswith(workspace + '/'):
            raise RuntimeError('unsafe Python base runtime')
        args += ['--ro-bind', base, base]
for raw_path in config.get('trustedPaths', []):
    trusted = os.path.realpath(host_path(raw_path))
    if not os.path.exists(trusted) or trusted in ('/', '/home', '/mnt'):
        raise RuntimeError('Invalid trusted sandbox mount: ' + raw_path)
    if trusted != workspace and not trusted.startswith(workspace + '/'):
        args += ['--ro-bind', trusted, trusted]
for raw_path in config.get('writableEnvPaths', []):
    writable = os.path.realpath(host_path(raw_path))
    if not os.path.exists(writable) or writable in ('/', '/home', '/mnt'):
        raise RuntimeError('Invalid writable kernel environment path: ' + raw_path)
    if writable != workspace and not writable.startswith(workspace + '/'):
        args += ['--bind', writable, writable]
# Hide credentials/config/control files even when the workspace contains them.
# Do not follow symlinks; they cannot resolve to unmounted host paths.
private_dirs = {'.git', '.zero', '.ssh', '.aws', '.azure', '.config', '.gnupg'}
private_files = {'.git', 'auth.json', 'settings.json', 'credentials', '.npmrc', '.pypirc', '.netrc'}
for root, dirs, files in os.walk(workspace, followlinks=False):
    for name in list(dirs):
        if name in private_dirs:
            target = os.path.join(root, name)
            if os.path.islink(target):
                raise RuntimeError('protected workspace directory is a symlink: ' + target)
            args += ['--tmpfs', target, '--remount-ro', target]
            dirs.remove(name)
    for name in files:
        if name in private_files or name == '.env' or name.startswith('.env.') or name.endswith(('.pem', '.key')):
            target = os.path.join(root, name)
            if os.path.islink(target):
                raise RuntimeError('protected workspace file is a symlink: ' + target)
            args += ['--ro-bind', '/dev/null', target]
for key, value in kernel_env.items():
    args += ['--setenv', key, value]
if protected.startswith(workspace + '/') and os.path.exists(protected):
    args += ['--tmpfs', protected, '--remount-ro', protected]
args += ['--remount-ro', '/', '--chdir', workspace, '--seccomp', str(fd), python, '-I', '-u', '-c', config['relay']]
# Launcher never consumes kernel frames or runs workspace code on the host.
# Hand initial config to the relay on a pipe, then pump the existing stdio.
child = subprocess.Popen(args, stdin=subprocess.PIPE, pass_fds=(fd,), env=supervisor_env, close_fds=True, start_new_session=True)
os.close(fd)
child.stdin.write((json.dumps({'connection': config['connection'], 'host_net': os.readlink('/proc/self/ns/net'), 'host_pid': os.readlink('/proc/self/ns/pid')}) + '\n').encode())
child.stdin.flush()
try:
    while True:
        if child.poll() is not None:
            break
        if not select.select([0], [], [], 0.1)[0]:
            continue
        data = os.read(0, 65536)
        if not data:
            break
        child.stdin.write(data)
        child.stdin.flush()
finally:
    child.stdin.close()
    try:
        child.wait(timeout=2)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()
sys.exit(child.returncode)
`;

// macOS has no namespaces, seccomp, or bubblewrap; confinement is a Seatbelt profile.
// The profile is deny-by-default and is probed before the kernel starts, so the
// launcher refuses to run if the profile does not block home-directory reads or
// outbound network access. Loopback stays reachable for the kernel's ZeroMQ sockets.
export const SANDBOX_LAUNCHER_DARWIN = String.raw`
import json, os, select, signal, subprocess, sys
config = json.loads(sys.stdin.buffer.readline())
SANDBOX_EXEC = '/usr/bin/sandbox-exec'
if not os.path.isfile(SANDBOX_EXEC):
    raise RuntimeError('Sandbox prerequisite missing: ' + SANDBOX_EXEC)
home = os.path.realpath(os.path.expanduser('~'))
def safe_path(value):
    if not isinstance(value, str) or not os.path.isabs(value) or any(c in value for c in '"\\\n\r\0()'):
        raise RuntimeError('Unsafe path for sandbox profile: ' + repr(value))
    return value
def real(value):
    return safe_path(os.path.realpath(os.path.expanduser(value)))
python = real(config.get('python') or '/usr/bin/python3')
if not os.path.isfile(python):
    raise RuntimeError('Sandbox prerequisite missing: Python at ' + python + '. Set ZERO_KERNEL_SANDBOX_PYTHON to a Python 3 with ipykernel, pyzmq, dill and zero-runtime installed.')
workspace = real(config['workspace'])
if workspace in ('/', '/Users', '/Volumes', '/private', home) or home.startswith(workspace + '/') or not os.path.isdir(workspace):
    raise RuntimeError('Sandbox requires a specific existing workspace directory')
protected = real(config['protectedPath'])
if workspace == protected or workspace.startswith(protected + '/'):
    raise RuntimeError('Agent configuration cannot be granted as a workspace')
scratch = real(config['scratch'])
kernel_home = os.path.join(scratch, 'home')
os.makedirs(kernel_home, exist_ok=True)
runtime = real(os.path.dirname(os.path.dirname(python)))
base = real(subprocess.check_output([python, '-I', '-c', 'import sys; print(sys.base_prefix)'], env={'PATH': '/usr/bin:/bin'}, text=True).strip())
exec_roots = ['/usr', '/bin', '/sbin', '/System', '/Library', '/opt/homebrew', runtime, base]
readable = ['/usr', '/bin', '/sbin', '/System', '/Library', '/opt/homebrew', '/private/etc', '/private/var/db', '/dev', runtime, base, workspace, scratch]
writable = [workspace, scratch]
def mount_path(raw, label):
    value = real(raw)
    if not os.path.exists(value) or value in ('/', '/Users', '/private', home):
        raise RuntimeError('Invalid ' + label + ': ' + raw)
    return value
for raw_path in config.get('trustedPaths', []):
    trusted = mount_path(raw_path, 'trusted sandbox mount')
    if trusted != workspace and not trusted.startswith(workspace + '/'):
        readable.append(trusted)
for raw_path in config.get('writableEnvPaths', []):
    target = mount_path(raw_path, 'writable kernel environment path')
    if target != workspace and not target.startswith(workspace + '/'):
        writable.append(target)
def subpath(value):
    return '(subpath "' + safe_path(value) + '")'
profile = '\n'.join([
    '(version 1)',
    '(deny default)',
    '(allow process-fork)',
    '(allow signal (target self))',
    '(allow sysctl-read)',
    '(allow mach-lookup)',
    '(allow ipc-posix-shm)',
    '(allow system-socket)',
    '(allow process-exec ' + ' '.join(subpath(p) for p in exec_roots) + ')',
    '(allow file-read* ' + ' '.join(subpath(p) for p in readable) + ')',
    '(allow file-read-metadata)',
    '(allow file-write* ' + ' '.join(subpath(p) for p in writable) + ' (literal "/dev/null") (regex #"^/dev/tty"))',
    '(allow network-bind (local ip "localhost:*"))',
    '(allow network-inbound (local ip "localhost:*"))',
    '(allow network-outbound (remote ip "localhost:*"))',
])
PROBE = "import os, socket, sys\ntry:\n    os.listdir(sys.argv[1])\n    sys.exit(4)\nexcept PermissionError:\n    pass\ntry:\n    socket.create_connection(('1.1.1.1', 443), timeout=3).close()\n    sys.exit(5)\nexcept OSError:\n    pass\n"
probe = subprocess.run([SANDBOX_EXEC, '-p', profile, python, '-I', '-c', PROBE, home], env={'PATH': '/usr/bin:/bin', 'HOME': kernel_home, 'TMPDIR': scratch}, capture_output=True, text=True, timeout=60)
if probe.returncode == 4:
    raise RuntimeError('Sandbox confinement failed: the home directory is readable inside the sandbox.')
if probe.returncode == 5:
    raise RuntimeError('Sandbox confinement failed: outbound network is reachable inside the sandbox.')
if probe.returncode != 0:
    raise RuntimeError('Sandbox confinement probe did not run (exit ' + str(probe.returncode) + '): ' + probe.stderr.strip()[-500:])
supervisor_env = {'PATH': '/usr/bin:/bin', 'HOME': kernel_home, 'TMPDIR': scratch, 'LANG': 'C.UTF-8', 'PYTHONNOUSERSITE': '1', 'PYTHONDONTWRITEBYTECODE': '1', 'NO_COLOR': '1'}
kernel_env = dict(supervisor_env)
for key, value in config.get('env', {}).items():
    if not isinstance(key, str) or not key or '=' in key or '\0' in key or not isinstance(value, str) or '\0' in value:
        raise RuntimeError('Invalid explicit kernel environment entry')
    if key not in ('PATH', 'HOME', 'TMPDIR', 'PYTHONNOUSERSITE', 'PYTHONDONTWRITEBYTECODE'):
        kernel_env[key] = value
child = subprocess.Popen([SANDBOX_EXEC, '-p', profile, python, '-I', '-u', '-c', config['relay']], stdin=subprocess.PIPE, env=kernel_env, close_fds=True, start_new_session=True)
child.stdin.write((json.dumps({'connection': config['connection'], 'scratch': scratch, 'kernelHome': kernel_home}) + '\n').encode())
child.stdin.flush()
try:
    while True:
        if child.poll() is not None:
            break
        if not select.select([0], [], [], 0.1)[0]:
            continue
        data = os.read(0, 65536)
        if not data:
            break
        child.stdin.write(data)
        child.stdin.flush()
finally:
    try:
        child.stdin.close()
        child.wait(timeout=2)
    except (subprocess.TimeoutExpired, OSError):
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()
sys.exit(child.returncode)
`;
