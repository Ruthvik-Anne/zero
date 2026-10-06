import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { describe, expect, it } from "vitest";
import { forkKernel, isForkServerEnabled } from "../src/core/kernel/fork-server.js";
import { KernelManager } from "../src/core/kernel/index.js";
import { sandboxPath } from "../src/core/kernel/sandbox.js";
import { SANDBOX_LAUNCHER } from "../src/core/kernel/sandbox-runtime.js";
import { IpythonKernelProvisioner } from "../src/core/tools/ipython.js";

// Python inside the Linux sandbox needs the path as WSL sees it, not as Windows does.
function toSandboxVisiblePath(hostPath: string): string {
	if (process.platform !== "win32") return hostPath;
	return execFileSync(
		"wsl.exe",
		["-d", process.env.ZERO_KERNEL_WSL_DISTRO ?? "Ubuntu", "--exec", "wslpath", "-a", hostPath],
		{ encoding: "utf8", windowsHide: true },
	)
		.replace(/\0/g, "")
		.trim();
}

describe("kernel sandbox", () => {
	it("defers Windows path mapping to the selected WSL distribution", () => {
		expect(sandboxPath("C:\\workspace with spaces\\file", "win32")).toBe("C:\\workspace with spaces\\file");
		expect(() => sandboxPath("\\\\server\\share", "win32")).toThrow();
		expect(SANDBOX_LAUNCHER).toContain("wslpath");
		expect(SANDBOX_LAUNCHER).not.toContain("workspace in ('/', '/home', '/mnt', '/mnt/c')");
	});
	it("denies dangerous socket families and masked raw socket types", () => {
		expect(SANDBOX_LAUNCHER).toContain("SCMP_CMP_MASKED_EQ");
		expect(SANDBOX_LAUNCHER).toContain("for family in (1, 9, 17, 21");
		expect(SANDBOX_LAUNCHER).toContain("Compare(0, SCMP_CMP_EQ, family, 0)");
		expect(SANDBOX_LAUNCHER).toContain("config.get('trustedPaths', [])");
		expect(SANDBOX_LAUNCHER).toContain("config.get('writableEnvPaths', [])");
		expect(SANDBOX_LAUNCHER).toContain("env=supervisor_env");
		expect(SANDBOX_LAUNCHER).not.toContain("env=kernel_env");
	});
	it.runIf(process.platform !== "win32" || Boolean(process.env.ZERO_KERNEL_SANDBOX_PYTHON))(
		"rejects missing prerequisites and the legacy unsandboxed fork path",
		async () => {
			expect(isForkServerEnabled()).toBe(false);
			await expect(forkKernel("python", { connectionPath: "unused" })).rejects.toThrow("disabled");
			const manager = new KernelManager({ cwd: process.cwd(), python: "/nonexistent/zero-sandbox-python" });
			try {
				await expect(manager.start()).rejects.toThrow("Sandbox prerequisite missing: Linux Python");
				expect(manager.isRunning).toBe(false);
			} finally {
				await manager.kill();
			}
		},
		40000,
	);
	it.runIf(process.platform !== "win32" || Boolean(process.env.ZERO_KERNEL_SANDBOX_PYTHON))(
		"prewarms the same isolated manager",
		async () => {
			const dir = mkdtempSync(join(tmpdir(), "zero-sandbox-prewarm-"));
			const provisioner = new IpythonKernelProvisioner(dir);
			try {
				provisioner.prewarm();
				const manager = await provisioner.ensure();
				const result = await manager.execute("import os; assert 'WSL_INTEROP' not in os.environ; print(rlm)");
				expect(result.status, result.error?.traceback.join("\n")).toBe("ok");
				expect(result.stdout).not.toContain("MissingRlm");
			} finally {
				await provisioner.dispose();
				rmSync(dir, { recursive: true, force: true });
			}
		},
		// See the 120000ms note below: an uncached WSL Python validation subprocess alone
		// takes 25-30s on Windows+WSL2 with a cold OS page cache, before bwrap or the kernel
		// itself even starts.
		90000,
	);
	it.runIf(process.platform !== "win32" || Boolean(process.env.ZERO_KERNEL_SANDBOX_PYTHON))(
		"enforces isolation through execute, subprocesses, restart and restore",
		async () => {
			const dir = mkdtempSync(join(tmpdir(), "zero-sandbox-test-"));
			const workspace = join(dir, "workspace");
			// The host fixture is deliberately outside the granted workspace.
			const secret = join(dir, "credential.txt");
			writeFileSync(secret, "synthetic-secret");
			mkdirSync(workspace);
			writeFileSync(join(workspace, ".env"), "synthetic-workspace-secret");
			writeFileSync(join(workspace, "auth.json"), "synthetic-auth");
			writeFileSync(join(workspace, "settings.json"), "synthetic-settings");
			const listener = createServer();
			await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve));
			const address = listener.address();
			if (!address || typeof address === "string") throw new Error("No listener address");
			const inheritedSecret = process.env.ZERO_SANDBOX_INHERITED_SECRET;
			process.env.ZERO_SANDBOX_INHERITED_SECRET = "must-not-cross";
			let privilegedRestoreCalls = 0;
			const manager = new KernelManager({
				cwd: workspace,
				env: { ZERO_PUBLIC_KERNEL_VALUE: "explicit-value" },
				hostHandlers: {
					"audit.privileged": async () => {
						privilegedRestoreCalls++;
						return { granted: true };
					},
				},
				snapshot: {
					path: join(dir, "state.dill"),
					manifestPath: join(dir, "state.json"),
					debounceMs: 60000,
				},
			});
			try {
				await manager.start();
				const chunks: string[] = [];
				const result = await manager.execute(
					`
import os, pathlib, socket, subprocess, sys
assert os.environ['ZERO_PUBLIC_KERNEL_VALUE'] == 'explicit-value'
assert 'ZERO_SANDBOX_INHERITED_SECRET' not in os.environ
assert 'WSL_INTEROP' not in os.environ
_status = pathlib.Path('/proc/self/status').read_text()
assert 'NoNewPrivs:\t1' in _status and 'Seccomp:\t2' in _status
assert 'CapEff:\t0000000000000000' in _status
for p in [${JSON.stringify(toSandboxVisiblePath(secret))}, '.env', 'auth.json', 'settings.json', '/etc/shadow', '/mnt/c/Windows', '/run/WSL']:
    try:
        pathlib.Path(p).read_bytes()
    except (OSError, IsADirectoryError):
        pass
    else:
        raise AssertionError(p)
for p in [${JSON.stringify(toSandboxVisiblePath(secret))}, '.env', 'auth.json', 'settings.json', sys.executable, '/usr/zero-write-test']:
    try:
        pathlib.Path(p).write_text('forbidden')
    except OSError:
        pass
    else:
        raise AssertionError('write allowed: ' + p)
for address in [('127.0.0.1', ${address.port}), ('1.1.1.1', 443)]:
    s = socket.socket(); s.settimeout(0.2)
    assert s.connect_ex(address) != 0
    s.close()
for family, kind in [(socket.AF_UNIX, socket.SOCK_STREAM), (socket.AF_INET, socket.SOCK_RAW | socket.SOCK_CLOEXEC), (40, socket.SOCK_STREAM)]:
    try:
        socket.socket(family, kind)
    except OSError:
        pass
    else:
        raise AssertionError('socket allowed')
assert subprocess.run([sys.executable, '-c', "import pathlib; pathlib.Path('/etc/shadow').read_bytes()"], capture_output=True).returncode != 0
assert subprocess.run([sys.executable, '-c', "import socket; socket.create_connection(('1.1.1.1', 443), timeout=0.2)"], capture_output=True).returncode != 0
pathlib.Path('allowed.txt').write_text('allowed')
saved_value = 'persistent'
class _ForbiddenRestore:
    def __reduce__(self):
        return (eval, ("open('/etc/shadow').read()",))
forbidden_restore = _ForbiddenRestore()
class _PrivilegedRestore:
    def __reduce__(self):
        return (exec, ("import asyncio, rlm; asyncio.get_event_loop().create_task(rlm.host_request('audit.privileged'))",))
privileged_restore = _PrivilegedRestore()
print('sandbox-ok', flush=True)
`,
					{ onStream: (chunk) => chunks.push(chunk) },
				);
				expect(result.status, result.error?.traceback.join("\n")).toBe("ok");
				expect(chunks.join("")).toContain("sandbox-ok");
				expect(readFileSync(join(workspace, "allowed.txt"), "utf8")).toBe("allowed");
				const shell = await manager.execute("%%bash\ntest ! -e /etc/shadow\nprintf 'shell-ok\\n'");
				expect(shell.status, shell.stderr).toBe("ok");
				expect(shell.stdout).toContain("shell-ok");
				expect((await manager.snapshotState())?.saved).toContain("saved_value");
				await manager.restart();
				const restored = await manager.restoreState({ keepHostRequestsSuspended: true });
				expect(restored?.restored).toContain("saved_value");
				expect(restored?.failed.some((entry) => entry.name === "forbidden_restore")).toBe(true);
				expect((await manager.execute("print(saved_value)")).stdout).toContain("persistent");
				await sleep(100);
				expect(privilegedRestoreCalls).toBe(0);
				manager.resumeHostRequests();
				await manager.execute(
					"import subprocess, sys; subprocess.Popen([sys.executable, '-c', \"import time, pathlib; time.sleep(1); pathlib.Path('escaped-child.txt').write_text('escaped')\"])",
				);
				await manager.kill();
				await sleep(1500);
				expect(existsSync(join(workspace, "escaped-child.txt"))).toBe(false);
				expect(readFileSync(secret, "utf8")).toBe("synthetic-secret");
			} finally {
				if (inheritedSecret === undefined) delete process.env.ZERO_SANDBOX_INHERITED_SECRET;
				else process.env.ZERO_SANDBOX_INHERITED_SECRET = inheritedSecret;
				await manager.kill();
				await new Promise<void>((resolve) => listener.close(() => resolve()));
				rmSync(dir, { recursive: true, force: true });
			}
		},
		// Each kernel start re-runs the uncached WSL Python validation subprocess (ipykernel,
		// zmq, dill, and the full default package set), and this test restarts the kernel.
		// A cold OS page cache makes that validation take 25-30s per start on Windows+WSL2.
		120000,
	);
});
