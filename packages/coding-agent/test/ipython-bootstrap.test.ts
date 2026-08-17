import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { KernelManager } from "../src/core/kernel/index.js";
import { buildRlmBootstrapCode } from "../src/core/tools/ipython.js";

describe("IPython RLM bootstrap", () => {
	it("pre-imports asyncio so the prompt's subagent patterns work without a manual import", () => {
		expect(buildRlmBootstrapCode()).toMatch(/^import asyncio$/m);
	});

	it("gives subagent registry operations the actionable missing-runtime fallback", () => {
		const code = buildRlmBootstrapCode();
		expect(code).toContain('async def find_models(self, query="", limit=8)');
		expect(code).toContain("async def list_subagents(self)");
		expect(code).toContain("async def delete_subagent(self, target)");
		expect(code).toContain("self._raise_missing()");
	});

	it("disables colored output for subprocesses launched by the kernel", () => {
		expect(buildRlmBootstrapCode()).toContain('_prime_agent_os.environ["NO_COLOR"] = "1"');
	});

	it("guards Python skill imports so a broken skill does not abort bootstrap", () => {
		const code = buildRlmBootstrapCode([
			{
				name: "broken-skill",
				importName: "broken_skill",
				packagePath: "/tmp/broken-skill",
				pyprojectPath: "/tmp/broken-skill/pyproject.toml",
			},
		]);

		expect(code).toContain("except Exception as _prime_agent_skill_error");
		expect(code).toContain("_PrimeAgentUnavailableSkill");
		expect(code).toContain("_PRIME_AGENT_SKILL_IMPORT_ERRORS");
		expect(code).toContain("globals()[_prime_agent_skill_name] = _PrimeAgentUnavailableSkill");
	});
});

/** Find a python that can launch an ipykernel, or null to skip. */
function resolveKernelPython(): string | null {
	// uv/stdlib venvs lay out bin/python on POSIX but Scripts/python.exe on
	// Windows — there is no bin/ dir there at all.
	const defaultVenvPython =
		process.platform === "win32"
			? join(homedir(), ".zero", "agent", "kernel-venv", "Scripts", "python.exe")
			: join(homedir(), ".zero", "agent", "kernel-venv", "bin", "python");
	const candidates = [process.env.ZERO_KERNEL_PYTHON, defaultVenvPython].filter((p): p is string => Boolean(p));
	for (const python of candidates) {
		if (!existsSync(python)) continue;
		const check = spawnSync(python, ["-c", "import ipykernel"], { encoding: "utf8", windowsHide: true });
		if (check.status === 0) return python;
	}
	return null;
}

const python = resolveKernelPython();
const describeIfKernel = python ? describe : describe.skip;

describeIfKernel("IPython RLM bootstrap (real kernel)", () => {
	const dir = mkdtempSync(join(tmpdir(), "prime-agent-bootstrap-"));

	afterAll(() => {
		// A just-killed real kernel subprocess (spawned with dir as its cwd) can
		// leave dir transiently undeletable on Windows even after dispose()
		// resolves — retry, and tolerate a leftover if it still hasn't released
		// by then; this is a cleanup artifact, not a test-correctness problem.
		// Mirrors test/suite/harness.ts's identical fix.
		try {
			rmSync(dir, { recursive: true, force: true, maxRetries: 40, retryDelay: 50 });
		} catch (error) {
			const code = (error as NodeJS.ErrnoException).code;
			if (code !== "ENOTEMPTY" && code !== "EPERM" && code !== "EBUSY") {
				throw error;
			}
		}
	});

	it("binds asyncio in the user namespace", async () => {
		const manager = new KernelManager({ python: python as string, cwd: dir });
		try {
			await manager.start();
			const bootstrap = await manager.execute(buildRlmBootstrapCode());
			expect(bootstrap.status).toBe("ok");

			const result = await manager.execute("_t = asyncio.create_task(asyncio.sleep(0))\nprint(type(_t).__name__)");
			expect(result.status).toBe("ok");
			expect(result.stdout).toContain("Task");

			// (task #35) Bare `%%bash` lets IPython resolve "bash" via its own PATH
			// search, which on a Windows machine with WSL installed can resolve to
			// the WSL launcher stub (a different, WSL-namespaced environment) ahead
			// of a real shell like Git Bash — not what NO_COLOR-inheritance is
			// actually testing here. Resolve an unambiguous shell path first and
			// target it explicitly via `%%script`, the same escape hatch
			// production's own shellPath option uses (applyShellSettingsToBashMagicCell).
			const shellPath = await manager.execute(
				"import shutil, sys\nprint(shutil.which('bash') or ('cmd.exe' if sys.platform == 'win32' else '/bin/sh'))",
			);
			expect(shellPath.status).toBe("ok");
			const resolvedShell = shellPath.stdout.trim();
			// %%script is parsed via `arg_split(line, posix=False)` on Windows,
			// where double quotes group (and get stripped) but single quotes
			// don't quote at all — matches the fix in ipython.ts's own
			// quoteScriptMagicArgument().
			const scriptLine = /^[A-Za-z0-9_@%+=:,./-]+$/.test(resolvedShell)
				? resolvedShell
				: process.platform === "win32"
					? `"${resolvedShell}"`
					: `'${resolvedShell.replace(/'/g, "'\"'\"'")}'`;
			const bashResult = await manager.execute(`%%script ${scriptLine}\nprintf %s "$NO_COLOR"`);
			expect(bashResult.status).toBe("ok");
			expect(bashResult.stdout).toBe("1");
		} finally {
			await manager.dispose();
		}
	}, 60_000);

	it("emits canonical paths for edits after the kernel changes directories", async () => {
		const firstDir = join(dir, "first");
		const secondDir = join(dir, "second");
		mkdirSync(firstDir, { recursive: true });
		mkdirSync(secondDir, { recursive: true });
		writeFileSync(join(firstDir, "same.txt"), "old");
		writeFileSync(join(secondDir, "same.txt"), "old");
		const editSkillRoot = join(process.cwd(), "skills", "edit");
		const manager = new KernelManager({
			python: python as string,
			cwd: dir,
			env: { PYTHONPATH: join(editSkillRoot, "src") },
		});
		try {
			await manager.start();
			const bootstrap = await manager.execute(
				buildRlmBootstrapCode([
					{
						name: "edit",
						importName: "edit",
						packagePath: editSkillRoot,
						pyprojectPath: join(editSkillRoot, "pyproject.toml"),
					},
				]),
			);
			expect(bootstrap.status).toBe("ok");

			const first = await manager.execute(
				'import os\nos.chdir("first")\nawait edit(path="same.txt", old_str="old", new_str="new")',
			);
			const second = await manager.execute(
				'os.chdir("../second")\nawait edit(path="same.txt", old_str="old", new_str="new")',
			);

			// (task #35) Node's plain realpathSync doesn't expand Windows 8.3 short
			// names (e.g. RUTHVI~1) the way Python's os.path.realpath does — both are
			// "correct" canonical forms for the same file, they just disagree when
			// TEMP itself is configured as a short name. realpathSync.native calls
			// the same OS API (GetFinalPathNameByHandleW) Python uses, so it agrees.
			expect(first.diffs?.[0]?.path).toBe(realpathSync.native(join(firstDir, "same.txt")));
			expect(second.diffs?.[0]?.path).toBe(realpathSync.native(join(secondDir, "same.txt")));
			expect(first.diffs?.[0]?.path).not.toBe(second.diffs?.[0]?.path);
		} finally {
			await manager.dispose();
		}
	}, 60_000);
});
