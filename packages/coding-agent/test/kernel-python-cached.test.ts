import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	DEFAULT_RLM_EXTRA_UV_ARGS,
	isKernelPythonLikelyCached,
	type KernelPythonSkill,
	resolveRuntimeIdentity,
} from "../src/core/kernel/bootstrap.js";

let tempDir = "";
let originalEnv: NodeJS.ProcessEnv;
let runtimeIdentity = "";

// Mirrors bootstrap.ts's own (unexported) venvPythonPath: uv/stdlib venv layouts put
// the interpreter at bin/python on POSIX but Scripts/python.exe on Windows.
function venvPythonPath(venv: string): string {
	return process.platform === "win32" ? join(venv, "Scripts", "python.exe") : join(venv, "bin", "python");
}

function writeVenvPython(venv: string): void {
	const python = venvPythonPath(venv);
	mkdirSync(join(venv, process.platform === "win32" ? "Scripts" : "bin"), { recursive: true });
	writeFileSync(python, "");
	if (process.platform !== "win32") chmodSync(python, 0o755);
}

function pyprojectHash(pyprojectPath: string): string {
	return `sha256:${createHash("sha256").update(readFileSync(pyprojectPath)).digest("hex")}`;
}

function writeBootstrapVersion(venv: string, pythonSkills: readonly KernelPythonSkill[] = []): void {
	writeFileSync(
		join(venv, ".bootstrap-version"),
		`${JSON.stringify({
			schema: 8,
			ipykernel: "ipykernel",
			runtime: runtimeIdentity,
			snapshot: "dill",
			extraUvArgs: DEFAULT_RLM_EXTRA_UV_ARGS,
			pythonSkills: pythonSkills.map((skill) => ({
				importName: skill.importName,
				packagePath: skill.packagePath,
				pyprojectPath: skill.pyprojectPath,
				pyprojectHash: pyprojectHash(skill.pyprojectPath),
			})),
		})}\n`,
	);
}

function createPythonSkill(name = "web-search"): KernelPythonSkill {
	const packagePath = join(tempDir, "skills", name);
	const importName = name.replaceAll("-", "_");
	const pyprojectPath = join(packagePath, "pyproject.toml");
	mkdirSync(join(packagePath, "src", importName), { recursive: true });
	writeFileSync(pyprojectPath, `[project]\nname = "${name}"\nversion = "0.1.0"\n`);
	writeFileSync(join(packagePath, "src", importName, "__init__.py"), "async def run():\n    return 'ok'\n");
	return { name, importName, packagePath, pyprojectPath };
}

describe("isKernelPythonLikelyCached", () => {
	beforeEach(async () => {
		runtimeIdentity = await resolveRuntimeIdentity();
		originalEnv = { ...process.env };
		tempDir = mkdtempSync(join(tmpdir(), "prime-agent-kernel-cached-"));
		process.env.HOME = tempDir;
		delete process.env.ZERO_KERNEL_PYTHON;
		delete process.env.ZERO_KERNEL_VENV;
		delete process.env.XDG_DATA_HOME;
	});

	afterEach(() => {
		process.env = originalEnv;
		if (tempDir) {
			rmSync(tempDir, { recursive: true, force: true });
			tempDir = "";
		}
	});

	it("returns false when the venv directory doesn't exist", async () => {
		const venv = join(tempDir, "kernel-venv");
		process.env.ZERO_KERNEL_VENV = venv;

		await expect(isKernelPythonLikelyCached()).resolves.toBe(false);
	});

	it("returns false when a marker exists but doesn't match the current key (pythonSkills changed)", async () => {
		const venv = join(tempDir, "kernel-venv");
		process.env.ZERO_KERNEL_VENV = venv;
		writeVenvPython(venv);
		writeBootstrapVersion(venv, []);

		const pythonSkill = createPythonSkill();
		await expect(isKernelPythonLikelyCached({ pythonSkills: [pythonSkill] })).resolves.toBe(false);
	});

	it("returns false when no marker file exists at all, even with the venv python present", async () => {
		const venv = join(tempDir, "kernel-venv");
		process.env.ZERO_KERNEL_VENV = venv;
		writeVenvPython(venv);

		await expect(isKernelPythonLikelyCached()).resolves.toBe(false);
	});

	it("returns true when a marker exists and matches the current key", async () => {
		const venv = join(tempDir, "kernel-venv");
		process.env.ZERO_KERNEL_VENV = venv;
		writeVenvPython(venv);
		writeBootstrapVersion(venv, []);

		await expect(isKernelPythonLikelyCached()).resolves.toBe(true);
	});

	it("returns true when a marker matches including a requested Python skill", async () => {
		const venv = join(tempDir, "kernel-venv");
		process.env.ZERO_KERNEL_VENV = venv;
		writeVenvPython(venv);
		const pythonSkill = createPythonSkill();
		writeBootstrapVersion(venv, [pythonSkill]);

		await expect(isKernelPythonLikelyCached({ pythonSkills: [pythonSkill] })).resolves.toBe(true);
	});

	it("returns true unconditionally when ZERO_KERNEL_PYTHON is set (no venv build possible)", async () => {
		process.env.ZERO_KERNEL_PYTHON = join(tempDir, "override-python");

		await expect(isKernelPythonLikelyCached()).resolves.toBe(true);
	});
});
