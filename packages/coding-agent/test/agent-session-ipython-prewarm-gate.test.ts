import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Agent } from "@zero-agent/agent-core";
import { getModel } from "@zero-agent/ai";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AgentSession } from "../src/core/agent-session.js";
import { AuthStorage } from "../src/core/auth-storage.js";
import * as bootstrapModule from "../src/core/kernel/bootstrap.js";
import { DEFAULT_RLM_EXTRA_UV_ARGS, resolveRuntimeIdentity } from "../src/core/kernel/bootstrap.js";
import { ModelRegistry } from "../src/core/model-registry.js";
import { SessionManager } from "../src/core/session-manager.js";
import { SettingsManager } from "../src/core/settings-manager.js";
import { IpythonKernelProvisioner } from "../src/core/tools/ipython.js";
import { createIpythonTool } from "../src/index.js";
import { createTestResourceLoader } from "./utilities.js";

// Mirrors bootstrap.ts's own (unexported) venvPythonPath.
function venvPythonPath(venv: string): string {
	return process.platform === "win32" ? join(venv, "Scripts", "python.exe") : join(venv, "bin", "python");
}

function writeVenvPython(venv: string): void {
	const python = venvPythonPath(venv);
	mkdirSync(join(venv, process.platform === "win32" ? "Scripts" : "bin"), { recursive: true });
	writeFileSync(python, "");
	if (process.platform !== "win32") chmodSync(python, 0o755);
}

function writeBootstrapVersion(venv: string, runtimeIdentity: string): void {
	writeFileSync(
		join(venv, ".bootstrap-version"),
		`${JSON.stringify({
			schema: 8,
			ipykernel: "ipykernel",
			runtime: runtimeIdentity,
			snapshot: "dill",
			extraUvArgs: DEFAULT_RLM_EXTRA_UV_ARGS,
			pythonSkills: [],
		})}\n`,
	);
}

let tempDir = "";
let originalEnv: NodeJS.ProcessEnv;

function createSessionWithPrewarm(): AgentSession {
	const model = getModel("anthropic", "claude-sonnet-4-5")!;
	const agent = new Agent({
		getApiKey: () => undefined,
		initialState: {
			model,
			systemPrompt: "You are a helpful assistant.",
			tools: [createIpythonTool(process.cwd())],
		},
	});
	const sessionManager = SessionManager.inMemory();
	const settingsManager = SettingsManager.create(tempDir, tempDir);
	const authStorage = AuthStorage.create(join(tempDir, "auth.json"));
	const modelRegistry = ModelRegistry.create(authStorage, tempDir);

	const session = new AgentSession({
		agent,
		sessionManager,
		settingsManager,
		cwd: tempDir,
		modelRegistry,
		resourceLoader: createTestResourceLoader(),
		prewarmIpythonKernel: true,
	});
	session.subscribe(() => {});
	return session;
}

describe("agent-session ipython prewarm gating", () => {
	let prewarmSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		originalEnv = { ...process.env };
		tempDir = mkdtempSync(join(tmpdir(), "prime-agent-prewarm-gate-"));
		process.env.HOME = tempDir;
		delete process.env.ZERO_KERNEL_PYTHON;
		delete process.env.XDG_DATA_HOME;
		prewarmSpy = vi.spyOn(IpythonKernelProvisioner.prototype, "prewarm").mockImplementation(() => {});
	});

	afterEach(() => {
		prewarmSpy.mockRestore();
		process.env = originalEnv;
		if (tempDir) {
			rmSync(tempDir, { recursive: true, force: true });
			tempDir = "";
		}
	});

	it("does not eagerly prewarm when there is no cached kernel venv", async () => {
		const venv = join(tempDir, "kernel-venv");
		process.env.ZERO_KERNEL_VENV = venv;
		const cachedCheckSpy = vi.spyOn(bootstrapModule, "isKernelPythonLikelyCached");

		const session = createSessionWithPrewarm();
		try {
			expect(cachedCheckSpy).toHaveBeenCalledTimes(1);
			// Await the exact promise the prewarm gate itself is awaiting, so the
			// assertion below runs after the gate has settled (not after some
			// arbitrary timeout that might race a slow first-run resolveRuntimeIdentity()
			// hash). The gate's own `.then()` was registered first (synchronously,
			// during construction), so it always runs before this continuation.
			await cachedCheckSpy.mock.results[0]?.value;
			expect(prewarmSpy).not.toHaveBeenCalled();
		} finally {
			session.dispose();
		}
	});

	it("eagerly prewarms when the kernel venv is already cached and current", async () => {
		const venv = join(tempDir, "kernel-venv");
		process.env.ZERO_KERNEL_VENV = venv;
		writeVenvPython(venv);
		writeBootstrapVersion(venv, await resolveRuntimeIdentity());

		const session = createSessionWithPrewarm();
		try {
			await vi.waitFor(() => {
				expect(prewarmSpy).toHaveBeenCalled();
			});
		} finally {
			session.dispose();
		}
	});
});
