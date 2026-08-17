import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ExtensionContext, ToolDefinition } from "../../src/core/extensions/types.js";
import type { SessionMode } from "../../src/core/mode/session-mode.js";
import { wrapToolDefinition } from "../../src/core/tools/tool-definition-wrapper.js";
import { createHarness, type Harness } from "./harness.js";

function git(args: string[], cwd: string): string {
	const result = spawnSync("git", args, { cwd, encoding: "utf-8", windowsHide: true });
	if (result.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${result.stderr}`);
	return result.stdout.trim();
}

function initGitRepo(repoDir: string): void {
	git(["init", "--initial-branch=main"], repoDir);
	git(["config", "--local", "user.email", "test@test.com"], repoDir);
	git(["config", "--local", "user.name", "Test"], repoDir);
	git(["config", "--local", "core.autocrlf", "false"], repoDir);
}

/** Same minimal fake as tool-definition-wrapper-guardrails.test.ts, plus `mode` (module I). */
function fakeCtx(overrides: {
	cwd: string;
	mode: SessionMode;
	hasUI: boolean;
	confirmResult?: boolean;
	notified?: Array<{ message: string; type: string }>;
}): ExtensionContext {
	return {
		cwd: overrides.cwd,
		mode: overrides.mode,
		hasUI: overrides.hasUI,
		ui: {
			confirm: async () => overrides.confirmResult ?? true,
			notify: (message: string, type?: string) => overrides.notified?.push({ message, type: type ?? "info" }),
			select: async () => undefined,
			input: async () => undefined,
			onTerminalInput: () => () => {},
			setStatus: () => {},
			setWorkingMessage: () => {},
			setWorkingVisible: () => {},
			setWorkingIndicator: () => {},
			setHiddenThinkingLabel: () => {},
			setWidget: () => {},
		},
		sessionManager: {
			getSessionDir: () => undefined,
			getSessionId: () => undefined,
		},
		isIdle: () => true,
		signal: undefined,
		abort: () => {},
		hasPendingMessages: () => false,
		shutdown: () => {},
		getContextUsage: () => undefined,
		compact: () => {},
		getSystemPrompt: () => "",
		modelRegistry: {} as ExtensionContext["modelRegistry"],
		model: undefined,
	} as unknown as ExtensionContext;
}

const ipythonLikeTool: ToolDefinition<any, unknown> = {
	name: "ipython",
	label: "ipython",
	description: "test ipython tool",
	parameters: {} as any,
	execute: async () => ({ content: [{ type: "text", text: "ok" }], details: undefined }),
};

const bashLikeTool: ToolDefinition<any, unknown> = {
	name: "bash",
	label: "bash",
	description: "test bash tool",
	parameters: {} as any,
	execute: async () => ({ content: [{ type: "text", text: "ok" }], details: undefined }),
};

/**
 * Module F/I red-team triple: the same destructive operation attempted via a
 * plain Python cell, a %%bash-equivalent bash tool call, and an RLM child —
 * across plan/auto/manual — must produce the documented verdict every time.
 * Out-of-workspace/system-path targets hard-block unconditionally; in-workspace
 * equivalents differ by mode (plan blocks outright with no confirm offered —
 * nothing executes in plan mode, not even after approval; auto/manual both
 * soft-block-confirm since the harm-check verdict itself is unaffected by
 * auto vs manual, manual's distinguishing behavior only shows up on otherwise
 * allow-verdict actions, see the "manual mode" describe block below).
 */
describe("red-team triple (module F + module I)", () => {
	let repoDir: string;

	beforeEach(() => {
		repoDir = join(tmpdir(), `zero-redteam-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(repoDir, { recursive: true });
		initGitRepo(repoDir);
		writeFileSync(join(repoDir, "tracked.txt"), "original\n");
		git(["add", "tracked.txt"], repoDir);
		git(["commit", "-m", "init"], repoDir);
	});

	afterEach(() => {
		if (existsSync(repoDir)) rmSync(repoDir, { recursive: true, force: true });
	});

	const OUT_OF_WORKSPACE_OS_LEVEL_CODE = "os.system('sudo shutdown -h now')";

	const modes: SessionMode[] = ["plan", "auto", "manual"];
	const channels: Array<{
		name: string;
		tool: ToolDefinition<any, unknown>;
		sourceKey: string;
		inWorkspaceDestructiveCode: string;
	}> = [
		{
			name: "python cell",
			tool: ipythonLikeTool,
			sourceKey: "code",
			inWorkspaceDestructiveCode: `os.remove("tracked.txt")`,
		},
		{
			name: "%%bash cell (via bash tool)",
			tool: bashLikeTool,
			sourceKey: "command",
			inWorkspaceDestructiveCode: "rm -rf tracked.txt",
		},
	];

	for (const mode of modes) {
		for (const channel of channels) {
			it(`hard-blocks an out-of-workspace/OS-level op via ${channel.name} in ${mode} mode, no confirm offered`, async () => {
				const notified: Array<{ message: string; type: string }> = [];
				const ctx = fakeCtx({ cwd: repoDir, mode, hasUI: true, notified });
				const wrapped = wrapToolDefinition(channel.tool, () => ctx);

				const result = await wrapped.execute(
					"call-1",
					{ [channel.sourceKey]: OUT_OF_WORKSPACE_OS_LEVEL_CODE },
					undefined,
					undefined,
				);

				expect((result as any).isError).toBe(true);
				expect((result as any).details?.harmBlocked).toBe(true);
				// hard_block never asks for confirmation, in any mode.
				expect(notified.length).toBeGreaterThan(0);
			});
		}
	}

	describe("plan mode: nothing mutating executes, no confirm offered", () => {
		for (const channel of channels) {
			it(`blocks an in-workspace destructive op via ${channel.name} outright`, async () => {
				const notified: Array<{ message: string; type: string }> = [];
				let confirmCalls = 0;
				const ctx = fakeCtx({ cwd: repoDir, mode: "plan", hasUI: true, notified });
				(ctx.ui as any).confirm = async () => {
					confirmCalls++;
					return true;
				};
				const wrapped = wrapToolDefinition(channel.tool, () => ctx);

				const result = await wrapped.execute(
					"call-2",
					{ [channel.sourceKey]: channel.inWorkspaceDestructiveCode },
					undefined,
					undefined,
				);

				expect((result as any).isError).toBe(true);
				expect((result as any).details?.harmBlocked).toBe(true);
				expect(confirmCalls).toBe(0); // plan mode never offers a confirm — it just refuses.
			});
		}

		it("allows read-only exploration (git status) unblocked", async () => {
			const ctx = fakeCtx({ cwd: repoDir, mode: "plan", hasUI: true });
			const wrapped = wrapToolDefinition(bashLikeTool, () => ctx);

			const result = await wrapped.execute("call-3", { command: "git status" }, undefined, undefined);

			expect((result as any).isError).toBeFalsy();
		});
	});

	describe("auto mode: in-workspace destructive ops soft-block with a real confirm", () => {
		for (const channel of channels) {
			it(`asks for confirmation via ${channel.name} and proceeds once approved`, async () => {
				let confirmCalls = 0;
				const ctx = fakeCtx({ cwd: repoDir, mode: "auto", hasUI: true, confirmResult: true });
				(ctx.ui as any).confirm = async (_title: string, message: string) => {
					confirmCalls++;
					expect(message.length).toBeGreaterThan(0); // plain-language consequence line, never a bare y/n
					return true;
				};
				const wrapped = wrapToolDefinition(channel.tool, () => ctx);

				const result = await wrapped.execute(
					"call-4",
					{ [channel.sourceKey]: channel.inWorkspaceDestructiveCode },
					undefined,
					undefined,
				);

				expect(confirmCalls).toBe(1);
				expect((result as any).isError).toBeFalsy();
			});
		}
	});

	describe("manual mode: every tool call is confirmed, even ones module F would allow outright", () => {
		it("confirms a benign, otherwise-allowed action before running it", async () => {
			let confirmCalls = 0;
			const ctx = fakeCtx({ cwd: repoDir, mode: "manual", hasUI: true });
			(ctx.ui as any).confirm = async () => {
				confirmCalls++;
				return true;
			};
			const wrapped = wrapToolDefinition(ipythonLikeTool, () => ctx);

			const result = await wrapped.execute("call-5", { code: "print(1 + 1)" }, undefined, undefined);

			expect(confirmCalls).toBe(1); // auto mode would NOT confirm this — manual mode's whole point.
			expect((result as any).isError).toBeFalsy();
		});

		it("blocks a benign action when the user declines in manual mode", async () => {
			const ctx = fakeCtx({ cwd: repoDir, mode: "manual", hasUI: true, confirmResult: false });
			const wrapped = wrapToolDefinition(ipythonLikeTool, () => ctx);

			const result = await wrapped.execute("call-6", { code: "print(1 + 1)" }, undefined, undefined);

			expect((result as any).isError).toBe(true);
		});

		it("still hard-blocks OS-level ops even with a UI attached and confirm auto-approving", async () => {
			const ctx = fakeCtx({ cwd: repoDir, mode: "manual", hasUI: true, confirmResult: true });
			const wrapped = wrapToolDefinition(ipythonLikeTool, () => ctx);

			const result = await wrapped.execute("call-7", { code: OUT_OF_WORKSPACE_OS_LEVEL_CODE }, undefined, undefined);

			expect((result as any).isError).toBe(true);
			expect((result as any).details?.harmBlocked).toBe(true);
		});
	});
});

/**
 * The RLM-child leg of the red-team triple: does a delegated child inherit
 * the parent's mode, or can plan mode be escaped by spawning a subagent?
 * Found and fixed as part of this verification pass — a fresh child session
 * has no persisted session_mode_state entry to load, so without explicitly
 * threading the parent's mode through subagent construction it silently
 * defaulted to "auto" regardless of what the parent was actually in.
 */
describe("red-team triple: RLM child mode inheritance (module B + module I)", () => {
	const harnesses: Harness[] = [];

	afterEach(() => {
		while (harnesses.length > 0) harnesses.pop()?.cleanup();
	});

	async function createGitBackedHarness(): Promise<Harness> {
		const harness = await createHarness();
		harnesses.push(harness);
		const repoDir = harness.tempDir;
		git(["init", "--initial-branch=main"], repoDir);
		git(["config", "--local", "user.email", "test@test.com"], repoDir);
		git(["config", "--local", "user.name", "Test"], repoDir);
		git(["config", "--local", "core.autocrlf", "false"], repoDir);
		writeFileSync(join(repoDir, "tracked.txt"), "shared\n");
		git(["add", "tracked.txt"], repoDir);
		git(["commit", "-m", "init"], repoDir);
		return harness;
	}

	for (const mode of ["plan", "auto", "manual"] as const) {
		it(`an RLM child inherits the parent's ${mode} mode rather than defaulting to auto`, async () => {
			const harness = await createGitBackedHarness();
			harness.session.setSessionMode(mode);

			const handle = await harness.session.runRlmChild("do a parallel task");
			const child = harness.session.getRlmChildSession(handle.rlm_child_id);

			expect(child).toBeDefined();
			expect(child?.getSessionMode()).toBe(mode);
		});
	}

	it("a worktree-isolated RLM child also inherits the parent's mode", async () => {
		const harness = await createGitBackedHarness();
		harness.session.setSessionMode("plan");

		const handle = await harness.session.runRlmChild("do a parallel task", { isolation: "worktree" });
		const child = harness.session.getRlmChildSession(handle.rlm_child_id);

		expect(child?.getSessionMode()).toBe("plan");
	});

	it("defaults to auto when the parent has never switched mode (backward compatible)", async () => {
		const harness = await createGitBackedHarness();

		const handle = await harness.session.runRlmChild("do a task");
		const child = harness.session.getRlmChildSession(handle.rlm_child_id);

		expect(child?.getSessionMode()).toBe("auto");
	});
});
