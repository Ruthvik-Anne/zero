import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ENV_AGENT_DIR } from "../src/config.js";
import { hasAnyCheckpoint } from "../src/core/checkpoint/checkpoint.js";
import type { ExtensionContext, ToolDefinition, VaultPlaceholderResolver } from "../src/core/extensions/types.js";
import { getLocalHarnessStateDir, loadHarnessState } from "../src/core/refinement/refinement.js";
import { getSessionArtifactPath } from "../src/core/session-manager.js";
import { wrapToolDefinition } from "../src/core/tools/tool-definition-wrapper.js";
import {
	resolveVaultPlaceholders,
	scrubKnownSecrets,
	storeCredential,
	VaultTokenRegistry,
} from "../src/core/vault/vault.js";

/** Mirrors the real `runner.bindVault(...)` binding in agent-session.ts (task #78/#84), for tests that construct a fake ctx.vault directly instead of going through a full AgentSession harness. */
function fakeVaultResolver(projectRoot: string, registry: VaultTokenRegistry): VaultPlaceholderResolver {
	return {
		resolvePlaceholders: (text) => resolveVaultPlaceholders(text, projectRoot, registry),
		scrubKnownSecrets: (text) => scrubKnownSecrets(text, registry, projectRoot),
	};
}

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

/** Minimal fake ExtensionContext exercising only what the guard actually touches. */
function fakeCtx(overrides: {
	cwd: string;
	sessionDir: string;
	sessionId: string;
	hasUI: boolean;
	confirmResult?: boolean;
	mode?: "plan" | "auto" | "manual";
	allowRiskyActions?: boolean;
}): ExtensionContext {
	return {
		cwd: overrides.cwd,
		hasUI: overrides.hasUI,
		mode: overrides.mode,
		allowRiskyActions: overrides.allowRiskyActions,
		ui: {
			confirm: async () => overrides.confirmResult ?? true,
			notify: () => {},
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
			getSessionDir: () => overrides.sessionDir,
			getSessionId: () => overrides.sessionId,
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
	execute: async (_toolCallId, _params, _signal, _onUpdate, _ctx) => ({
		content: [{ type: "text", text: "ok" }],
		details: undefined,
	}),
};

const editLikeTool: ToolDefinition<any, unknown> = {
	name: "edit",
	label: "edit",
	description: "test edit tool",
	parameters: {} as any,
	execute: async (_toolCallId, _params, _signal, _onUpdate, _ctx) => ({
		content: [{ type: "text", text: "edited" }],
		details: undefined,
	}),
};

describe("tool-definition-wrapper guardrail integration (modules F + H)", () => {
	let repoDir: string;
	let sessionDir: string;
	let agentDir: string;
	const previousAgentDir = process.env[ENV_AGENT_DIR];

	beforeEach(() => {
		repoDir = join(tmpdir(), `zero-wrapper-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(repoDir, { recursive: true });
		initGitRepo(repoDir);
		writeFileSync(join(repoDir, "tracked.txt"), "original\n");
		git(["add", "tracked.txt"], repoDir);
		git(["commit", "-m", "init"], repoDir);
		sessionDir = join(repoDir, "sessions");
		mkdirSync(sessionDir, { recursive: true });
		// task #78 vault tests below store a real credential — redirect the
		// machine-key directory away from the real ~/.zero/agent/vault-keys/.
		agentDir = join(repoDir, "agent-dir");
		mkdirSync(agentDir, { recursive: true });
		process.env[ENV_AGENT_DIR] = agentDir;
	});

	afterEach(() => {
		if (previousAgentDir === undefined) {
			delete process.env[ENV_AGENT_DIR];
		} else {
			process.env[ENV_AGENT_DIR] = previousAgentDir;
		}
		if (existsSync(repoDir)) rmSync(repoDir, { recursive: true, force: true });
	});

	async function readAuditLog(): Promise<Array<{ type: string; detail: Record<string, unknown> }>> {
		const auditPath = join(getSessionArtifactPath(sessionDir, "sess-1"), "audit", "audit.jsonl");
		if (!existsSync(auditPath)) return [];
		return (await readFile(auditPath, "utf8"))
			.trim()
			.split("\n")
			.filter(Boolean)
			.map((l) => JSON.parse(l));
	}

	it("allows benign code, logs an allow verdict and a tool_call entry, and creates no checkpoint", async () => {
		const ctx = fakeCtx({ cwd: repoDir, sessionDir, sessionId: "sess-1", hasUI: true });
		const wrapped = wrapToolDefinition(ipythonLikeTool, () => ctx);

		const result = await wrapped.execute("call-1", { code: "print(1)" }, undefined, undefined);

		expect((result as any).isError).toBeFalsy();
		expect(hasAnyCheckpoint(repoDir)).toBe(false);
		const log = await readAuditLog();
		expect(log.some((e) => e.type === "harm_verdict" && e.detail.action === "allow")).toBe(true);
		expect(log.some((e) => e.type === "tool_call" && e.detail.outcome === "ok")).toBe(true);
	});

	it("soft-blocks a workspace-contained destructive command, and creates a checkpoint once approved", async () => {
		const ctx = fakeCtx({ cwd: repoDir, sessionDir, sessionId: "sess-1", hasUI: true, confirmResult: true });
		const wrapped = wrapToolDefinition(ipythonLikeTool, () => ctx);

		const result = await wrapped.execute(
			"call-2",
			{ code: `os.remove("${repoDir.replace(/\\/g, "\\\\")}\\\\tracked.txt")` },
			undefined,
			undefined,
		);

		expect((result as any).isError).toBeFalsy(); // approved, so the underlying tool ran
		expect(hasAnyCheckpoint(repoDir)).toBe(true);
		const log = await readAuditLog();
		expect(log.some((e) => e.type === "harm_verdict" && e.detail.action === "soft_block")).toBe(true);
	});

	it("refuses when the user declines a soft-block confirmation, and does not create a checkpoint", async () => {
		const ctx = fakeCtx({ cwd: repoDir, sessionDir, sessionId: "sess-1", hasUI: true, confirmResult: false });
		const wrapped = wrapToolDefinition(ipythonLikeTool, () => ctx);

		const result = await wrapped.execute(
			"call-3",
			{ code: `os.remove("${repoDir.replace(/\\/g, "\\\\")}\\\\tracked.txt")` },
			undefined,
			undefined,
		);

		expect((result as any).isError).toBe(true);
		expect(hasAnyCheckpoint(repoDir)).toBe(false);
	});

	it("hard-blocks an OS-level command with no confirmation offered", async () => {
		const ctx = fakeCtx({ cwd: repoDir, sessionDir, sessionId: "sess-1", hasUI: true });
		const wrapped = wrapToolDefinition(ipythonLikeTool, () => ctx);

		const result = await wrapped.execute(
			"call-4",
			{ code: "os.system('sudo shutdown -h now')" },
			undefined,
			undefined,
		);

		expect((result as any).isError).toBe(true);
		const log = await readAuditLog();
		expect(log.some((e) => e.type === "harm_verdict" && e.detail.action === "hard_block")).toBe(true);
	});

	it("records a durable guardrail precedent entry (module C) for a hard-blocked action", async () => {
		const ctx = fakeCtx({ cwd: repoDir, sessionDir, sessionId: "sess-1", hasUI: true });
		const wrapped = wrapToolDefinition(ipythonLikeTool, () => ctx);

		await wrapped.execute("call-5", { code: "os.system('sudo shutdown -h now')" }, undefined, undefined);

		const harnessStateDir = getLocalHarnessStateDir(getSessionArtifactPath(sessionDir, "sess-1"));
		const state = loadHarnessState(harnessStateDir!, "local");
		const guardrailEntries = Object.values(state.entries.guardrail);
		expect(guardrailEntries).toHaveLength(1);
		expect(guardrailEntries[0].metadata.lastAction).toBe("hard_block");
		expect(guardrailEntries[0].metadata.toolName).toBe("ipython");
	});

	it("increments occurrence count instead of duplicating on a repeated identical flag", async () => {
		const ctx = fakeCtx({ cwd: repoDir, sessionDir, sessionId: "sess-1", hasUI: true, confirmResult: true });
		const wrapped = wrapToolDefinition(ipythonLikeTool, () => ctx);
		const code = `os.remove("${repoDir.replace(/\\/g, "\\\\")}\\\\tracked.txt")`;

		await wrapped.execute("call-6", { code }, undefined, undefined);
		await wrapped.execute("call-7", { code }, undefined, undefined);

		const harnessStateDir = getLocalHarnessStateDir(getSessionArtifactPath(sessionDir, "sess-1"));
		const state = loadHarnessState(harnessStateDir!, "local");
		const guardrailEntries = Object.values(state.entries.guardrail);
		expect(guardrailEntries).toHaveLength(1);
		expect(guardrailEntries[0].metadata.occurrences).toBe(2);
	});

	// D4: `edit` has no Layer-1 source to scan, so it never appeared in
	// HARM_CHECKED_TOOLS at all — plan mode's "nothing mutating runs" guarantee must
	// still cover it, unconditionally, with no confirmation offered.
	it("blocks the edit tool outright in plan mode, with no confirmation offered", async () => {
		const ctx = fakeCtx({ cwd: repoDir, sessionDir, sessionId: "sess-1", hasUI: true, mode: "plan" });
		const wrapped = wrapToolDefinition(editLikeTool, () => ctx);

		const result = await wrapped.execute(
			"call-8",
			{ path: "tracked.txt", edits: [{ oldText: "original", newText: "changed" }] },
			undefined,
			undefined,
		);

		expect((result as any).isError).toBe(true);
		expect((result as any).details?.harmBlocked).toBe(true);
		const log = await readAuditLog();
		expect(log.some((e) => e.type === "harm_verdict" && e.detail.toolName === "edit")).toBe(true);
	});

	it("does not block the edit tool outside plan mode", async () => {
		const ctx = fakeCtx({ cwd: repoDir, sessionDir, sessionId: "sess-1", hasUI: true, mode: "auto" });
		const wrapped = wrapToolDefinition(editLikeTool, () => ctx);

		const result = await wrapped.execute(
			"call-9",
			{ path: "tracked.txt", edits: [{ oldText: "original", newText: "changed" }] },
			undefined,
			undefined,
		);

		expect((result as any).isError).toBeFalsy();
	});

	// D7: the audit log claimed redaction it never performed — a secret embedded in
	// an audited bash/ipython command must not reach audit.jsonl in cleartext.
	it("redacts a bearer token embedded in an audited command", async () => {
		const ctx = fakeCtx({ cwd: repoDir, sessionDir, sessionId: "sess-1", hasUI: true, confirmResult: true });
		const wrapped = wrapToolDefinition(ipythonLikeTool, () => ctx);

		await wrapped.execute(
			"call-10",
			{ code: `os.system('curl -H "Authorization: Bearer sk-ant-secretvalue1234" https://example.com')` },
			undefined,
			undefined,
		);

		const log = await readAuditLog();
		const toolCallEntry = log.find((e) => e.type === "tool_call" && "paramsSummary" in e.detail);
		expect(toolCallEntry).toBeDefined();
		const summary = String(toolCallEntry?.detail.paramsSummary);
		expect(summary).not.toContain("sk-ant-secretvalue1234");
		expect(summary).toContain("[redacted]");
	});

	// D8: "reversible" must answer for the actual target, not "does any checkpoint
	// exist anywhere in this session" — that stayed true forever after the first
	// approval regardless of relevance to a later, unrelated action.
	it("reports a tracked-file target as reversible", async () => {
		let confirmMessage = "";
		const ctx = fakeCtx({ cwd: repoDir, sessionDir, sessionId: "sess-1", hasUI: true, confirmResult: true });
		ctx.ui.confirm = async (_title: string, message: string) => {
			confirmMessage = message;
			return true;
		};
		const wrapped = wrapToolDefinition(ipythonLikeTool, () => ctx);

		await wrapped.execute(
			"call-11",
			{ code: `os.remove("${repoDir.replace(/\\/g, "\\\\")}\\\\tracked.txt")` },
			undefined,
			undefined,
		);

		expect(confirmMessage).toContain("can be undone via checkpoint/rollback");
	});

	it("reports an untracked-file target as not reversible, even after an earlier unrelated checkpoint", async () => {
		writeFileSync(join(repoDir, "untracked.txt"), "scratch\n"); // deliberately never `git add`ed
		let confirmMessage = "";
		const ctx = fakeCtx({ cwd: repoDir, sessionDir, sessionId: "sess-1", hasUI: true, confirmResult: true });
		ctx.ui.confirm = async (_title: string, message: string) => {
			confirmMessage = message;
			return true;
		};
		const wrapped = wrapToolDefinition(ipythonLikeTool, () => ctx);

		// An unrelated earlier soft-block approval creates a checkpoint — under the
		// old hasAnyCheckpoint() check this alone would make every later action
		// "reversible", regardless of whether it actually covers the new target.
		await wrapped.execute(
			"call-12",
			{ code: `os.remove("${repoDir.replace(/\\/g, "\\\\")}\\\\tracked.txt")` },
			undefined,
			undefined,
		);
		expect(hasAnyCheckpoint(repoDir)).toBe(true);

		await wrapped.execute(
			"call-13",
			{ code: `os.remove("${repoDir.replace(/\\/g, "\\\\")}\\\\untracked.txt")` },
			undefined,
			undefined,
		);

		expect(confirmMessage).toContain("cannot be undone");
	});

	// D10: a UI context being bound (hasUI: true — what module J's MCP task
	// sessions do, so ask_user can function) must NOT by itself let a soft-block
	// confirmation round-trip to an unverifiable remote answerer.
	it("fails closed on a soft-block when hasUI is true but allowRiskyActions is explicitly false", async () => {
		let confirmCalled = false;
		const ctx = fakeCtx({
			cwd: repoDir,
			sessionDir,
			sessionId: "sess-1",
			hasUI: true,
			confirmResult: true,
			allowRiskyActions: false,
		});
		ctx.ui.confirm = async () => {
			confirmCalled = true;
			return true;
		};
		const wrapped = wrapToolDefinition(ipythonLikeTool, () => ctx);

		const result = await wrapped.execute(
			"call-14",
			{ code: `os.remove("${repoDir.replace(/\\/g, "\\\\")}\\\\tracked.txt")` },
			undefined,
			undefined,
		);

		expect((result as any).isError).toBe(true);
		expect(confirmCalled).toBe(false);
		const log = await readAuditLog();
		const verdictEntry = log.find((e) => e.type === "harm_verdict" && e.detail.action === "soft_block");
		expect(verdictEntry?.detail.allowRiskyActions).toBe(false);
	});

	it("still confirms a soft-block normally when allowRiskyActions is left unset", async () => {
		const ctx = fakeCtx({ cwd: repoDir, sessionDir, sessionId: "sess-1", hasUI: true, confirmResult: true });
		const wrapped = wrapToolDefinition(ipythonLikeTool, () => ctx);

		const result = await wrapped.execute(
			"call-15",
			{ code: `os.remove("${repoDir.replace(/\\/g, "\\\\")}\\\\tracked.txt")` },
			undefined,
			undefined,
		);

		expect((result as any).isError).toBeFalsy();
	});

	it("does not gate a hard-block behind allowRiskyActions — it stays unconditional", async () => {
		const ctx = fakeCtx({
			cwd: repoDir,
			sessionDir,
			sessionId: "sess-1",
			hasUI: true,
			allowRiskyActions: true,
		});
		const wrapped = wrapToolDefinition(ipythonLikeTool, () => ctx);

		const result = await wrapped.execute(
			"call-16",
			{ code: "os.system('sudo shutdown -h now')" },
			undefined,
			undefined,
		);

		expect((result as any).isError).toBe(true);
		const log = await readAuditLog();
		expect(log.some((e) => e.type === "harm_verdict" && e.detail.action === "hard_block")).toBe(true);
	});

	// task #78: vault placeholder substitution must run strictly AFTER harm-check
	// has already scanned the placeholder-only text — never before.
	describe("vault placeholder substitution (task #78)", () => {
		function bashLikeTool(onExecute: (command: string) => void): ToolDefinition<any, unknown> {
			return {
				name: "bash",
				label: "bash",
				description: "test bash tool",
				parameters: {} as any,
				execute: async (_toolCallId, params) => {
					onExecute((params as { command: string }).command);
					return { content: [{ type: "text", text: "ok" }], details: undefined };
				},
			};
		}

		it("allows a placeholder-only command whose decrypted plaintext would itself be hard-blocked — proving harm-check saw only the placeholder", async () => {
			// If substitution ran BEFORE harm-check, Layer 1 would see "sudo shutdown
			// -h now" (an os-level hard-block pattern) and refuse the call outright.
			await storeCredential(repoDir, "danger", "sudo shutdown -h now");
			const registry = new VaultTokenRegistry();
			const token = registry.issue("danger");

			let receivedCommand: string | undefined;
			const ctx = {
				...fakeCtx({ cwd: repoDir, sessionDir, sessionId: "sess-1", hasUI: true }),
				vault: fakeVaultResolver(repoDir, registry),
			};
			const wrapped = wrapToolDefinition(
				bashLikeTool((command) => {
					receivedCommand = command;
				}),
				() => ctx,
			);

			const result = await wrapped.execute("call-vault-1", { command: token }, undefined, undefined);

			expect((result as any).isError).toBeFalsy();
			const log = await readAuditLog();
			expect(log.some((e) => e.type === "harm_verdict" && e.detail.action === "hard_block")).toBe(false);

			// Substitution DID happen: the underlying tool received the real secret.
			expect(receivedCommand).toBe("sudo shutdown -h now");
		});

		it("audits the pre-substitution placeholder text, never the resolved secret", async () => {
			await storeCredential(repoDir, "stripe_api_key", "sk-live-secret-value");
			const registry = new VaultTokenRegistry();
			const token = registry.issue("stripe_api_key");

			const ctx = {
				...fakeCtx({ cwd: repoDir, sessionDir, sessionId: "sess-1", hasUI: true }),
				vault: fakeVaultResolver(repoDir, registry),
			};
			const wrapped = wrapToolDefinition(
				bashLikeTool(() => {}),
				() => ctx,
			);

			await wrapped.execute(
				"call-vault-2",
				{ command: `curl -H "Authorization: Bearer ${token}"` },
				undefined,
				undefined,
			);

			const log = await readAuditLog();
			const toolCallEntry = log.find((e) => e.type === "tool_call" && "paramsSummary" in e.detail);
			expect(String(toolCallEntry?.detail.paramsSummary)).not.toContain("sk-live-secret-value");
			expect(String(toolCallEntry?.detail.paramsSummary)).toContain(token);
		});

		it("does not substitute a fabricated/mismatched token, leaving it as literal text", async () => {
			await storeCredential(repoDir, "stripe_api_key", "sk-live-secret-value");
			const registry = new VaultTokenRegistry();
			registry.issue("stripe_api_key"); // a real token is issued, but we never use it below
			const fabricated = "zero-cred://stripe_api_key/deadbeefdeadbeefdeadbeef";

			let receivedCommand: string | undefined;
			const ctx = {
				...fakeCtx({ cwd: repoDir, sessionDir, sessionId: "sess-1", hasUI: true }),
				vault: fakeVaultResolver(repoDir, registry),
			};
			const wrapped = wrapToolDefinition(
				bashLikeTool((command) => {
					receivedCommand = command;
				}),
				() => ctx,
			);

			await wrapped.execute("call-vault-3", { command: `echo ${fabricated}` }, undefined, undefined);

			expect(receivedCommand).toBe(`echo ${fabricated}`);
			expect(receivedCommand).not.toContain("sk-live-secret-value");
		});
	});

	// task #84: a substituted command's OWN OUTPUT can echo the resolved secret
	// back — the harm-check/substitution boundary above only ever sees the
	// placeholder-only SOURCE, never this. A post-execution scrub is the only
	// thing standing between that echoed plaintext and the returned result
	// (and, via the tool_call audit entry right after, the audit log).
	describe("output scrubbing of resolved secrets (task #84)", () => {
		it("scrubs a resolved secret echoed back in the tool result's content before it is returned", async () => {
			await storeCredential(repoDir, "stripe_api_key", "sk-live-secret-value");
			const registry = new VaultTokenRegistry();
			const token = registry.issue("stripe_api_key");

			const echoingTool: ToolDefinition<any, unknown> = {
				name: "bash",
				label: "bash",
				description: "test bash tool that echoes its resolved input back",
				parameters: {} as any,
				execute: async (_toolCallId, params) => ({
					content: [{ type: "text", text: `ran: ${(params as { command: string }).command}` }],
					details: undefined,
				}),
			};
			const ctx = {
				...fakeCtx({ cwd: repoDir, sessionDir, sessionId: "sess-1", hasUI: true }),
				vault: fakeVaultResolver(repoDir, registry),
			};
			const wrapped = wrapToolDefinition(echoingTool, () => ctx);

			const result = await wrapped.execute("call-vault-4", { command: token }, undefined, undefined);

			const text = (result as any).content[0].text as string;
			expect(text).not.toContain("sk-live-secret-value");
			expect(text).toBe(`ran: ${token}`);
		});

		it("scrubs a resolved secret echoed back in the tool result's details (e.g. ipython-style stdout) too", async () => {
			await storeCredential(repoDir, "stripe_api_key", "sk-live-secret-value");
			const registry = new VaultTokenRegistry();
			const token = registry.issue("stripe_api_key");

			const echoingIpythonLikeTool: ToolDefinition<any, { stdout: string }> = {
				name: "ipython",
				label: "ipython",
				description: "test ipython tool that echoes its resolved code back into stdout",
				parameters: {} as any,
				execute: async (_toolCallId, params) => ({
					content: [{ type: "text", text: "" }],
					details: { stdout: `printed: ${(params as { code: string }).code}` },
				}),
			};
			const ctx = {
				...fakeCtx({ cwd: repoDir, sessionDir, sessionId: "sess-1", hasUI: true }),
				vault: fakeVaultResolver(repoDir, registry),
			};
			const wrapped = wrapToolDefinition(echoingIpythonLikeTool, () => ctx);

			const result = await wrapped.execute("call-vault-5", { code: token }, undefined, undefined);

			expect((result as any).details.stdout).not.toContain("sk-live-secret-value");
			expect((result as any).details.stdout).toBe(`printed: ${token}`);
		});

		it("does not scrub anything, and adds no overhead path, when ctx.vault is unbound", async () => {
			const ctx = fakeCtx({ cwd: repoDir, sessionDir, sessionId: "sess-1", hasUI: true });
			const tool: ToolDefinition<any, unknown> = {
				name: "bash",
				label: "bash",
				description: "test bash tool",
				parameters: {} as any,
				execute: async () => ({
					content: [{ type: "text", text: "sk-live-secret-value" }],
					details: undefined,
				}),
			};
			const wrapped = wrapToolDefinition(tool, () => ctx);

			const result = await wrapped.execute("call-vault-6", { command: "echo hi" }, undefined, undefined);

			// No vault bound at all -> nothing to scrub against -> left exactly as returned.
			expect((result as any).content[0].text).toBe("sk-live-secret-value");
		});
	});
});
