import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ENV_AGENT_DIR } from "../../src/config.js";
import type { ExtensionUIContext } from "../../src/core/extensions/types.js";
import { wrapToolDefinition } from "../../src/core/tools/tool-definition-wrapper.js";
import { getCredential } from "../../src/core/vault/vault.js";
import { createHarness, type Harness } from "./harness.js";

function fakeUI(overrides: Partial<ExtensionUIContext> = {}): ExtensionUIContext {
	return {
		select: vi.fn(async () => undefined),
		confirm: vi.fn(async () => true),
		input: vi.fn(async () => undefined),
		notify: vi.fn(),
		onTerminalInput: vi.fn(() => () => {}),
		setStatus: vi.fn(),
		setWorkingMessage: vi.fn(),
		setWorkingVisible: vi.fn(),
		setWorkingIndicator: vi.fn(),
		setHiddenThinkingLabel: vi.fn(),
		setWidget: vi.fn(),
		...overrides,
	} as unknown as ExtensionUIContext;
}

/**
 * (task #78) The "credential" ask_user variant, driven end to end through
 * AgentSession — proving the model only ever sees an opaque placeholder, and
 * that the SAME session's tool-definition-wrapper choke point correctly
 * resolves a validly-issued placeholder while refusing a fabricated one.
 */
describe("AgentSession vault (credential ask_user variant)", () => {
	const harnesses: Harness[] = [];
	const previousAgentDir = process.env[ENV_AGENT_DIR];
	let agentDir: string;

	beforeEach(() => {
		agentDir = mkdtempSync(join(tmpdir(), "zero-vault-agent-"));
		process.env[ENV_AGENT_DIR] = agentDir;
	});

	afterEach(() => {
		while (harnesses.length > 0) harnesses.pop()?.cleanup();
		if (previousAgentDir === undefined) {
			delete process.env[ENV_AGENT_DIR];
		} else {
			process.env[ENV_AGENT_DIR] = previousAgentDir;
		}
		rmSync(agentDir, { recursive: true, force: true });
	});

	async function createVaultHarness(): Promise<Harness> {
		const harness = await createHarness();
		harnesses.push(harness);
		return harness;
	}

	it("returns only an opaque placeholder token to the model, never the typed secret", async () => {
		const harness = await createVaultHarness();
		const input = vi.fn(async () => "sk-live-secret-value");
		await harness.session.bindExtensions({ uiContext: fakeUI({ input }) });

		const result = await harness.session.handleAskUserHostRequest({
			type: "credential",
			question: "What's your Stripe API key?",
			name: "stripe_api_key",
		});

		expect(result.type).toBe("credential");
		expect(result.answer).toMatch(/^zero-cred:\/\/stripe_api_key\/[0-9a-f]{24}$/);
		expect(JSON.stringify(result)).not.toContain("sk-live-secret-value");

		// The masked-input primitive was used, not a plain free_text prompt.
		expect(input).toHaveBeenCalledWith(
			"What's your Stripe API key?",
			undefined,
			expect.objectContaining({ masked: true }),
		);

		// The plaintext really did land in this session's project-local vault.
		await expect(getCredential(harness.tempDir, "stripe_api_key")).resolves.toBe("sk-live-secret-value");
	});

	it("returns a null answer without storing anything when the user cancels", async () => {
		const harness = await createVaultHarness();
		await harness.session.bindExtensions({ uiContext: fakeUI({ input: vi.fn(async () => undefined) }) });

		const result = await harness.session.handleAskUserHostRequest({
			type: "credential",
			question: "What's your Stripe API key?",
			name: "stripe_api_key",
		});

		expect(result).toEqual({ type: "credential", answer: null });
		await expect(getCredential(harness.tempDir, "stripe_api_key")).resolves.toBeUndefined();
	});

	it("rejects a malformed credential name before touching the UI", async () => {
		const harness = await createVaultHarness();
		const input = vi.fn();
		await harness.session.bindExtensions({ uiContext: fakeUI({ input }) });

		await expect(
			harness.session.handleAskUserHostRequest({
				type: "credential",
				question: "What's your key?",
				name: "has space",
			}),
		).rejects.toThrow(/ask_user credential name must match/);
		expect(input).not.toHaveBeenCalled();
	});

	it("resolves a validly-issued placeholder to the real secret at the tool-definition-wrapper choke point", async () => {
		const harness = await createVaultHarness();
		await harness.session.bindExtensions({ uiContext: fakeUI({ input: vi.fn(async () => "sk-live-secret-value") }) });

		const { answer: token } = await harness.session.handleAskUserHostRequest({
			type: "credential",
			question: "What's your Stripe API key?",
			name: "stripe_api_key",
		});

		let receivedCommand: string | undefined;
		const bashLikeTool = {
			name: "bash",
			label: "bash",
			description: "test bash tool",
			parameters: {} as any,
			execute: async (_toolCallId: string, params: any) => {
				receivedCommand = params.command;
				return { content: [{ type: "text" as const, text: "ok" }], details: undefined };
			},
		};
		const ctx = harness.session.extensionRunner.createContext();
		const wrapped = wrapToolDefinition(bashLikeTool, () => ctx);

		const result = await wrapped.execute(
			"call-1",
			{ command: `curl -H "Authorization: Bearer ${token}" https://example.com` },
			undefined,
			undefined,
		);

		expect((result as any).isError).toBeFalsy();
		expect(receivedCommand).toBe('curl -H "Authorization: Bearer sk-live-secret-value" https://example.com');
	});

	it("does not substitute a fabricated/mismatched token, and leaves it as literal text", async () => {
		const harness = await createVaultHarness();
		await harness.session.bindExtensions({ uiContext: fakeUI({ input: vi.fn(async () => "sk-live-secret-value") }) });

		await harness.session.handleAskUserHostRequest({
			type: "credential",
			question: "What's your Stripe API key?",
			name: "stripe_api_key",
		});
		const fabricated = "zero-cred://stripe_api_key/deadbeefdeadbeefdeadbeef";

		let receivedCommand: string | undefined;
		const bashLikeTool = {
			name: "bash",
			label: "bash",
			description: "test bash tool",
			parameters: {} as any,
			execute: async (_toolCallId: string, params: any) => {
				receivedCommand = params.command;
				return { content: [{ type: "text" as const, text: "ok" }], details: undefined };
			},
		};
		const ctx = harness.session.extensionRunner.createContext();
		const wrapped = wrapToolDefinition(bashLikeTool, () => ctx);

		await wrapped.execute("call-2", { command: `echo ${fabricated}` }, undefined, undefined);

		expect(receivedCommand).toBe(`echo ${fabricated}`);
		expect(receivedCommand).not.toContain("sk-live-secret-value");
	});

	// task #84: the kernel evaluates `rlm.run`'s arguments (e.g. an f-string
	// built from a variable a prior cell resolved to the real secret) BEFORE
	// the host request is ever dispatched — so `prompt`/`cellSourceCode` can
	// already contain the raw plaintext, with no placeholder anywhere in
	// sight for pre-execution harm-check/vault substitution to catch. Only a
	// post-hoc scrub, applied before that text is used to build the child
	// session's initial message, can catch this.
	describe("rlm.run cellSourceCode/prompt scrubbing (task #84)", () => {
		it("scrubs a live-resolved secret out of the prompt before it reaches the child session", async () => {
			const harness = await createVaultHarness();
			await harness.session.bindExtensions({
				uiContext: fakeUI({ input: vi.fn(async () => "sk-live-secret-value") }),
			});
			await harness.session.handleAskUserHostRequest({
				type: "credential",
				question: "What's your Stripe API key?",
				name: "stripe_api_key",
			});

			// Simulates what the kernel actually dispatches once it has evaluated an
			// f-string like `rlm.run(prompt=f"use {api_key} for X")` against a
			// variable that already holds the decrypted secret in kernel memory.
			const handle = await harness.session.runRlmChild("use sk-live-secret-value for X");

			// The default child session name is slugified from the prompt — an
			// unscrubbed secret would appear verbatim (as "sk-live-secret-value")
			// in that slug; a scrubbed prompt (now containing a zero-cred://
			// placeholder) does not. This observation point is synchronous with
			// `runRlmChild` resolving, unlike the child's actual conversation
			// history, which starts up on a detached async path.
			expect(handle.name).not.toContain("sk-live-secret-value");
		});

		it("scrubs a live-resolved secret out of the spawning cell's source (cellSourceCode) too", async () => {
			// `spawnCode` (the "cellSourceCode" the kernel captured) doesn't feed
			// the returned handle at all — it's only ever forwarded to whatever
			// creates the child runtime (`SubagentRuntimeHost.createRlmSubagentRuntime`,
			// e.g. for display in the agents-view). Capture it there instead of
			// letting a real child actually start.
			let capturedSpawnCode: string | undefined;
			let resolveCaptured: () => void = () => {};
			const captured = new Promise<void>((resolve) => {
				resolveCaptured = resolve;
			});
			const harness = await createHarness({
				subagentRuntimeHost: {
					createRlmSubagentRuntime: async (options) => {
						capturedSpawnCode = options.spawnCode;
						resolveCaptured();
						throw new Error("test-stop: no real child runtime is needed for this assertion");
					},
					deleteRlmSubagentRuntime: async () => {},
				},
			});
			harnesses.push(harness);
			await harness.session.bindExtensions({
				uiContext: fakeUI({ input: vi.fn(async () => "sk-live-secret-value") }),
			});
			await harness.session.handleAskUserHostRequest({
				type: "credential",
				question: "What's your Stripe API key?",
				name: "stripe_api_key",
			});

			await harness.session.runRlmChild(
				"benign prompt",
				{},
				'rlm.run(prompt="benign prompt", extra=f"key was sk-live-secret-value")',
			);
			await captured;

			expect(capturedSpawnCode).not.toContain("sk-live-secret-value");
			expect(capturedSpawnCode).toMatch(/zero-cred:\/\/stripe_api_key\/[0-9a-f]{24}/);
		});

		it("passes an unrelated prompt through unchanged when nothing to scrub is active", async () => {
			const harness = await createVaultHarness();
			const handle = await harness.session.runRlmChild("just a normal task, nothing sensitive");
			expect(handle.name).toContain("just-a-normal-task");
		});
	});
});
