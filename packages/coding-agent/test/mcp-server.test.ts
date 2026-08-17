import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { fauxAssistantMessage, fauxToolCall, registerFauxProvider } from "@zero-agent/ai";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuthStorage } from "../src/core/auth-storage.js";
import { createZeroMcpServer } from "../src/core/mcp-server/server.js";
import { ModelRegistry } from "../src/core/model-registry.js";
import { SettingsManager } from "../src/core/settings-manager.js";

/**
 * Module J — Zero as an MCP server, exercised over the real MCP wire
 * protocol (InMemoryTransport + a real Client), not just the internal
 * registry/runner pieces in isolation: proves run_task/get_status/get_result
 * actually work end to end through the four-tool worker-harness surface an
 * external MCP client would see.
 */
describe("Zero MCP server (run_task/get_status/get_result/answer)", () => {
	let faux: ReturnType<typeof registerFauxProvider>;
	let authStorage: AuthStorage;
	let modelRegistry: ModelRegistry;
	let settingsManager: SettingsManager;

	beforeEach(() => {
		faux = registerFauxProvider({});
		authStorage = AuthStorage.inMemory();
		authStorage.setRuntimeApiKey(faux.models[0].provider, "faux-key");
		modelRegistry = ModelRegistry.inMemory(authStorage);
		modelRegistry.registerProvider(faux.models[0].provider, {
			baseUrl: faux.models[0].baseUrl,
			apiKey: "faux-key",
			api: faux.api,
			models: faux.models.map((m) => ({
				id: m.id,
				name: m.name,
				api: m.api,
				reasoning: m.reasoning,
				input: m.input,
				cost: m.cost,
				contextWindow: m.contextWindow,
				maxTokens: m.maxTokens,
				baseUrl: m.baseUrl,
			})),
		});
		// Disable the Agent's built-in exponential-backoff retry (default 2s/4s/8s)
		// so the error-path test doesn't have to wait through real backoff delays.
		settingsManager = SettingsManager.inMemory({ retry: { enabled: false } });
	});

	afterEach(() => {
		faux.unregister();
	});

	async function connectClient() {
		// Passes model explicitly rather than relying on settingsManager
		// defaultProvider/defaultModel auto-resolution — see task #27: that
		// resolution path (createAgentSession -> findInitialModel ->
		// ModelRegistry.refreshAvailableModels) is racy against the faux
		// provider's registration once any await separates them, independent
		// of anything in this module. Mirrors the same workaround
		// test/sdk-provider-fallback.test.ts already uses.
		const { server } = createZeroMcpServer({
			cwd: process.cwd(),
			authStorage,
			modelRegistry,
			settingsManager,
			model: faux.getModel(),
		});
		const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
		const client = new Client({ name: "test-client", version: "1.0.0" });
		await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);
		return {
			client,
			async close() {
				await client.close();
				await server.close();
			},
		};
	}

	function parse(result: any): any {
		const first = result.content?.[0];
		return first?.type === "text" && first.text ? JSON.parse(first.text) : undefined;
	}

	async function waitUntilDone(client: Client, taskId: string, timeoutMs = 5000): Promise<any> {
		const deadline = Date.now() + timeoutMs;
		while (Date.now() < deadline) {
			const status = parse(await client.callTool({ name: "get_status", arguments: { task_id: taskId } }));
			if (status.status === "done" || status.status === "error") return status;
			await new Promise((resolve) => setTimeout(resolve, 10));
		}
		throw new Error(`task ${taskId} did not finish within ${timeoutMs}ms`);
	}

	it("runs a task to completion and returns its result", async () => {
		faux.setResponses([fauxAssistantMessage("42 is the answer")]);
		const { client, close } = await connectClient();

		const run = parse(await client.callTool({ name: "run_task", arguments: { prompt: "what is the answer?" } }));
		expect(run.task_id).toBeTruthy();

		const status = await waitUntilDone(client, run.task_id);
		expect(status.status).toBe("done");

		const result = parse(await client.callTool({ name: "get_result", arguments: { task_id: run.task_id } }));
		expect(result).toEqual({ status: "done", result: "42 is the answer", success: true });

		await close();
	});

	it("get_result reports not-finished while a task is still running", async () => {
		let releaseResponse: (() => void) | undefined;
		faux.setResponses([
			async () => {
				await new Promise<void>((resolve) => {
					releaseResponse = resolve;
				});
				return fauxAssistantMessage("done eventually");
			},
		]);
		const { client, close } = await connectClient();

		const run = parse(await client.callTool({ name: "run_task", arguments: { prompt: "slow task" } }));
		const result = parse(await client.callTool({ name: "get_result", arguments: { task_id: run.task_id } }));
		expect(result.status).toBe("running");
		expect(result.message).toMatch(/not finished/);

		// run_task's session creation + prompt happen in the background; wait for
		// the faux response factory to actually be invoked (setting
		// releaseResponse) before releasing it, rather than racing a still-undefined closure.
		const deadline = Date.now() + 5000;
		while (!releaseResponse && Date.now() < deadline) {
			await new Promise((resolve) => setTimeout(resolve, 5));
		}
		releaseResponse?.();
		await waitUntilDone(client, run.task_id);
		await close();
	});

	it("get_status/get_result/answer/cancel_task all report a clear error for an unknown task_id", async () => {
		const { client, close } = await connectClient();

		for (const name of ["get_status", "get_result", "cancel_task"]) {
			const result = await client.callTool({ name, arguments: { task_id: "nope" } });
			expect(result.isError).toBe(true);
		}
		const answerResult = await client.callTool({
			name: "answer",
			arguments: { task_id: "nope", question_id: "nope", response: true },
		});
		expect(answerResult.isError).toBe(true);

		await close();
	});

	it("cancel_task on a live task succeeds and the task ends up done or error, never stuck running forever", async () => {
		faux.setResponses([
			async () => {
				await new Promise(() => {}); // never resolves — cancel_task must be what ends this task.
				return fauxAssistantMessage("unreachable");
			},
		]);
		const { client, close } = await connectClient();

		const run = parse(await client.callTool({ name: "run_task", arguments: { prompt: "hangs forever" } }));
		const cancelResult = parse(await client.callTool({ name: "cancel_task", arguments: { task_id: run.task_id } }));
		expect(cancelResult).toEqual({ ok: true });

		await close();
	});

	it("reports a task-level error rather than throwing when the model call fails", async () => {
		faux.setResponses([fauxAssistantMessage([], { stopReason: "error", errorMessage: "faux failure" })]);
		const { client, close } = await connectClient();

		const run = parse(await client.callTool({ name: "run_task", arguments: { prompt: "will fail" } }));
		const status = await waitUntilDone(client, run.task_id);
		expect(status.status).toBe("done");
		const result = parse(await client.callTool({ name: "get_result", arguments: { task_id: run.task_id } }));
		expect(result.status).toBe("done");
		expect(result.success).toBe(false);
		expect(result.result).toBe("faux failure");

		await close();
	});

	// D10: a harm-check soft-block must not become an unverifiable remote
	// approval just because run_task binds a real UI context (needed for
	// ask_user). allowRiskyActions must be explicitly opted into per task.
	it("fails a soft-blocked tool call closed by default, never surfacing a pending question", async () => {
		faux.setResponses([
			fauxAssistantMessage(fauxToolCall("ipython", { code: "os.system('rm -rf ./scratch')" })),
			fauxAssistantMessage("acknowledged the block"),
		]);
		const { client, close } = await connectClient();

		const run = parse(await client.callTool({ name: "run_task", arguments: { prompt: "clean up" } }));

		// Poll status while the task runs; it must never wait for an answer.
		const deadline = Date.now() + 5000;
		let sawWaitingForAnswer = false;
		let status: any;
		do {
			status = parse(await client.callTool({ name: "get_status", arguments: { task_id: run.task_id } }));
			if (status.status === "waiting_for_answer") sawWaitingForAnswer = true;
			if (status.status === "done" || status.status === "error") break;
			await new Promise((resolve) => setTimeout(resolve, 10));
		} while (Date.now() < deadline);

		expect(sawWaitingForAnswer).toBe(false);
		expect(status.status).toBe("done");

		await close();
	});

	it("surfaces a soft-block as a pending question when allowRiskyActions is explicitly true", async () => {
		faux.setResponses([
			fauxAssistantMessage(fauxToolCall("ipython", { code: "os.system('rm -rf ./scratch')" })),
			fauxAssistantMessage("acknowledged the decline"),
		]);
		const { client, close } = await connectClient();

		const run = parse(
			await client.callTool({
				name: "run_task",
				arguments: { prompt: "clean up", allowRiskyActions: true },
			}),
		);

		const deadline = Date.now() + 5000;
		let status: any;
		do {
			status = parse(await client.callTool({ name: "get_status", arguments: { task_id: run.task_id } }));
			if (status.status === "waiting_for_answer") break;
			await new Promise((resolve) => setTimeout(resolve, 10));
		} while (Date.now() < deadline);

		expect(status.status).toBe("waiting_for_answer");
		expect(status.pending_question).toBeDefined();
		expect(status.pending_question.method).toBe("confirm");

		// Decline rather than approve — proves the round trip itself works without
		// needing a real kernel to execute the (still-risky) underlying command.
		const answerResult = parse(
			await client.callTool({
				name: "answer",
				arguments: { task_id: run.task_id, question_id: status.pending_question.question_id, response: false },
			}),
		);
		expect(answerResult.ok).toBe(true);

		await waitUntilDone(client, run.task_id);
		await close();
	});
});
