import { afterEach, describe, expect, it } from "vitest";
import { createMcpTaskUiContext } from "../../src/core/mcp-server/mcp-task-ui-context.js";
import { McpTaskRegistry } from "../../src/core/mcp-server/task-registry.js";
import { createHarness, type Harness } from "./harness.js";

/**
 * Module J — proves the MCP task UI context is a real ExtensionUIContext
 * that ask_user.ask (module E) and the harm-check soft-block confirm (module
 * F, exercised indirectly via the same ctx.ui.confirm path) can drive end to
 * end through a real AgentSession: a question raised inside the session
 * surfaces as a registry pending question, and the registry's answer()
 * resolves it back into the session exactly like a real UI would.
 */
describe("AgentSession bound to the MCP task UI context", () => {
	const harnesses: Harness[] = [];

	afterEach(() => {
		while (harnesses.length > 0) harnesses.pop()?.cleanup();
	});

	async function createMcpHarness(): Promise<Harness> {
		const harness = await createHarness();
		harnesses.push(harness);
		return harness;
	}

	it("round-trips a confirm-type ask_user call through the registry", async () => {
		const harness = await createMcpHarness();
		const registry = new McpTaskRegistry();
		const { id: taskId } = registry.create("do the risky thing");
		await harness.session.bindExtensions({ uiContext: createMcpTaskUiContext(registry, taskId) });

		const askPromise = harness.session.handleAskUserHostRequest({
			type: "confirm",
			question: "Delete the build cache?",
			consequence: "This cannot be undone.",
		});

		// The confirm call is in-flight; the task registry should show it as a
		// pending question rather than the session hanging with no observable state.
		await Promise.resolve();
		await Promise.resolve();
		const pending = registry.snapshot(taskId).pendingQuestion;
		expect(pending).toMatchObject({ method: "confirm", title: "Delete the build cache?" });
		expect(registry.snapshot(taskId).status).toBe("waiting_for_answer");

		const answered = registry.answer(taskId, pending!.questionId, { cancelled: false, confirmed: true });
		expect(answered).toBe(true);

		expect(await askPromise).toEqual({ type: "confirm", answer: "yes" });
		expect(registry.snapshot(taskId).status).toBe("running");
	});

	it("round-trips a single_select ask_user call and cancellation maps to a null answer", async () => {
		const harness = await createMcpHarness();
		const registry = new McpTaskRegistry();
		const { id: taskId } = registry.create("pick a strategy");
		await harness.session.bindExtensions({ uiContext: createMcpTaskUiContext(registry, taskId) });

		const askPromise = harness.session.handleAskUserHostRequest({
			type: "single_select",
			question: "How should this subagent be isolated?",
			options: [
				{ label: "inline", description: "share the current worktree" },
				{ label: "worktree", description: "isolate in a fresh git worktree" },
			],
		});

		await Promise.resolve();
		await Promise.resolve();
		const pending = registry.snapshot(taskId).pendingQuestion!;
		expect(pending.options).toEqual([
			"inline — share the current worktree",
			"worktree — isolate in a fresh git worktree",
		]);

		registry.answer(taskId, pending.questionId, { cancelled: true });
		expect(await askPromise).toEqual({ type: "single_select", answer: null });
	});
});
