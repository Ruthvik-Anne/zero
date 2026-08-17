import { describe, expect, it } from "vitest";
import { createMcpTaskUiContext } from "../src/core/mcp-server/mcp-task-ui-context.js";
import { McpTaskRegistry } from "../src/core/mcp-server/task-registry.js";

/**
 * Module J — the headless ExtensionUIContext an MCP-driven task session is
 * bound to. Proves select/confirm/input each surface as a registry pending
 * question and resolve with the value an external answer() call provides.
 */
describe("createMcpTaskUiContext", () => {
	it("select() surfaces a pending question and resolves to the chosen label", async () => {
		const registry = new McpTaskRegistry();
		const { id } = registry.create("task");
		const ui = createMcpTaskUiContext(registry, id);

		const resultPromise = ui.select("Pick one", ["a", "b", "c"]);
		const pending = registry.snapshot(id).pendingQuestion;
		expect(pending).toMatchObject({ method: "select", title: "Pick one", options: ["a", "b", "c"] });

		registry.answer(id, pending!.questionId, { cancelled: false, value: "b" });
		expect(await resultPromise).toBe("b");
	});

	it("select() resolves to undefined when the answer is cancelled", async () => {
		const registry = new McpTaskRegistry();
		const { id } = registry.create("task");
		const ui = createMcpTaskUiContext(registry, id);

		const resultPromise = ui.select("Pick one", ["a", "b"]);
		const pending = registry.snapshot(id).pendingQuestion!;
		registry.answer(id, pending.questionId, { cancelled: true });
		expect(await resultPromise).toBeUndefined();
	});

	it("confirm() surfaces a pending question and resolves to the boolean answer", async () => {
		const registry = new McpTaskRegistry();
		const { id } = registry.create("task");
		const ui = createMcpTaskUiContext(registry, id);

		const resultPromise = ui.confirm("Confirm risky action", "This cannot be undone.");
		const pending = registry.snapshot(id).pendingQuestion!;
		expect(pending).toMatchObject({
			method: "confirm",
			title: "Confirm risky action",
			message: "This cannot be undone.",
		});

		registry.answer(id, pending.questionId, { cancelled: false, confirmed: true });
		expect(await resultPromise).toBe(true);
	});

	it("confirm() resolves to false when cancelled (fail-closed)", async () => {
		const registry = new McpTaskRegistry();
		const { id } = registry.create("task");
		const ui = createMcpTaskUiContext(registry, id);

		const resultPromise = ui.confirm("Confirm risky action", "msg");
		const pending = registry.snapshot(id).pendingQuestion!;
		registry.answer(id, pending.questionId, { cancelled: true });
		expect(await resultPromise).toBe(false);
	});

	it("input() surfaces a pending question with the placeholder and resolves to the typed text", async () => {
		const registry = new McpTaskRegistry();
		const { id } = registry.create("task");
		const ui = createMcpTaskUiContext(registry, id);

		const resultPromise = ui.input("Enter a value", "e.g. 42");
		const pending = registry.snapshot(id).pendingQuestion!;
		expect(pending).toMatchObject({ method: "input", title: "Enter a value", placeholder: "e.g. 42" });

		registry.answer(id, pending.questionId, { cancelled: false, value: "42" });
		expect(await resultPromise).toBe("42");
	});

	it("respects an already-aborted signal without creating a pending question", async () => {
		const registry = new McpTaskRegistry();
		const { id } = registry.create("task");
		const ui = createMcpTaskUiContext(registry, id);
		const controller = new AbortController();
		controller.abort();

		const result = await ui.confirm("x", "y", { signal: controller.signal });
		expect(result).toBe(false);
		expect(registry.snapshot(id).pendingQuestion).toBeUndefined();
	});

	it("notify() records a notification on the task", () => {
		const registry = new McpTaskRegistry();
		const { id } = registry.create("task");
		const ui = createMcpTaskUiContext(registry, id);

		ui.notify("Blocked: dangerous op", "error");
		expect(registry.snapshot(id).notifications).toEqual([
			expect.objectContaining({ message: "Blocked: dangerous op", notifyType: "error" }),
		]);
	});
});
