import { describe, expect, it, vi } from "vitest";
import { McpTaskRegistry, resolveAnswerPayload } from "../src/core/mcp-server/task-registry.js";

/** Module J — MCP server worker-harness task registry, pure state machine (no session involved). */
describe("McpTaskRegistry", () => {
	it("creates a task in running status with an empty notification list", () => {
		const registry = new McpTaskRegistry();
		const { id } = registry.create("do the thing", "auto");
		const snapshot = registry.snapshot(id);
		expect(snapshot.status).toBe("running");
		expect(snapshot.prompt).toBe("do the thing");
		expect(snapshot.mode).toBe("auto");
		expect(snapshot.notifications).toEqual([]);
		expect(snapshot.pendingQuestion).toBeUndefined();
	});

	it("throws on an unknown task id", () => {
		const registry = new McpTaskRegistry();
		expect(() => registry.snapshot("does-not-exist")).toThrow(/unknown task_id/);
		expect(registry.has("does-not-exist")).toBe(false);
	});

	it("askQuestion flips status to waiting_for_answer and records the pending question", async () => {
		const registry = new McpTaskRegistry();
		const { id } = registry.create("do the thing");

		const pending = registry.askQuestion(id, { method: "confirm", title: "Delete cache?", message: "Irreversible." });
		const snapshot = registry.snapshot(id);
		expect(snapshot.status).toBe("waiting_for_answer");
		expect(snapshot.pendingQuestion).toMatchObject({ method: "confirm", title: "Delete cache?" });
		expect(snapshot.pendingQuestion?.questionId).toBeTruthy();

		const ok = registry.answer(id, snapshot.pendingQuestion!.questionId, { cancelled: false, confirmed: true });
		expect(ok).toBe(true);
		await expect(pending).resolves.toEqual({ cancelled: false, confirmed: true });

		const after = registry.snapshot(id);
		expect(after.status).toBe("running");
		expect(after.pendingQuestion).toBeUndefined();
	});

	it("answer() returns false for a mismatched or stale question id", async () => {
		const registry = new McpTaskRegistry();
		const { id } = registry.create("do the thing");
		registry.askQuestion(id, { method: "input", title: "Value?" });

		expect(registry.answer(id, "wrong-question-id", { cancelled: true })).toBe(false);
		expect(registry.answer("wrong-task-id", "wrong-question-id", { cancelled: true })).toBe(false);
	});

	it("resolves as cancelled immediately when the signal is already aborted", async () => {
		const registry = new McpTaskRegistry();
		const { id } = registry.create("do the thing");
		const controller = new AbortController();
		controller.abort();

		const response = await registry.askQuestion(id, { method: "select", title: "Pick" }, controller.signal);
		expect(response).toEqual({ cancelled: true });
		expect(registry.snapshot(id).status).toBe("running");
	});

	it("resolves as cancelled when the signal aborts while a question is pending", async () => {
		const registry = new McpTaskRegistry();
		const { id } = registry.create("do the thing");
		const controller = new AbortController();

		const pending = registry.askQuestion(id, { method: "select", title: "Pick" }, controller.signal);
		expect(registry.snapshot(id).status).toBe("waiting_for_answer");
		controller.abort();

		await expect(pending).resolves.toEqual({ cancelled: true });
		expect(registry.snapshot(id).status).toBe("running");
		expect(registry.snapshot(id).pendingQuestion).toBeUndefined();
	});

	it("caps stored notifications at the retention limit, keeping the most recent", () => {
		const registry = new McpTaskRegistry();
		const { id } = registry.create("do the thing");
		for (let i = 0; i < 25; i++) {
			registry.notify(id, `note ${i}`, "info");
		}
		const snapshot = registry.snapshot(id);
		expect(snapshot.notifications).toHaveLength(20);
		expect(snapshot.notifications[0].message).toBe("note 5");
		expect(snapshot.notifications.at(-1)?.message).toBe("note 24");
	});

	it("notify() on an unknown task id is a silent no-op", () => {
		const registry = new McpTaskRegistry();
		expect(() => registry.notify("nope", "hi", "info")).not.toThrow();
	});

	it("cancel() resolves a pending question and requests session abort", async () => {
		const registry = new McpTaskRegistry();
		const { id, attach } = registry.create("do the thing");
		const requestAbort = vi.fn();
		attach({ requestAbort } as any);

		const pending = registry.askQuestion(id, { method: "confirm", title: "Proceed?" });
		expect(registry.cancel(id)).toBe(true);

		await expect(pending).resolves.toEqual({ cancelled: true });
		expect(requestAbort).toHaveBeenCalledOnce();
		expect(registry.snapshot(id).status).toBe("running");
	});

	it("cancel() still requests session abort when there is no pending question", () => {
		const registry = new McpTaskRegistry();
		const { id, attach } = registry.create("do the thing");
		const requestAbort = vi.fn();
		attach({ requestAbort } as any);

		expect(registry.cancel(id)).toBe(true);
		expect(requestAbort).toHaveBeenCalledOnce();
	});

	it("cancel() returns false for an unknown task id", () => {
		const registry = new McpTaskRegistry();
		expect(registry.cancel("nope")).toBe(false);
	});

	it("cancelAll() cancels every live task", async () => {
		const registry = new McpTaskRegistry();
		const { id: id1, attach: attach1 } = registry.create("a");
		const { attach: attach2 } = registry.create("b");
		const abort1 = vi.fn();
		const abort2 = vi.fn();
		attach1({ requestAbort: abort1 } as any);
		attach2({ requestAbort: abort2 } as any);
		const pending1 = registry.askQuestion(id1, { method: "input", title: "Value?" });

		registry.cancelAll();

		await expect(pending1).resolves.toEqual({ cancelled: true });
		expect(abort1).toHaveBeenCalledOnce();
		expect(abort2).toHaveBeenCalledOnce();
	});

	describe("resolveAnswerPayload", () => {
		it("accepts a boolean response for a confirm question", () => {
			const result = resolveAnswerPayload({ questionId: "q1", method: "confirm", title: "x" }, { response: true });
			expect(result).toEqual({ ok: true, payload: { cancelled: false, confirmed: true } });
		});

		it("rejects a string response for a confirm question rather than coercing it", () => {
			const result = resolveAnswerPayload({ questionId: "q1", method: "confirm", title: "x" }, { response: "yes" });
			expect(result.ok).toBe(false);
			expect((result as { error: string }).error).toMatch(/method=confirm.*boolean/);
		});

		it("accepts a string response for a select question", () => {
			const result = resolveAnswerPayload(
				{ questionId: "q1", method: "select", title: "x", options: ["a", "b"] },
				{ response: "b" },
			);
			expect(result).toEqual({ ok: true, payload: { cancelled: false, value: "b" } });
		});

		it("rejects a boolean response for an input question rather than coercing it", () => {
			const result = resolveAnswerPayload({ questionId: "q1", method: "input", title: "x" }, { response: true });
			expect(result.ok).toBe(false);
			expect((result as { error: string }).error).toMatch(/method=input.*string/);
		});

		it("treats an explicit cancelled:true as cancelled regardless of method", () => {
			const result = resolveAnswerPayload(
				{ questionId: "q1", method: "confirm", title: "x" },
				{ response: true, cancelled: true },
			);
			expect(result).toEqual({ ok: true, payload: { cancelled: true } });
		});

		it("treats a missing response as cancelled", () => {
			const result = resolveAnswerPayload({ questionId: "q1", method: "select", title: "x" }, {});
			expect(result).toEqual({ ok: true, payload: { cancelled: true } });
		});
	});

	it("markDone/markError set terminal status and payload", () => {
		const registry = new McpTaskRegistry();
		const { id: doneId } = registry.create("a");
		registry.markDone(doneId, { text: "the answer", success: true });
		expect(registry.snapshot(doneId)).toMatchObject({
			status: "done",
			result: { text: "the answer", success: true },
		});

		const { id: errorId } = registry.create("b");
		registry.markError(errorId, "boom");
		expect(registry.snapshot(errorId)).toMatchObject({ status: "error", error: "boom" });
	});
});
