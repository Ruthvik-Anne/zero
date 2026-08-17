import { beforeEach, describe, expect, it, vi } from "vitest";
import { getModel } from "../src/models.js";
import { streamSimple } from "../src/stream.js";

// OpenRouter surfaces extra upstream-provider detail via error.error.metadata.raw.
// That text comes straight from a third-party provider and is unbounded (could be
// a full HTML error page from a broken upstream); it must be capped before landing
// in the user-facing errorMessage that the TUI renders.

const mockState = vi.hoisted(() => ({
	errorToThrow: undefined as unknown,
}));

vi.mock("openai", () => {
	class FakeOpenAI {
		chat = {
			completions: {
				create: () => {
					const promise = Promise.resolve({
						async *[Symbol.asyncIterator]() {},
					}) as Promise<unknown> & {
						withResponse: () => Promise<{
							data: unknown;
							response: { status: number; headers: Headers };
						}>;
					};
					promise.withResponse = async () => {
						throw mockState.errorToThrow;
					};
					return promise;
				},
			},
		};
	}
	return { default: FakeOpenAI };
});

describe("openai-completions error metadata truncation", () => {
	beforeEach(() => {
		mockState.errorToThrow = undefined;
	});

	it("caps an oversized error.error.metadata.raw field with a truncation marker", async () => {
		const { compat: _compat, ...baseModel } = getModel("openai", "gpt-4o-mini")!;
		const model = { ...baseModel, api: "openai-completions" } as const;

		const hugeRaw = "x".repeat(50_000);
		const error = new Error("upstream error") as Error & {
			error?: { type: string; message: string; metadata: { raw: string } };
		};
		error.error = {
			type: "invalid_request_error",
			message: "bad request",
			metadata: { raw: hugeRaw },
		};
		mockState.errorToThrow = error;

		const message = await streamSimple(
			model,
			{ messages: [{ role: "user", content: "hi", timestamp: Date.now() }] },
			{ apiKey: "test" },
		).result();

		expect(message.stopReason).toBe("error");
		expect(message.errorMessage).toBeDefined();
		expect(message.errorMessage?.length ?? 0).toBeLessThan(hugeRaw.length);
		expect(message.errorMessage).toContain("…");
		expect(message.errorMessage).not.toContain(hugeRaw);
	});

	it("does not append anything when error.error.metadata.raw is absent", async () => {
		const { compat: _compat, ...baseModel } = getModel("openai", "gpt-4o-mini")!;
		const model = { ...baseModel, api: "openai-completions" } as const;

		const error = new Error("upstream error") as Error & { error?: { type: string; message: string } };
		error.error = { type: "invalid_request_error", message: "bad request" };
		mockState.errorToThrow = error;

		const message = await streamSimple(
			model,
			{ messages: [{ role: "user", content: "hi", timestamp: Date.now() }] },
			{ apiKey: "test" },
		).result();

		expect(message.stopReason).toBe("error");
		expect(message.errorMessage).not.toContain("\n");
	});
});
