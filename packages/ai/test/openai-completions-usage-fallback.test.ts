import { beforeEach, describe, expect, it, vi } from "vitest";
import { getModel } from "../src/models.js";
import { streamSimple } from "../src/stream.js";

// Some OpenAI-compatible providers (e.g. Moonshot) put token usage on
// choice.usage instead of the standard chunk.usage. That field isn't part of
// the SDK type, so it must be validated before being read: a missing or
// malformed value should degrade to "no usage" rather than propagate
// NaN/undefined into cost calculations.

const mockState = vi.hoisted(() => ({
	chunks: [] as unknown[],
}));

vi.mock("openai", () => {
	class FakeOpenAI {
		chat = {
			completions: {
				create: () => {
					const chunks = mockState.chunks;
					const stream = {
						async *[Symbol.asyncIterator]() {
							for (const chunk of chunks) yield chunk;
						},
					};
					const promise = Promise.resolve(stream) as Promise<typeof stream> & {
						withResponse: () => Promise<{
							data: typeof stream;
							response: { status: number; headers: Headers };
						}>;
					};
					promise.withResponse = async () => ({
						data: stream,
						response: { status: 200, headers: new Headers() },
					});
					return promise;
				},
			},
		};
	}
	return { default: FakeOpenAI };
});

describe("openai-completions choice.usage fallback", () => {
	beforeEach(() => {
		mockState.chunks = [];
	});

	it("reads usage from choice.usage when chunk.usage is absent and well-formed", async () => {
		const { compat: _compat, ...baseModel } = getModel("openai", "gpt-4o-mini")!;
		const model = { ...baseModel, api: "openai-completions" } as const;

		mockState.chunks = [
			{
				id: "chatcmpl-1",
				choices: [
					{
						index: 0,
						delta: { content: "hi" },
						finish_reason: "stop",
						usage: {
							prompt_tokens: 10,
							completion_tokens: 5,
							prompt_tokens_details: { cached_tokens: 2 },
						},
					},
				],
			},
		];

		const message = await streamSimple(
			model,
			{ messages: [{ role: "user", content: "hi", timestamp: Date.now() }] },
			{ apiKey: "test" },
		).result();

		expect(message.usage.input).toBe(8);
		expect(message.usage.output).toBe(5);
		expect(message.usage.cacheRead).toBe(2);
	});

	it("ignores a malformed choice.usage (non-object) and leaves usage at defaults", async () => {
		const { compat: _compat, ...baseModel } = getModel("openai", "gpt-4o-mini")!;
		const model = { ...baseModel, api: "openai-completions" } as const;

		mockState.chunks = [
			{
				id: "chatcmpl-2",
				choices: [
					{
						index: 0,
						delta: { content: "hi" },
						finish_reason: "stop",
						usage: "not-an-object",
					},
				],
			},
		];

		const message = await streamSimple(
			model,
			{ messages: [{ role: "user", content: "hi", timestamp: Date.now() }] },
			{ apiKey: "test" },
		).result();

		expect(message.stopReason).toBe("stop");
		expect(message.usage.input).toBe(0);
		expect(message.usage.output).toBe(0);
		expect(message.usage.totalTokens).toBe(0);
	});

	it("ignores a malformed choice.usage (wrong field types) and leaves usage at defaults", async () => {
		const { compat: _compat, ...baseModel } = getModel("openai", "gpt-4o-mini")!;
		const model = { ...baseModel, api: "openai-completions" } as const;

		mockState.chunks = [
			{
				id: "chatcmpl-3",
				choices: [
					{
						index: 0,
						delta: { content: "hi" },
						finish_reason: "stop",
						usage: { prompt_tokens: "ten", completion_tokens: 5 },
					},
				],
			},
		];

		const message = await streamSimple(
			model,
			{ messages: [{ role: "user", content: "hi", timestamp: Date.now() }] },
			{ apiKey: "test" },
		).result();

		expect(message.stopReason).toBe("stop");
		expect(message.usage.input).toBe(0);
		expect(message.usage.output).toBe(0);
		expect(Number.isNaN(message.usage.totalTokens)).toBe(false);
	});
});
