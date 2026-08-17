import { beforeEach, describe, expect, it, vi } from "vitest";
import { getModel } from "../src/models.js";
import { streamSimple } from "../src/stream.js";
import type { ToolCall } from "../src/types.js";

// OpenRouter's `reasoning_details` array carries encrypted reasoning payloads
// keyed by tool-call id. Entries are untrusted provider data (could be null, a
// primitive, or missing fields) and must be validated before use rather than
// trusted blindly or allowed to throw mid-stream.

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

function toolCallChunk(reasoningDetails: unknown) {
	return {
		id: "chatcmpl-1",
		choices: [
			{
				index: 0,
				delta: {
					tool_calls: [{ index: 0, id: "call_1", function: { name: "search", arguments: '{"q":"x"}' } }],
					reasoning_details: reasoningDetails,
				},
			},
		],
	};
}

describe("openai-completions reasoning_details validation", () => {
	beforeEach(() => {
		mockState.chunks = [];
	});

	it("attaches a well-formed encrypted reasoning detail to the matching tool call", async () => {
		const { compat: _compat, ...baseModel } = getModel("openai", "gpt-4o-mini")!;
		const model = { ...baseModel, api: "openai-completions" } as const;

		mockState.chunks = [
			toolCallChunk([{ type: "reasoning.encrypted", id: "call_1", data: "encrypted-payload" }]),
			{ id: "chatcmpl-1", choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] },
		];

		const message = await streamSimple(
			model,
			{ messages: [{ role: "user", content: "hi", timestamp: Date.now() }] },
			{ apiKey: "test" },
		).result();

		const toolCall = message.content.find((b): b is ToolCall => b.type === "toolCall");
		expect(toolCall?.thoughtSignature).toBeDefined();
		expect(JSON.parse(toolCall?.thoughtSignature ?? "{}")).toMatchObject({ id: "call_1" });
	});

	it("skips a null entry in reasoning_details without crashing", async () => {
		const { compat: _compat, ...baseModel } = getModel("openai", "gpt-4o-mini")!;
		const model = { ...baseModel, api: "openai-completions" } as const;

		mockState.chunks = [
			toolCallChunk([null, { type: "reasoning.encrypted", id: "call_1", data: "encrypted-payload" }]),
			{ id: "chatcmpl-1", choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] },
		];

		const message = await streamSimple(
			model,
			{ messages: [{ role: "user", content: "hi", timestamp: Date.now() }] },
			{ apiKey: "test" },
		).result();

		expect(message.stopReason).toBe("toolUse");
		expect(message.errorMessage).toBeUndefined();
		const toolCall = message.content.find((b): b is ToolCall => b.type === "toolCall");
		expect(toolCall?.thoughtSignature).toBeDefined();
	});

	it("ignores entries missing required fields and a non-array reasoning_details", async () => {
		const { compat: _compat, ...baseModel } = getModel("openai", "gpt-4o-mini")!;
		const model = { ...baseModel, api: "openai-completions" } as const;

		mockState.chunks = [
			toolCallChunk([{ type: "reasoning.encrypted", id: "call_1" /* missing data */ }]),
			{ id: "chatcmpl-1", choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] },
		];

		const message = await streamSimple(
			model,
			{ messages: [{ role: "user", content: "hi", timestamp: Date.now() }] },
			{ apiKey: "test" },
		).result();

		expect(message.stopReason).toBe("toolUse");
		expect(message.errorMessage).toBeUndefined();
		const toolCall = message.content.find((b): b is ToolCall => b.type === "toolCall");
		expect(toolCall?.thoughtSignature).toBeUndefined();
	});

	it("does not crash when reasoning_details itself is not an array", async () => {
		const { compat: _compat, ...baseModel } = getModel("openai", "gpt-4o-mini")!;
		const model = { ...baseModel, api: "openai-completions" } as const;

		mockState.chunks = [
			toolCallChunk("not-an-array"),
			{ id: "chatcmpl-1", choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] },
		];

		const message = await streamSimple(
			model,
			{ messages: [{ role: "user", content: "hi", timestamp: Date.now() }] },
			{ apiKey: "test" },
		).result();

		expect(message.stopReason).toBe("toolUse");
		expect(message.errorMessage).toBeUndefined();
	});
});
