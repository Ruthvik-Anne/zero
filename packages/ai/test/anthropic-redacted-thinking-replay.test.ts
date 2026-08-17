import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";
import { streamAnthropic } from "../src/providers/anthropic.js";
import type { AssistantMessage, Context, Model, Usage } from "../src/types.js";

// Sessions saved before the redacted-thinking signature field existed can contain
// an assistant message with `{ type: "thinking", redacted: true }` and no
// `thinkingSignature`. Replaying that message must not crash the request (a bare
// non-null assertion would send `data: undefined`, which the API would reject)
// and must not send a redacted_thinking block with missing data.

interface CapturedRequest {
	body: Record<string, unknown>;
}

const emptyUsage: Usage = {
	input: 0,
	output: 0,
	cacheRead: 0,
	cacheWrite: 0,
	totalTokens: 0,
	cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
};

function createModel(baseUrl: string): Model<"anthropic-messages"> {
	return {
		id: "claude-haiku-4-5",
		name: "Claude Haiku 4.5",
		api: "anthropic-messages",
		provider: "test-anthropic",
		baseUrl,
		reasoning: true,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 200000,
		maxTokens: 32000,
	};
}

async function readRequestBody(request: IncomingMessage): Promise<Record<string, unknown>> {
	const chunks: Buffer[] = [];
	for await (const chunk of request) {
		chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
	}
	return JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
}

function writeEmptySseResponse(response: ServerResponse): void {
	response.writeHead(200, { "content-type": "text/event-stream" });
	response.end();
}

async function captureAnthropicRequest(context: Context): Promise<CapturedRequest> {
	let capturedRequest: CapturedRequest | undefined;

	const server = createServer(async (request, response) => {
		capturedRequest = { body: await readRequestBody(request) };
		writeEmptySseResponse(response);
	});

	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address() as AddressInfo;

	try {
		const stream = streamAnthropic(createModel(`http://127.0.0.1:${address.port}`), context, {
			apiKey: "test-key",
			cacheRetention: "none",
		});

		for await (const event of stream) {
			if (event.type === "done" || event.type === "error") break;
		}
	} finally {
		await new Promise<void>((resolve, reject) => {
			server.close((error) => (error ? reject(error) : resolve()));
		});
	}

	if (!capturedRequest) {
		throw new Error("Anthropic request was not captured");
	}
	return capturedRequest;
}

function buildContextWithRedactedThinking(thinkingSignature: string | undefined): Context {
	const priorAssistantMessage: AssistantMessage = {
		role: "assistant",
		content: [
			{
				type: "thinking",
				thinking: "[Reasoning redacted]",
				redacted: true,
				...(thinkingSignature !== undefined ? { thinkingSignature } : {}),
			},
			{ type: "text", text: "Here is my answer." },
		],
		api: "anthropic-messages",
		provider: "test-anthropic",
		model: "claude-haiku-4-5",
		usage: emptyUsage,
		stopReason: "stop",
		timestamp: 1,
	};

	return {
		messages: [
			{ role: "user", content: "First question", timestamp: 0 },
			priorAssistantMessage,
			{ role: "user", content: "Follow-up question", timestamp: 2 },
		],
	};
}

describe("Anthropic redacted thinking replay", () => {
	it("drops a redacted thinking block that has no signature (old session) instead of sending malformed data", async () => {
		const request = await captureAnthropicRequest(buildContextWithRedactedThinking(undefined));

		const assistantMessage = (request.body.messages as Array<{ role: string; content: unknown }>).find(
			(m) => m.role === "assistant",
		);
		expect(assistantMessage).toBeDefined();
		const blocks = assistantMessage?.content as Array<{ type: string; data?: unknown }>;
		expect(blocks.some((b) => b.type === "redacted_thinking")).toBe(false);
		expect(blocks.some((b) => b.type === "text")).toBe(true);
	});

	it("replays a redacted thinking block that has a signature as redacted_thinking", async () => {
		const request = await captureAnthropicRequest(buildContextWithRedactedThinking("opaque-signature"));

		const assistantMessage = (request.body.messages as Array<{ role: string; content: unknown }>).find(
			(m) => m.role === "assistant",
		);
		expect(assistantMessage).toBeDefined();
		const blocks = assistantMessage?.content as Array<{ type: string; data?: unknown }>;
		const redacted = blocks.find((b) => b.type === "redacted_thinking");
		expect(redacted).toBeDefined();
		expect(redacted?.data).toBe("opaque-signature");
	});
});
