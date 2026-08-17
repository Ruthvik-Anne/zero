import { describe, expect, it, vi } from "vitest";
import { getModel } from "../src/models.js";
import { streamSimple } from "../src/stream.js";
import type { Context, Model, SimpleStreamOptions } from "../src/types.js";

// (C6) capturePayload below deliberately targets an unreachable local port so
// the SDK's own retry-with-backoff genuinely runs before failing — that
// legitimately takes longer than the file-wide fast-unit-test default lowered
// to in the C6 fix, but far less than a real live-API test needs.
vi.setConfig({ testTimeout: 20000 });

interface MistralPayload {
	promptMode?: "reasoning";
	reasoningEffort?: "none" | "high";
}

function makeContext(): Context {
	return {
		messages: [{ role: "user", content: "Hello", timestamp: Date.now() }],
	};
}

async function capturePayload(
	model: Model<"mistral-conversations">,
	options?: SimpleStreamOptions,
): Promise<MistralPayload> {
	let capturedPayload: MistralPayload | undefined;
	const payloadCaptureModel: Model<"mistral-conversations"> = {
		...model,
		baseUrl: "http://127.0.0.1:9",
	};

	const stream = streamSimple(payloadCaptureModel, makeContext(), {
		...options,
		apiKey: "fake-key",
		onPayload: (payload) => {
			capturedPayload = payload as MistralPayload;
			return payload;
		},
	});

	await stream.result();

	if (!capturedPayload) {
		throw new Error("Expected payload to be captured before request failure");
	}

	return capturedPayload;
}

describe("Mistral reasoning mode selection", () => {
	it("uses reasoning_effort for Mistral Small 4", async () => {
		const payload = await capturePayload(getModel("mistral", "mistral-small-2603"), { reasoning: "medium" });

		expect(payload.reasoningEffort).toBe("high");
		expect(payload.promptMode).toBeUndefined();
	});

	it("omits reasoning controls for Mistral Small 4 when thinking is off", async () => {
		const payload = await capturePayload(getModel("mistral", "mistral-small-2603"));

		expect(payload.reasoningEffort).toBeUndefined();
		expect(payload.promptMode).toBeUndefined();
	});

	it("uses prompt_mode for Magistral reasoning models", async () => {
		const payload = await capturePayload(getModel("mistral", "magistral-medium-latest"), { reasoning: "medium" });

		expect(payload.promptMode).toBe("reasoning");
		expect(payload.reasoningEffort).toBeUndefined();
	});

	it("uses reasoning_effort for Mistral Medium 3.5", async () => {
		const payload = await capturePayload(getModel("mistral", "mistral-medium-3.5"), { reasoning: "medium" });

		expect(payload.reasoningEffort).toBe("high");
		expect(payload.promptMode).toBeUndefined();
	});

	it("omits reasoning controls for Mistral Medium 3.5 when thinking is off", async () => {
		const payload = await capturePayload(getModel("mistral", "mistral-medium-3.5"));

		expect(payload.reasoningEffort).toBeUndefined();
		expect(payload.promptMode).toBeUndefined();
	});
});
