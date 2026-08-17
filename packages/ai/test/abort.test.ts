import { afterEach, describe, expect, it } from "vitest";
import { fauxAssistantMessage, registerFauxProvider } from "../src/providers/faux.js";
import { complete, stream } from "../src/stream.js";
import type { Context } from "../src/types.js";

/**
 * (C6) `abort.live.test.ts` proves these same behaviors against real
 * providers, but every case there needs a live API key — mid-stream abort
 * semantics were otherwise completely untested without keys. This exercises
 * the identical `stream`/`complete` code path through the faux provider
 * instead, with `tokensPerSecond` pacing so a test can genuinely abort while
 * a response is still in flight (not just after it's already finished).
 */

const registrations: Array<{ unregister: () => void }> = [];

afterEach(() => {
	for (const registration of registrations.splice(0)) {
		registration.unregister();
	}
});

function makeContext(text = "Hello"): Context {
	return { messages: [{ role: "user", content: text, timestamp: Date.now() }] };
}

describe("abort semantics (faux provider — see abort.live.test.ts for real-API equivalents)", () => {
	it("aborting mid-stream sets stopReason to aborted and preserves content produced before the abort", async () => {
		const registration = registerFauxProvider({ tokensPerSecond: 100, tokenSize: { min: 3, max: 3 } });
		registrations.push(registration);
		registration.setResponses([fauxAssistantMessage("abcdefghijklmnopqrstuvwxyz")]);

		const controller = new AbortController();
		let deltaCount = 0;
		const response = stream(registration.getModel(), makeContext(), { signal: controller.signal });
		for await (const event of response) {
			if (event.type === "text_delta") {
				deltaCount++;
				controller.abort();
			}
		}
		const msg = await response.result();

		expect(msg.stopReason).toBe("aborted");
		expect(deltaCount).toBeGreaterThan(0);
		// Partial content produced before the abort must be preserved, not discarded.
		expect(msg.content.length).toBeGreaterThan(0);
	});

	it("a conversation can continue normally after a mid-stream abort", async () => {
		const registration = registerFauxProvider({ tokensPerSecond: 100, tokenSize: { min: 3, max: 3 } });
		registrations.push(registration);
		registration.setResponses([
			fauxAssistantMessage("abcdefghijklmnopqrstuvwxyz"),
			fauxAssistantMessage("follow-up done"),
		]);

		const context = makeContext();
		const controller = new AbortController();
		const response = stream(registration.getModel(), context, { signal: controller.signal });
		for await (const event of response) {
			if (event.type === "text_delta") {
				controller.abort();
			}
		}
		const aborted = await response.result();
		expect(aborted.stopReason).toBe("aborted");

		// Mirrors what the real coding agent does: push the aborted assistant
		// message into context, then continue the conversation normally.
		context.messages.push(aborted);
		context.messages.push({ role: "user", content: "Please continue.", timestamp: Date.now() });

		const followUp = await complete(registration.getModel(), context);
		expect(followUp.stopReason).toBe("stop");
		expect(followUp.content.length).toBeGreaterThan(0);
	});

	it("an already-aborted signal short-circuits before any content is produced", async () => {
		const registration = registerFauxProvider();
		registrations.push(registration);
		registration.setResponses([fauxAssistantMessage("should never be seen")]);

		const controller = new AbortController();
		controller.abort();

		const response = await complete(registration.getModel(), makeContext(), { signal: controller.signal });

		expect(response.stopReason).toBe("aborted");
		expect(response.content.length).toBe(0);
	});

	it("an aborted-then-continued conversation works even though the aborted message has empty content", async () => {
		const registration = registerFauxProvider();
		registrations.push(registration);
		// (faux provider detail) it shifts a queued response the moment stream()
		// is called, before checking the signal — even an immediately-aborted
		// call consumes one, so the follow-up call below needs its own.
		registration.setResponses([fauxAssistantMessage("hi there"), fauxAssistantMessage("4")]);

		const controller = new AbortController();
		controller.abort();
		const context = makeContext("Hello, how are you?");
		const abortedResponse = await complete(registration.getModel(), context, { signal: controller.signal });

		expect(abortedResponse.stopReason).toBe("aborted");
		// Aborted before anything arrived — content must be empty, not partial.
		expect(abortedResponse.content.length).toBe(0);

		context.messages.push(abortedResponse);
		context.messages.push({ role: "user", content: "What is 2 + 2?", timestamp: Date.now() });

		const followUp = await complete(registration.getModel(), context);
		expect(followUp.stopReason).toBe("stop");
		expect(followUp.content.length).toBeGreaterThan(0);
	});

	it("distinguishes a partial-content abort from a zero-content abort", async () => {
		const registration = registerFauxProvider({ tokensPerSecond: 100, tokenSize: { min: 3, max: 3 } });
		registrations.push(registration);

		registration.setResponses([fauxAssistantMessage("abcdefghijklmnopqrstuvwxyz")]);
		const midStreamController = new AbortController();
		const midStreamResponse = stream(registration.getModel(), makeContext(), { signal: midStreamController.signal });
		for await (const event of midStreamResponse) {
			if (event.type === "text_delta") midStreamController.abort();
		}
		const partial = await midStreamResponse.result();
		expect(partial.stopReason).toBe("aborted");
		expect(partial.content.length).toBeGreaterThan(0);

		registration.setResponses([fauxAssistantMessage("never streamed")]);
		const immediateController = new AbortController();
		immediateController.abort();
		const empty = await complete(registration.getModel(), makeContext(), { signal: immediateController.signal });
		expect(empty.stopReason).toBe("aborted");
		expect(empty.content.length).toBe(0);
	});
});
