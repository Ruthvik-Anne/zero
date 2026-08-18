import { fauxAssistantMessage } from "@zero-agent/ai";
import { afterEach, describe, expect, it } from "vitest";
import { createHarness, getAssistantTexts, type Harness } from "../harness.js";

describe("issue #3317 network connection lost retry", () => {
	const harnesses: Harness[] = [];

	afterEach(() => {
		while (harnesses.length > 0) {
			harnesses.pop()?.cleanup();
		}
	});

	it('retries transient "Network connection lost." failures', async () => {
		const harness = await createHarness({
			settings: { retry: { enabled: true, maxRetries: 3, baseDelayMs: 1 } },
		});
		harnesses.push(harness);
		harness.setResponses([
			() => ({
				...fauxAssistantMessage("", { stopReason: "error", errorMessage: "Network connection lost." }),
				diagnostics: [
					{
						type: "provider_stream_failure",
						timestamp: Date.now(),
						details: { kind: "network_error" },
					},
				],
			}),
			fauxAssistantMessage("recovered after reconnect"),
		]);

		await harness.session.prompt("test");

		expect(harness.faux.state.callCount).toBe(2);
		expect(harness.eventsOfType("auto_retry_start").map((event) => event.errorMessage)).toEqual([
			"Network connection lost.",
		]);
		// Classified as "network_error" so the TUI can say "Reconnecting" instead
		// of the generic "Retrying" — see interactive-mode.ts's auto_retry_start handler.
		expect(harness.eventsOfType("auto_retry_start").map((event) => event.kind)).toEqual(["network_error"]);
		expect(harness.eventsOfType("auto_retry_end").map((event) => event.success)).toEqual([true]);
		expect(getAssistantTexts(harness)).toContain("recovered after reconnect");
	});
});
