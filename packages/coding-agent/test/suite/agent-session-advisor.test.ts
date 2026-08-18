import { fauxAssistantMessage } from "@zero-agent/ai";
import { afterEach, describe, expect, it } from "vitest";
import { createHarness, getMessageText, type Harness } from "./harness.js";

/**
 * module E: native advisor.consult host-request — the same role Claude Code's
 * own advisor tool plays, built on the existing side-conversation mechanism
 * (side-question.ts) with a review-oriented framing instead of a plain Q&A one.
 */
describe("AgentSession advisor", () => {
	const harnesses: Harness[] = [];

	afterEach(() => {
		while (harnesses.length > 0) harnesses.pop()?.cleanup();
	});

	async function createAdvisorHarness(): Promise<Harness> {
		const harness = await createHarness();
		harnesses.push(harness);
		return harness;
	}

	it("returns the reviewer model's advice without touching main session state", async () => {
		const harness = await createAdvisorHarness();
		harness.setResponses([fauxAssistantMessage("main work happened here")]);
		await harness.session.prompt("Do the thing.");
		const messagesBefore = structuredClone(harness.session.messages);

		harness.setResponses([
			(context) => {
				const promptText = context.messages.map(getMessageText).join("\n");
				expect(promptText).toContain("stronger, more skeptical reviewer");
				expect(promptText).toContain("Review my recent approach");
				return fauxAssistantMessage("The approach looks sound; consider edge case X.");
			},
		]);

		const result = await harness.session.handleAdvisorHostRequest({});

		expect(result.outcome).toBe("complete");
		expect(result.advice).toBe("The approach looks sound; consider edge case X.");
		expect(result.error_message).toBeNull();
		// The main session transcript is untouched by the consultation.
		expect(harness.session.messages).toEqual(messagesBefore);
	});

	it("passes a custom question through to the reviewer", async () => {
		const harness = await createAdvisorHarness();
		harness.setResponses([
			(context) => {
				const promptText = context.messages.map(getMessageText).join("\n");
				expect(promptText).toContain("Did I miss a simpler approach for the retry logic?");
				return fauxAssistantMessage("Yes — exponential backoff is unnecessary here.");
			},
		]);

		const result = await harness.session.handleAdvisorHostRequest({
			question: "Did I miss a simpler approach for the retry logic?",
		});

		expect(result.advice).toBe("Yes — exponential backoff is unnecessary here.");
	});

	it("rejects a non-string question", async () => {
		const harness = await createAdvisorHarness();

		await expect(harness.session.handleAdvisorHostRequest({ question: 123 })).rejects.toThrow(
			"advisor.consult question must be a string when provided",
		);
	});

	it("defaults to a class-S reviewer, not the session's own (unclassified) model", async () => {
		// "Claude Opus 4.8" and "GLM-5.2" are both real class-S entries in the
		// classification snapshot (see rlm-model-class.test.ts) — GLM-5.2 is
		// cheaper, so rankSameClassModels' price tiebreak should pick it.
		const harness = await createHarness({
			provider: "anthropic",
			models: [
				{
					id: "session-model",
					name: "Session Model",
					reasoning: false,
					input: ["text"],
					cost: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0 },
					contextWindow: 128000,
					maxTokens: 8192,
				},
				{
					id: "expensive-s-class",
					name: "Claude Opus 4.8",
					reasoning: true,
					input: ["text"],
					cost: { input: 5, output: 25, cacheRead: 0, cacheWrite: 0 },
					contextWindow: 200000,
					maxTokens: 8192,
				},
				{
					id: "cheap-s-class",
					name: "GLM-5.2",
					reasoning: false,
					input: ["text"],
					cost: { input: 0.68, output: 2.14, cacheRead: 0, cacheWrite: 0 },
					contextWindow: 128000,
					maxTokens: 8192,
				},
			],
		});
		harnesses.push(harness);
		expect(harness.session.model?.id).toBe("session-model"); // sanity: session runs the unclassified model

		let modelUsedForReview: string | undefined;
		harness.setResponses([
			(_context, _options, _state, model) => {
				modelUsedForReview = model.id;
				return fauxAssistantMessage("Looks fine.");
			},
		]);

		await harness.session.handleAdvisorHostRequest({});

		expect(modelUsedForReview).toBe("cheap-s-class");
	});

	it("surfaces an error status without throwing when the reviewer call fails", async () => {
		const harness = await createAdvisorHarness();
		harness.setResponses([
			fauxAssistantMessage("boom", { stopReason: "error", errorMessage: "reviewer unavailable" }),
		]);

		const result = await harness.session.handleAdvisorHostRequest({});

		expect(result.outcome).toBe("error");
		expect(result.error_message).toBe("reviewer unavailable");
	});
});
