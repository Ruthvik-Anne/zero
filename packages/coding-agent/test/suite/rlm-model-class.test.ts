import { afterEach, describe, expect, it } from "vitest";
import { createHarness, type Harness } from "./harness.js";

/**
 * Module G (task #19): `rlm.run(modelClass="same"|"smaller")` lets a subagent
 * opt into a cheaper live-available model ranked by classification class and
 * price, instead of exactly inheriting the parent's model. Both registered
 * faux models below are named after real class-S entries in the classification
 * snapshot ("Claude Opus 4.8", "GLM-5.2") so the store's fuzzy name match
 * actually resolves them.
 */
describe("rlm.run modelClass (module G, task #19)", () => {
	const harnesses: Harness[] = [];

	afterEach(() => {
		while (harnesses.length > 0) harnesses.pop()?.cleanup();
	});

	async function createTwoTierHarness(): Promise<Harness> {
		const harness = await createHarness({
			models: [
				{
					id: "expensive",
					name: "Claude Opus 4.8",
					reasoning: false,
					input: ["text"],
					cost: { input: 5, output: 25, cacheRead: 0, cacheWrite: 0 },
					contextWindow: 128000,
					maxTokens: 8192,
				},
				{
					id: "cheap-same-class",
					name: "GLM-5.2",
					reasoning: false,
					input: ["text"],
					cost: { input: 0.68, output: 2.14, cacheRead: 0, cacheWrite: 0 },
					contextWindow: 128000,
					maxTokens: 8192,
				},
				{
					id: "cheaper-smaller-class",
					name: "GPT-5.4 Mini", // class B — one tier below class S
					reasoning: false,
					input: ["text"],
					cost: { input: 0.1, output: 0.5, cacheRead: 0, cacheWrite: 0 },
					contextWindow: 128000,
					maxTokens: 8192,
				},
			],
		});
		harnesses.push(harness);
		expect(harness.session.model?.name).toBe("Claude Opus 4.8"); // sanity: parent runs the expensive model
		return harness;
	}

	it('routes the child to a cheaper same-class model with modelClass="same"', async () => {
		const harness = await createTwoTierHarness();
		const handle = await harness.session.runRlmChild("do a parallel task", { modelClass: "same" });
		const child = harness.session.getRlmChildSession(handle.rlm_child_id);
		expect(child?.model?.name).toBe("GLM-5.2");
	});

	it('considers a smaller class with modelClass="smaller", but still only if cheaper/available', async () => {
		const harness = await createTwoTierHarness();
		const handle = await harness.session.runRlmChild("do a parallel task", { modelClass: "smaller" });
		const child = harness.session.getRlmChildSession(handle.rlm_child_id);
		// Same-class ("GLM-5.2") ranks ahead of any smaller-class candidate
		// regardless of price, per rankSameClassModels' documented ordering.
		expect(child?.model?.name).toBe("GLM-5.2");
	});

	it("falls back to inheriting the parent's exact model when nothing in-class is available", async () => {
		const harness = await createHarness({
			models: [
				{
					id: "solo",
					name: "Totally Unclassified Custom Model",
					reasoning: false,
					input: ["text"],
					cost: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0 },
					contextWindow: 128000,
					maxTokens: 8192,
				},
			],
		});
		harnesses.push(harness);

		const handle = await harness.session.runRlmChild("do a task", { modelClass: "same" });
		const child = harness.session.getRlmChildSession(handle.rlm_child_id);
		expect(child?.model?.name).toBe("Totally Unclassified Custom Model");
	});

	it("rejects modelClass combined with an explicit model selector as ambiguous", async () => {
		const harness = await createTwoTierHarness();
		await expect(
			harness.session.runRlmChild("do a task", {
				modelClass: "same",
				model: `${harness.session.model?.provider}/expensive`,
			}),
		).rejects.toThrow(/mutually exclusive/);
	});

	it("rejects an unrecognized modelClass value", async () => {
		const harness = await createTwoTierHarness();
		await expect(harness.session.runRlmChild("do a task", { modelClass: "tiny" })).rejects.toThrow(
			/modelClass must be "same" or "smaller"/,
		);
	});
});
