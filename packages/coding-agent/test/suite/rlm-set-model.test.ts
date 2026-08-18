import { afterEach, describe, expect, it } from "vitest";
import { createHarness, type Harness } from "./harness.js";

/**
 * `rlm.set_model(model=..., model_class="same"|"smaller")` — the self-switch
 * counterpart to `rlm.run(modelClass=...)`: lets the running agent change its
 * OWN active model instead of only being able to pick one for a spawned
 * child. Reuses the exact same resolution helpers and classification data as
 * `rlm.run`'s modelClass option (see rlm-model-class.test.ts).
 */
describe("rlm.set_model (self-switch)", () => {
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
		expect(harness.session.model?.name).toBe("Claude Opus 4.8"); // sanity: session starts on the expensive model
		return harness;
	}

	it('switches the session itself to a cheaper same-class model with model_class="same"', async () => {
		const harness = await createTwoTierHarness();
		const result = await harness.session.handleRlmSetModel({ modelClass: "same" });

		expect(harness.session.model?.name).toBe("GLM-5.2");
		expect(result.model).toBe(`${harness.session.model?.provider}/cheap-same-class`);
	});

	it('considers a smaller class with model_class="smaller", but same-class still ranks first', async () => {
		const harness = await createTwoTierHarness();
		await harness.session.handleRlmSetModel({ modelClass: "smaller" });

		expect(harness.session.model?.name).toBe("GLM-5.2");
	});

	it("switches to an explicitly requested model by exact selector", async () => {
		const harness = await createTwoTierHarness();
		const result = await harness.session.handleRlmSetModel({
			model: `${harness.session.model?.provider}/cheaper-smaller-class`,
		});

		expect(harness.session.model?.name).toBe("GPT-5.4 Mini");
		expect(result.model).toBe(`${harness.session.model?.provider}/cheaper-smaller-class`);
	});

	it("leaves the current model unchanged when nothing in-class is available", async () => {
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

		await harness.session.handleRlmSetModel({ modelClass: "same" });
		expect(harness.session.model?.name).toBe("Totally Unclassified Custom Model");
	});

	it("rejects model_class combined with an explicit model selector as ambiguous", async () => {
		const harness = await createTwoTierHarness();
		await expect(
			harness.session.handleRlmSetModel({
				modelClass: "same",
				model: `${harness.session.model?.provider}/expensive`,
			}),
		).rejects.toThrow(/mutually exclusive/);
	});

	it("rejects an unrecognized model_class value", async () => {
		const harness = await createTwoTierHarness();
		await expect(harness.session.handleRlmSetModel({ modelClass: "tiny" as never })).rejects.toThrow(
			/model_class must be "same" or "smaller"/,
		);
	});
});
