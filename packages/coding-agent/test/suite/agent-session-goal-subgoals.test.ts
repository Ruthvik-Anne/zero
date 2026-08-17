import type { AgentTool } from "@zero-agent/agent-core";
import { afterEach, describe, expect, it } from "vitest";
import type { Harness } from "./harness.js";
import { createHarness } from "./harness.js";

/**
 * module D: GoalState.subGoals (task list) and acceptanceCriteria (definition
 * of done) — the same underlying structure serves both the Claude-Code-style
 * anti-drift task list and goal decomposition, re-injected via goals.ts's
 * existing per-turn continuation prompt.
 */
describe("AgentSession goal sub-goals and acceptance criteria", () => {
	let harnesses: Harness[] = [];

	afterEach(() => {
		for (const harness of harnesses) harness.cleanup();
		harnesses = [];
	});

	async function createGoalHarness(extraTools: AgentTool[] = []): Promise<Harness> {
		const harness = await createHarness({ tools: extraTools });
		harnesses.push(harness);
		return harness;
	}

	it("accepts sub_goals and acceptance_criteria as plain strings at creation", async () => {
		const harness = await createGoalHarness();

		const created = harness.session.handleGoalHostRequest("goal.create", {
			objective: "ship the feature",
			sub_goals: ["write the code", "write tests", "update docs"],
			acceptance_criteria: ["tests pass", "docs mention the new flag"],
		});

		expect(created.goal?.sub_goals).toHaveLength(3);
		expect(created.goal?.sub_goals?.[0]).toMatchObject({ text: "write the code", done: false });
		expect(created.goal?.acceptance_criteria).toHaveLength(2);
		expect(created.goal?.acceptance_criteria?.[0]).toMatchObject({ text: "tests pass", met: false });
	});

	it("refuses goal.complete() while any acceptance criterion is unmet", async () => {
		const harness = await createGoalHarness();
		harness.session.handleGoalHostRequest("goal.create", {
			objective: "ship the feature",
			acceptance_criteria: ["tests pass", "docs updated"],
		});

		expect(() => harness.session.handleGoalHostRequest("goal.complete")).toThrow(
			/cannot complete goal: 2 acceptance criteria are unmet/,
		);
	});

	it("allows goal.complete() once every acceptance criterion is met via goal.update", async () => {
		const harness = await createGoalHarness();
		const created = harness.session.handleGoalHostRequest("goal.create", {
			objective: "ship the feature",
			acceptance_criteria: ["tests pass"],
		});
		const criterionId = created.goal?.acceptance_criteria?.[0]?.id;

		harness.session.handleGoalHostRequest("goal.update", {
			acceptance_criteria: [{ id: criterionId, text: "tests pass", met: true }],
		});

		const completed = harness.session.handleGoalHostRequest("goal.complete");
		expect(completed.goal).toMatchObject({ status: "complete" });
	});

	it("goal.update replaces sub_goals without requiring acceptance_criteria, and vice versa", async () => {
		const harness = await createGoalHarness();
		harness.session.handleGoalHostRequest("goal.create", {
			objective: "ship the feature",
			sub_goals: ["step one"],
			acceptance_criteria: ["tests pass"],
		});

		const updated = harness.session.handleGoalHostRequest("goal.update", {
			sub_goals: [{ text: "step one", done: true }, "step two"],
		});

		expect(updated.goal?.sub_goals).toHaveLength(2);
		expect(updated.goal?.sub_goals?.[0]).toMatchObject({ text: "step one", done: true });
		// acceptance_criteria untouched by an update that only specifies sub_goals.
		expect(updated.goal?.acceptance_criteria).toHaveLength(1);
		expect(updated.goal?.acceptance_criteria?.[0]).toMatchObject({ text: "tests pass", met: false });
	});

	it("goal.update refuses when there is no active goal", async () => {
		const harness = await createGoalHarness();

		expect(() => harness.session.handleGoalHostRequest("goal.update", { sub_goals: ["x"] })).toThrow(
			"cannot update goal because this thread has no goal",
		);
	});

	it("rejects malformed sub_goals and acceptance_criteria payloads", async () => {
		const harness = await createGoalHarness();

		expect(() =>
			harness.session.handleGoalHostRequest("goal.create", { objective: "x", sub_goals: "not an array" }),
		).toThrow("sub_goals must be an array");
		expect(() => harness.session.handleGoalHostRequest("goal.create", { objective: "x", sub_goals: [123] })).toThrow(
			/sub_goals entries must be/,
		);
		expect(() =>
			harness.session.handleGoalHostRequest("goal.create", {
				objective: "x",
				acceptance_criteria: "not an array",
			}),
		).toThrow("acceptance_criteria must be an array");
	});

	it("plain string goal.create leaves sub_goals/acceptance_criteria undefined (backward compatible)", async () => {
		const harness = await createGoalHarness();

		const created = harness.session.handleGoalHostRequest("goal.create", { objective: "no decomposition" });

		expect(created.goal?.sub_goals).toBeUndefined();
		expect(created.goal?.acceptance_criteria).toBeUndefined();
		// A goal created without acceptance criteria completes normally.
		const completed = harness.session.handleGoalHostRequest("goal.complete");
		expect(completed.goal).toMatchObject({ status: "complete" });
	});
});
