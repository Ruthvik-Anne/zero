import { describe, expect, it } from "vitest";
import {
	createGoalContextMessage,
	emptyGoalState,
	type GoalState,
	unmetAcceptanceCriteria,
	validateAcceptanceCriteria,
	validateSubGoals,
} from "../src/core/goals.js";

function activeGoal(overrides: Partial<GoalState> = {}): GoalState {
	return {
		...emptyGoalState(),
		active: true,
		status: "active",
		objective: "ship the feature",
		...overrides,
	};
}

describe("goals.ts sub-goals / acceptance criteria (module D)", () => {
	describe("validateSubGoals", () => {
		it("returns undefined when omitted", () => {
			expect(validateSubGoals(undefined)).toBeUndefined();
		});

		it("normalizes plain strings into SubGoal objects", () => {
			const result = validateSubGoals(["a", "b"]);
			expect(result).toHaveLength(2);
			expect(result?.[0]).toMatchObject({ text: "a", done: false });
			expect(typeof result?.[0]?.id).toBe("string");
		});

		it("preserves an explicit id and done flag on object entries", () => {
			const result = validateSubGoals([{ id: "sg_fixed", text: "a", done: true }]);
			expect(result?.[0]).toEqual({ id: "sg_fixed", text: "a", done: true });
		});

		it("rejects non-array input", () => {
			expect(() => validateSubGoals("nope")).toThrow("sub_goals must be an array");
		});

		it("rejects an empty-string entry", () => {
			expect(() => validateSubGoals([""])).toThrow("sub_goals entries must not be empty");
		});
	});

	describe("validateAcceptanceCriteria / unmetAcceptanceCriteria", () => {
		it("reports every criterion unmet by default", () => {
			const criteria = validateAcceptanceCriteria(["tests pass", "docs updated"])!;
			const goal = activeGoal({ acceptanceCriteria: criteria });
			expect(unmetAcceptanceCriteria(goal)).toHaveLength(2);
		});

		it("reports none unmet once all are marked met", () => {
			const criteria = validateAcceptanceCriteria([{ text: "tests pass", met: true }])!;
			const goal = activeGoal({ acceptanceCriteria: criteria });
			expect(unmetAcceptanceCriteria(goal)).toHaveLength(0);
		});

		it("a goal with no acceptance criteria at all has none unmet", () => {
			expect(unmetAcceptanceCriteria(activeGoal())).toHaveLength(0);
		});
	});

	describe("per-turn re-injection renders the task list (anti-drift)", () => {
		it("includes sub-goal checkboxes and acceptance criteria in the continuation prompt", () => {
			const goal = activeGoal({
				subGoals: validateSubGoals([
					{ text: "write the code", done: true },
					{ text: "write tests", done: false },
				]),
				acceptanceCriteria: validateAcceptanceCriteria([{ text: "tests pass", met: false }]),
			});

			const message = createGoalContextMessage(goal, "continuation");
			const text = typeof message.content === "string" ? message.content : "";

			expect(text).toContain("[x] write the code");
			expect(text).toContain("[ ] write tests");
			expect(text).toContain("[ ] tests pass");
			expect(text).toContain("goal.complete() refuses while any are unmet");
		});

		it("omits the task-list section entirely when there are no sub-goals or criteria", () => {
			const message = createGoalContextMessage(activeGoal(), "continuation");
			const text = typeof message.content === "string" ? message.content : "";

			expect(text).not.toContain("Task list");
			expect(text).not.toContain("Acceptance criteria");
		});
	});
});
