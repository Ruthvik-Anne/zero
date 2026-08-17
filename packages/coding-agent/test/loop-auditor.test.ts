import { describe, expect, it } from "vitest";
import {
	buildLoopAuditQuestion,
	createLoopAuditContextMessage,
	createLoopAuditorState,
	recordLoopAuditorTurn,
	resetLoopAuditor,
	shouldRunLoopAudit,
} from "../src/core/advisor/loop-auditor.js";
import { emptyGoalState, validateSubGoals } from "../src/core/goals.js";

describe("loop-auditor.ts (module E)", () => {
	describe("trigger state", () => {
		it("is disabled by default (byte-identical to unconfigured behavior)", () => {
			const state = createLoopAuditorState();
			for (let i = 0; i < 100; i++) recordLoopAuditorTurn(state);
			expect(shouldRunLoopAudit(state)).toBe(false);
		});

		it("triggers once the configured turn interval is reached", () => {
			const state = createLoopAuditorState({ enabled: true, turnInterval: 3 });
			expect(shouldRunLoopAudit(state)).toBe(false);
			recordLoopAuditorTurn(state);
			recordLoopAuditorTurn(state);
			expect(shouldRunLoopAudit(state)).toBe(false);
			recordLoopAuditorTurn(state);
			expect(shouldRunLoopAudit(state)).toBe(true);
		});

		it("resets the counter after an audit runs", () => {
			const state = createLoopAuditorState({ enabled: true, turnInterval: 2 });
			recordLoopAuditorTurn(state);
			recordLoopAuditorTurn(state);
			expect(shouldRunLoopAudit(state)).toBe(true);
			resetLoopAuditor(state);
			expect(shouldRunLoopAudit(state)).toBe(false);
			expect(state.turnsSinceLastAudit).toBe(0);
		});

		it("falls back to the default interval for an invalid configured interval", () => {
			const state = createLoopAuditorState({ enabled: true, turnInterval: 0 });
			expect(state.turnInterval).toBeGreaterThan(0);
		});
	});

	describe("buildLoopAuditQuestion", () => {
		it("references the user's original request when no goal is active", () => {
			const question = buildLoopAuditQuestion(undefined);
			expect(question).toContain("the user's original request");
			expect(question).not.toContain("<objective>");
		});

		it("references the objective and task list when a goal is active", () => {
			const goal = {
				...emptyGoalState(),
				objective: "ship the feature",
				subGoals: validateSubGoals([{ text: "write tests", done: true }, "write docs"]),
			};
			const question = buildLoopAuditQuestion(goal);
			expect(question).toContain("<objective>\nship the feature\n</objective>");
			expect(question).toContain("[x] write tests");
			expect(question).toContain("[ ] write docs");
		});
	});

	describe("createLoopAuditContextMessage", () => {
		it("wraps the advisor's findings in a loop_audit block and preserves them in details", () => {
			const message = createLoopAuditContextMessage("Looks like scope creep on task 2 — refocus.");
			expect(message.customType).toBe("loop_audit_context");
			expect(message.content).toContain("<loop_audit>");
			expect(message.content).toContain("Looks like scope creep on task 2 — refocus.");
			expect(message.details?.advice).toBe("Looks like scope creep on task 2 — refocus.");
		});
	});
});
