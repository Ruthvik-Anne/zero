import type { GoalState } from "../goals.js";
import type { CustomMessage } from "../messages.js";

/**
 * Loop auditor (module E): periodically has the agent "take a break" from
 * active work to audit its own recent actions against the active goal/task
 * list and course-correct if needed. Built as a simple turn-interval counter
 * (mirroring autonomous.ts's plain-state style) rather than auto-refine's
 * heavier branch-versioned/abort-controller machinery — the loop auditor's
 * job is narrower: decide whether an audit is due, and inject its findings,
 * not apply structured edits to persisted state.
 *
 * The actual audit call reuses module E's advisor (`consultAdvisor`) — the
 * loop auditor is the advisor's periodic, self-triggered mode rather than a
 * separate review implementation.
 */

export const DEFAULT_LOOP_AUDITOR_TURN_INTERVAL = 15;

export interface LoopAuditorConfig {
	/** Default: false — opt-in, so an unconfigured session behaves exactly as before. */
	enabled?: boolean;
	/** Assistant turns between audits. Default: 15. */
	turnInterval?: number;
}

export interface LoopAuditorState {
	enabled: boolean;
	turnInterval: number;
	turnsSinceLastAudit: number;
}

export function createLoopAuditorState(config?: LoopAuditorConfig): LoopAuditorState {
	return {
		enabled: config?.enabled ?? false,
		turnInterval:
			config?.turnInterval && config.turnInterval > 0 ? config.turnInterval : DEFAULT_LOOP_AUDITOR_TURN_INTERVAL,
		turnsSinceLastAudit: 0,
	};
}

export function recordLoopAuditorTurn(state: LoopAuditorState): void {
	state.turnsSinceLastAudit++;
}

export function shouldRunLoopAudit(state: LoopAuditorState): boolean {
	return state.enabled && state.turnsSinceLastAudit >= state.turnInterval;
}

export function resetLoopAuditor(state: LoopAuditorState): void {
	state.turnsSinceLastAudit = 0;
}

/** Builds the self-audit question, referencing the live task list when a goal is active. */
export function buildLoopAuditQuestion(goal: GoalState | undefined): string {
	const intro =
		"Take a break from active work and audit your own recent actions in this conversation for drift — scope creep, an unproductive tangent, or repeating a failed approach.";
	if (!goal?.objective) {
		return `${intro} Judge against the user's original request. If drift is found, say exactly what to change; if the work is on track, say so briefly.`;
	}
	const taskListText =
		goal.subGoals && goal.subGoals.length > 0
			? `\nTask list:\n${goal.subGoals.map((item) => `- [${item.done ? "x" : " "}] ${item.text}`).join("\n")}`
			: "";
	return `${intro} Judge against the active goal.\n<objective>\n${goal.objective}\n</objective>${taskListText}\n\nAre you making real progress toward this objective? If drift is found, say exactly what to change; if the work is on track, say so briefly.`;
}

export const LOOP_AUDIT_CONTEXT_CUSTOM_TYPE = "loop_audit_context";

export interface LoopAuditContextDetails {
	advice: string;
}

export function createLoopAuditContextMessage(advice: string): CustomMessage<LoopAuditContextDetails> {
	const text = `<loop_audit>\nSelf-audit findings from a periodic review of your own recent work:\n\n${advice}\n\nAct on this now if it identifies a real problem; otherwise continue as planned.\n</loop_audit>`;
	return {
		role: "custom",
		customType: LOOP_AUDIT_CONTEXT_CUSTOM_TYPE,
		content: text,
		display: true,
		details: { advice },
		timestamp: Date.now(),
	};
}
