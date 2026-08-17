import { randomUUID } from "node:crypto";
import type { Agent } from "@zero-agent/agent-core";
import type { Model } from "@zero-agent/ai";
import { startSideQuestion } from "../side-question.js";

/**
 * Native advisor (module E) — the same role the advisor tool plays in Claude
 * Code itself: a stronger, more skeptical reviewer that sees the full
 * conversation transcript and gives a candid second opinion before more work
 * builds on a possibly-wrong assumption. Built natively on top of the existing
 * side-conversation mechanism (`side-question.ts`) rather than a new
 * transcript-cloning implementation — same tool-less clone of the live
 * conversation, different framing instruction (and optionally a different,
 * stronger model).
 */

export const DEFAULT_ADVISOR_QUESTION =
	"Review my recent approach and progress in this conversation. Is the current plan sound? Are there risks, wrong assumptions, missed simpler approaches, or contradicting evidence I should address before continuing?";

export const ADVISOR_INSTRUCTION =
	"You are acting as a stronger, more skeptical reviewer of the work above. You see the full conversation transcript above — every tool call and result, the reasoning that led here — and must give a candid second opinion BEFORE more work builds on a possibly-wrong assumption. Do not simply agree with the approach taken. Look specifically for: a wrong assumption baked in early, a simpler approach being missed, a risk or edge case that hasn't been considered, or evidence already in the transcript that contradicts the current plan. If the approach is genuinely sound, say so briefly rather than inventing problems. Be direct, specific, and concise — reference concrete points in the transcript rather than generic advice.";

export interface AdvisorConsultResult {
	advice: string;
	status: "complete" | "error" | "cancelled";
	errorMessage?: string;
}

/**
 * Run one advisor consultation to completion. `overrideModel`, when given,
 * routes the consultation to a different (typically stronger) model than the
 * active session model — omit it to review with the same model.
 *
 * (D13) `signal`, when given, lets a caller cancel a still-running
 * consultation — `startSideQuestion`'s returned `SideQuestionRun` already
 * has an `abort()` for exactly this; this just wires an external signal to
 * it. Without it, there was no way to interrupt a loop-audit consultation
 * (Esc during one left the turn blocked until the advisor call finished on
 * its own, however long that took).
 */
export async function consultAdvisor(
	parent: Agent,
	question: string = DEFAULT_ADVISOR_QUESTION,
	overrideModel?: Model<any>,
	signal?: AbortSignal,
): Promise<AdvisorConsultResult> {
	let advice = "";
	let status: AdvisorConsultResult["status"] = "complete";
	let errorMessage: string | undefined;

	const run = startSideQuestion(
		parent,
		randomUUID(),
		question,
		(event) => {
			advice = event.answer;
			if (event.status === "error" || event.status === "cancelled") {
				status = event.status;
				errorMessage = event.errorMessage;
			}
		},
		[],
		ADVISOR_INSTRUCTION,
		overrideModel,
	);

	if (signal) {
		if (signal.aborted) {
			run.abort();
		} else {
			signal.addEventListener("abort", () => run.abort(), { once: true });
		}
	}

	await run.done;
	return { advice, status, errorMessage };
}
