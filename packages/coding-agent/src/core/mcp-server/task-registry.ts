import { randomUUID } from "node:crypto";
import type { AgentSession } from "../agent-session.js";

/**
 * Module J — MCP server mode. Zero exposes itself as a small, cheap
 * worker-harness MCP server (`run_task`/`get_status`/`get_result`/`answer`),
 * never its internal tool surface. This registry is the state each of those
 * four MCP tools reads/writes; one entry per `run_task` call, one full Zero
 * session (queue, RLM, harness, goal, harm-check — everything) driving it
 * internally.
 */

export type McpTaskStatus = "running" | "waiting_for_answer" | "done" | "error";

export type McpPendingQuestionMethod = "select" | "confirm" | "input";

export interface McpPendingQuestion {
	questionId: string;
	method: McpPendingQuestionMethod;
	title: string;
	message?: string;
	options?: string[];
	placeholder?: string;
}

export interface McpTaskNotification {
	message: string;
	notifyType: "info" | "warning" | "error";
	at: number;
}

export interface McpTaskResult {
	text: string;
	success: boolean;
}

export interface McpTaskSnapshot {
	id: string;
	prompt: string;
	mode?: string;
	status: McpTaskStatus;
	createdAt: number;
	pendingQuestion?: McpPendingQuestion;
	notifications: McpTaskNotification[];
	result?: McpTaskResult;
	error?: string;
}

/** Response the answer() tool hands back to a pending select/confirm/input. */
export type McpAnswerResponse = { cancelled: true } | { cancelled: false; value?: string; confirmed?: boolean };

/**
 * Interprets the `answer` MCP tool's raw `{response, cancelled}` input against
 * the specific pending question it's answering. Method-aware on purpose: a
 * `confirm` question needs a boolean, everything else needs a string — a
 * mismatched type is rejected rather than silently coerced (a bare
 * `Boolean(undefined)` on a wrong-typed response would previously read as a
 * silent "no" to a confirm, which fails closed but is still a wrong answer).
 */
export function resolveAnswerPayload(
	pending: McpPendingQuestion,
	input: { response?: string | boolean; cancelled?: boolean },
): { ok: true; payload: McpAnswerResponse } | { ok: false; error: string } {
	if (input.cancelled || input.response === undefined) {
		return { ok: true, payload: { cancelled: true } };
	}
	if (pending.method === "confirm") {
		if (typeof input.response !== "boolean") {
			return {
				ok: false,
				error: `this question is method=confirm; response must be a boolean, got ${typeof input.response}`,
			};
		}
		return { ok: true, payload: { cancelled: false, confirmed: input.response } };
	}
	if (typeof input.response !== "string") {
		return {
			ok: false,
			error: `this question is method=${pending.method}; response must be a string, got ${typeof input.response}`,
		};
	}
	return { ok: true, payload: { cancelled: false, value: input.response } };
}

const MAX_NOTIFICATIONS_PER_TASK = 20;
/**
 * (D13) The task map was never evicted — a long-lived server accumulates one
 * entry per run_task call forever. Terminal (done/error) tasks are pruned
 * oldest-first once the map exceeds this bound; a still-running/waiting task
 * is never evicted regardless of count (that would silently orphan a live
 * session with no way to poll it) — task-runner.ts's own concurrency cap is
 * what actually bounds how many of those can exist at once.
 */
const MAX_TRACKED_TASKS = 500;

function isTerminal(status: McpTaskStatus): boolean {
	return status === "done" || status === "error";
}

interface InternalTask extends McpTaskSnapshot {
	session?: AgentSession;
	resolvePending?: (response: McpAnswerResponse) => void;
}

/** In-memory registry of MCP-driven Zero tasks. One process, one registry. */
export class McpTaskRegistry {
	private readonly tasks = new Map<string, InternalTask>();

	/** (D13) Tasks not yet done/errored — what task-runner.ts's concurrency cap counts against. */
	countActive(): number {
		let count = 0;
		for (const task of this.tasks.values()) {
			if (!isTerminal(task.status)) count++;
		}
		return count;
	}

	private pruneTerminalTasksIfOverCapacity(): void {
		if (this.tasks.size < MAX_TRACKED_TASKS) return;
		const terminal = [...this.tasks.values()].filter((task) => isTerminal(task.status));
		terminal.sort((a, b) => a.createdAt - b.createdAt);
		const overBy = this.tasks.size - MAX_TRACKED_TASKS + 1;
		for (const task of terminal.slice(0, overBy)) {
			this.tasks.delete(task.id);
		}
	}

	create(prompt: string, mode?: string): { id: string; attach: (session: AgentSession) => void } {
		this.pruneTerminalTasksIfOverCapacity();
		const id = randomUUID();
		const task: InternalTask = {
			id,
			prompt,
			mode,
			status: "running",
			createdAt: Date.now(),
			notifications: [],
		};
		this.tasks.set(id, task);
		return {
			id,
			attach: (session) => {
				task.session = session;
			},
		};
	}

	private require(id: string): InternalTask {
		const task = this.tasks.get(id);
		if (!task) {
			throw new Error(`unknown task_id: ${id}`);
		}
		return task;
	}

	snapshot(id: string): McpTaskSnapshot {
		const { session: _session, resolvePending: _resolvePending, ...snapshot } = this.require(id);
		return snapshot;
	}

	has(id: string): boolean {
		return this.tasks.has(id);
	}

	notify(id: string, message: string, notifyType: "info" | "warning" | "error"): void {
		const task = this.tasks.get(id);
		if (!task) return;
		task.notifications.push({ message, notifyType, at: Date.now() });
		if (task.notifications.length > MAX_NOTIFICATIONS_PER_TASK) {
			task.notifications.splice(0, task.notifications.length - MAX_NOTIFICATIONS_PER_TASK);
		}
	}

	/**
	 * Called from the task's UI context (select/confirm/input). Records the
	 * pending question, flips status to `waiting_for_answer`, and returns a
	 * promise that resolves once `answer()` (or task teardown) settles it.
	 */
	askQuestion(
		id: string,
		question: Omit<McpPendingQuestion, "questionId">,
		signal?: AbortSignal,
	): Promise<McpAnswerResponse> {
		const task = this.require(id);
		if (signal?.aborted) {
			return Promise.resolve({ cancelled: true });
		}
		const questionId = randomUUID();
		task.pendingQuestion = { ...question, questionId };
		task.status = "waiting_for_answer";
		return new Promise<McpAnswerResponse>((resolve) => {
			const settle = (response: McpAnswerResponse) => {
				signal?.removeEventListener("abort", onAbort);
				task.pendingQuestion = undefined;
				task.resolvePending = undefined;
				if (task.status === "waiting_for_answer") {
					task.status = "running";
				}
				resolve(response);
			};
			const onAbort = () => settle({ cancelled: true });
			signal?.addEventListener("abort", onAbort, { once: true });
			task.resolvePending = settle;
		});
	}

	/** Resolves the task's pending question. Returns false if it doesn't match. */
	answer(id: string, questionId: string, response: McpAnswerResponse): boolean {
		const task = this.tasks.get(id);
		if (!task?.pendingQuestion || !task.resolvePending || task.pendingQuestion.questionId !== questionId) {
			return false;
		}
		task.resolvePending(response);
		return true;
	}

	markDone(id: string, result: McpTaskResult): void {
		const task = this.require(id);
		task.status = "done";
		task.result = result;
	}

	markError(id: string, error: string): void {
		const task = this.require(id);
		task.status = "error";
		task.error = error;
	}

	/**
	 * Cancels a task: resolves any pending question as cancelled (unblocking
	 * an in-flight ask_user/harm-check confirm immediately, since nothing else
	 * on this path times out) and requests the underlying session abort so a
	 * task that isn't currently waiting on a question also stops rather than
	 * leaking its session/kernel for the server's lifetime. Returns false for
	 * an unknown task_id.
	 */
	cancel(id: string): boolean {
		const task = this.tasks.get(id);
		if (!task) return false;
		if (task.pendingQuestion && task.resolvePending) {
			task.resolvePending({ cancelled: true });
		}
		task.session?.requestAbort();
		return true;
	}

	/** Best-effort cancel of every still-live task — used on server shutdown. */
	cancelAll(): void {
		for (const id of this.tasks.keys()) this.cancel(id);
	}
}
