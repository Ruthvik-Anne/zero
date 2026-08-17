import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Model } from "@zero-agent/ai";
import { z } from "zod";
import type { AuthStorage } from "../auth-storage.js";
import type { ModelRegistry } from "../model-registry.js";
import type { SettingsManager } from "../settings-manager.js";
import { McpTaskRegistry, resolveAnswerPayload } from "./task-registry.js";
import { runTask } from "./task-runner.js";

export interface ZeroMcpServerOptions {
	cwd: string;
	agentDir?: string;
	name?: string;
	version?: string;
	/** Overrides for embedding with already-configured services (e.g. tests) instead of resolving from disk. */
	authStorage?: AuthStorage;
	modelRegistry?: ModelRegistry;
	settingsManager?: SettingsManager;
	model?: Model<any>;
}

function textResult(payload: unknown) {
	return { content: [{ type: "text" as const, text: JSON.stringify(payload) }] };
}

function errorResult(message: string) {
	return { content: [{ type: "text" as const, text: message }], isError: true };
}

export interface ZeroMcpServer {
	server: McpServer;
	/** Cancels every still-live task (pending questions + session abort). Call before shutdown to avoid leaking kernels. */
	cancelAllTasks(): void;
}

/**
 * Module J — Zero as an MCP server. A small, cheap worker-harness surface
 * (`run_task`/`get_status`/`get_result`/`answer`/`cancel_task`), not Zero's
 * internal tool surface: each `run_task` drives a full internal Zero session
 * (queue, RLM, harness, harm-check, goals — the whole runtime), but the
 * external MCP caller only ever sees this five-tool protocol. Lets any MCP
 * client (Claude Desktop, Claude Code, another orchestrator) wire Zero in as
 * a delegate worker without reimplementing or exposing its internals.
 */
export function createZeroMcpServer(options: ZeroMcpServerOptions): ZeroMcpServer {
	const registry = new McpTaskRegistry();
	const server = new McpServer({
		name: options.name ?? "zero",
		version: options.version ?? "0.1.0",
	});

	server.registerTool(
		"run_task",
		{
			title: "Run a Zero task",
			description:
				"Submit a prompt to a fresh, full-capability Zero agent session and return immediately with a task_id. " +
				"Poll get_status/get_result for progress and the final answer; call answer() if get_status reports a pending question.",
			inputSchema: {
				prompt: z.string().min(1).describe("The task/prompt to run."),
				mode: z.string().optional().describe("Advisory run mode (e.g. plan/auto/manual); not yet enforced."),
				budget: z
					.object({
						maxTokens: z.number().int().positive().optional(),
						timeoutMs: z.number().int().positive().optional(),
						maxTurns: z.number().int().positive().optional(),
						maxContinuations: z.number().int().positive().optional(),
					})
					.optional()
					.describe("Resource caps for this task, mapped onto Zero's autonomous-continuation limits."),
				allowRiskyActions: z
					.boolean()
					.optional()
					.describe(
						"Defaults to false. When false, a harm-check soft-block confirmation fails closed instead of " +
							"surfacing as a pending question — answer() can't be verified as a human who reviewed the " +
							"consequence line, so this must be explicitly opted into per task, not implied by having a " +
							"UI context bound at all.",
					),
			},
		},
		async ({ prompt, mode, budget, allowRiskyActions }) => {
			// (D13) runTask now throws synchronously when the concurrency cap is
			// hit, before creating a task entry — surface that as a normal tool
			// error instead of letting it propagate as a framework-level failure.
			try {
				const { taskId } = runTask(registry, {
					cwd: options.cwd,
					agentDir: options.agentDir,
					prompt,
					mode,
					budget,
					allowRiskyActions,
					authStorage: options.authStorage,
					modelRegistry: options.modelRegistry,
					settingsManager: options.settingsManager,
					model: options.model,
				});
				return textResult({ task_id: taskId });
			} catch (error) {
				return errorResult(error instanceof Error ? error.message : String(error));
			}
		},
	);

	server.registerTool(
		"get_status",
		{
			title: "Get Zero task status",
			description: "Check a run_task task's lifecycle status: running, waiting_for_answer, done, or error.",
			inputSchema: {
				task_id: z.string().min(1),
			},
		},
		async ({ task_id }) => {
			if (!registry.has(task_id)) return errorResult(`unknown task_id: ${task_id}`);
			const snapshot = registry.snapshot(task_id);
			return textResult({
				status: snapshot.status,
				mode: snapshot.mode,
				pending_question: snapshot.pendingQuestion
					? {
							question_id: snapshot.pendingQuestion.questionId,
							method: snapshot.pendingQuestion.method,
							title: snapshot.pendingQuestion.title,
							message: snapshot.pendingQuestion.message,
							options: snapshot.pendingQuestion.options,
							placeholder: snapshot.pendingQuestion.placeholder,
						}
					: undefined,
				notifications: snapshot.notifications,
			});
		},
	);

	server.registerTool(
		"get_result",
		{
			title: "Get Zero task result",
			description: "Fetch the final result of a run_task task once its status is done or error.",
			inputSchema: {
				task_id: z.string().min(1),
			},
		},
		async ({ task_id }) => {
			if (!registry.has(task_id)) return errorResult(`unknown task_id: ${task_id}`);
			const snapshot = registry.snapshot(task_id);
			if (snapshot.status === "done") {
				return textResult({
					status: "done",
					result: snapshot.result?.text ?? "",
					success: snapshot.result?.success,
				});
			}
			if (snapshot.status === "error") {
				return textResult({ status: "error", error: snapshot.error });
			}
			return textResult({ status: snapshot.status, message: "task has not finished yet" });
		},
	);

	server.registerTool(
		"answer",
		{
			title: "Answer a Zero task's pending question",
			description:
				"Resolve a task's pending ask_user/confirmation question (surfaced via get_status.pending_question). " +
				"For method=confirm pass a boolean response; for select pass one of pending_question.options; " +
				"for input pass free text. Omit response (or pass cancelled=true) to decline/cancel.",
			inputSchema: {
				task_id: z.string().min(1),
				question_id: z.string().min(1),
				response: z.union([z.string(), z.boolean()]).optional(),
				cancelled: z.boolean().optional(),
			},
		},
		async ({ task_id, question_id, response, cancelled }) => {
			if (!registry.has(task_id)) return errorResult(`unknown task_id: ${task_id}`);
			if (!cancelled && response !== undefined) {
				const pending = registry.snapshot(task_id).pendingQuestion;
				if (!pending || pending.questionId !== question_id) {
					return errorResult(`no matching pending question ${question_id} for task ${task_id}`);
				}
				const resolved = resolveAnswerPayload(pending, { response, cancelled });
				if (!resolved.ok) return errorResult(resolved.error);
				const ok = registry.answer(task_id, question_id, resolved.payload);
				if (!ok) return errorResult(`no matching pending question ${question_id} for task ${task_id}`);
				return textResult({ ok: true });
			}
			const ok = registry.answer(task_id, question_id, { cancelled: true });
			if (!ok) return errorResult(`no matching pending question ${question_id} for task ${task_id}`);
			return textResult({ ok: true });
		},
	);

	server.registerTool(
		"cancel_task",
		{
			title: "Cancel a Zero task",
			description:
				"Cancel a run_task task: resolves any pending question as cancelled and aborts the underlying session. " +
				"Use this to release a task instead of abandoning it — an unresolved pending question otherwise blocks forever.",
			inputSchema: {
				task_id: z.string().min(1),
			},
		},
		async ({ task_id }) => {
			const ok = registry.cancel(task_id);
			if (!ok) return errorResult(`unknown task_id: ${task_id}`);
			return textResult({ ok: true });
		},
	);

	return { server, cancelAllTasks: () => registry.cancelAll() };
}
