import type { Model } from "@zero-agent/ai";
import { selectHeadlessTerminalResult, waitForHeadlessCompletion } from "../../modes/headless-completion.js";
import type { AuthStorage } from "../auth-storage.js";
import type { ModelRegistry } from "../model-registry.js";
import type { SettingsManager } from "../settings-manager.js";
import { createMcpTaskUiContext } from "./mcp-task-ui-context.js";
import { createMcpWorkerSession, type McpTaskBudget } from "./session-factory.js";
import type { McpTaskRegistry } from "./task-registry.js";

/**
 * (D13) Each active task is a full Zero session plus an IPython kernel — a
 * client looping run_task with no cap would spawn unboundedly many of these.
 */
export const MAX_CONCURRENT_MCP_TASKS = 8;

export interface RunTaskOptions {
	cwd: string;
	agentDir?: string;
	prompt: string;
	mode?: string;
	budget?: McpTaskBudget;
	authStorage?: AuthStorage;
	modelRegistry?: ModelRegistry;
	settingsManager?: SettingsManager;
	model?: Model<any>;
	/**
	 * (D10) Explicit, per-task opt-in for module F's soft-block confirmations to
	 * actually round-trip through `answer()` instead of failing closed. Defaults
	 * to `false`: an MCP client answering a pending question can't be verified
	 * as a human who reviewed the consequence line, so a task must declare this
	 * intent up front rather than getting it implicitly from having a UI context
	 * bound at all (that context is also what `ask_user` needs to function).
	 */
	allowRiskyActions?: boolean;
}

/**
 * Kicks off a `run_task` call: creates a fresh Zero session, wires its UI
 * context to the task registry so `ask_user`/harm-check confirmations
 * surface as a pending question instead of hanging, and drives it to
 * completion in the background. Returns the task id immediately — this is
 * the "cheap task-submission round trip" the external MCP caller pays for;
 * it polls `get_status`/`get_result` rather than blocking on one long call.
 *
 * `mode` (plan/auto/manual) is recorded on the task but not yet enforced —
 * module I (native mode system) has not landed; once it does, this should
 * gate the session's active tools the same way an interactive session's
 * `/mode` command would.
 */
export function runTask(registry: McpTaskRegistry, options: RunTaskOptions): { taskId: string } {
	// (D13) Checked before registry.create() so an over-capacity call never
	// creates a task entry at all — the caller gets a clear rejection, not a
	// task_id for something that was never actually started.
	if (registry.countActive() >= MAX_CONCURRENT_MCP_TASKS) {
		throw new Error(
			`too many concurrent tasks (max ${MAX_CONCURRENT_MCP_TASKS}); wait for one to finish or call cancel_task`,
		);
	}
	const { id, attach } = registry.create(options.prompt, options.mode);

	void (async () => {
		let session: Awaited<ReturnType<typeof createMcpWorkerSession>>["session"] | undefined;
		try {
			const created = await createMcpWorkerSession({
				cwd: options.cwd,
				agentDir: options.agentDir,
				budget: options.budget,
				authStorage: options.authStorage,
				modelRegistry: options.modelRegistry,
				settingsManager: options.settingsManager,
				model: options.model,
			});
			session = created.session;
			attach(session);
			if (!session.model) {
				throw new Error("no model available: configure a provider before running MCP tasks");
			}
			// (D10) Must be set before bindExtensions — guardHarm reads it on the very
			// first tool call, and there is no safe "default allow" window to close later.
			session.setAllowRiskyActions(options.allowRiskyActions ?? false);
			await session.bindExtensions({ uiContext: createMcpTaskUiContext(registry, id) });
			await session.promptAndWait(options.prompt);
			await waitForHeadlessCompletion(session);
			const { primary } = selectHeadlessTerminalResult(session.messages);
			if (primary?.role === "assistant") {
				const failed = primary.stopReason === "error" || primary.stopReason === "aborted";
				const text = primary.content
					.filter((part): part is { type: "text"; text: string } => part.type === "text")
					.map((part) => part.text)
					.join("\n");
				registry.markDone(id, { text: failed ? primary.errorMessage || text : text, success: !failed });
			} else {
				registry.markDone(id, { text: "", success: true });
			}
		} catch (error) {
			registry.markError(id, error instanceof Error ? error.message : String(error));
		} finally {
			await session?.disposeAsync().catch(() => {});
		}
	})();

	return { taskId: id };
}
