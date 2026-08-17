import type { Model } from "@zero-agent/ai";
import type { AuthStorage } from "../auth-storage.js";
import type { AgentAutonomousConfig } from "../autonomous.js";
import type { ModelRegistry } from "../model-registry.js";
import { createAgentSession } from "../sdk.js";
import { SessionManager } from "../session-manager.js";
import type { SettingsManager } from "../settings-manager.js";

/** Resource budget for one `run_task` call, mapped onto the existing autonomous-continuation limits (module D). */
export interface McpTaskBudget {
	maxTokens?: number;
	timeoutMs?: number;
	maxTurns?: number;
	maxContinuations?: number;
}

export interface CreateMcpWorkerSessionOptions {
	cwd: string;
	agentDir?: string;
	budget?: McpTaskBudget;
	/** Overrides for embedding this factory with already-configured services (e.g. tests, a hosting daemon) instead of resolving from disk. */
	authStorage?: AuthStorage;
	modelRegistry?: ModelRegistry;
	settingsManager?: SettingsManager;
	model?: Model<any>;
}

/**
 * One-shot Zero session for an MCP `run_task` call — full runtime (queue,
 * RLM, harness, guardrails, goal system), never persisted to the user's own
 * session history, since it exists only for the lifetime of one external
 * task. `createAgentSession` (the SDK's public entry point) resolves model
 * and auth exactly the way the CLI does, so a task picks up the same
 * configured default model/provider fallback chain as an interactive run.
 */
export async function createMcpWorkerSession(options: CreateMcpWorkerSessionOptions) {
	const autonomous: AgentAutonomousConfig | undefined = options.budget
		? {
				enabled: true,
				maxTokens: options.budget.maxTokens,
				timeoutMs: options.budget.timeoutMs,
				maxTurns: options.budget.maxTurns,
				maxContinuations: options.budget.maxContinuations,
			}
		: undefined;

	return createAgentSession({
		cwd: options.cwd,
		agentDir: options.agentDir,
		sessionManager: SessionManager.inMemory(options.cwd),
		authStorage: options.authStorage,
		modelRegistry: options.modelRegistry,
		settingsManager: options.settingsManager,
		model: options.model,
		autonomous,
	});
}
