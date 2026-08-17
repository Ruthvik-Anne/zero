import { existsSync } from "node:fs";
import { Agent } from "@zero-agent/agent-core";
import { fauxAssistantMessage } from "@zero-agent/ai";
import { afterEach, describe, expect, it } from "vitest";
import { AgentSession } from "../../src/core/agent-session.js";
import { AuthStorage } from "../../src/core/auth-storage.js";
import { ModelRegistry } from "../../src/core/model-registry.js";
import { SessionManager } from "../../src/core/session-manager.js";
import { SettingsManager } from "../../src/core/settings-manager.js";
import { createTestResourceLoader } from "../utilities.js";
import { createHarness, type Harness } from "./harness.js";

/**
 * module I: native plan/auto/manual mode. Persistence mirrors goals.ts's own
 * pattern exactly (see agent-session-goal.test.ts's createRestartSession) —
 * a custom session entry, restored on construction/navigateTree.
 */
describe("AgentSession session mode", () => {
	const harnesses: Harness[] = [];

	afterEach(() => {
		while (harnesses.length > 0) {
			harnesses.pop()?.cleanup();
		}
	});

	it("defaults to auto", async () => {
		const harness = await createHarness({});
		harnesses.push(harness);

		expect(harness.session.getSessionMode()).toBe("auto");
	});

	it("setSessionMode switches and returns the previous mode", async () => {
		const harness = await createHarness({});
		harnesses.push(harness);

		const previous = harness.session.setSessionMode("plan");
		expect(previous).toBe("auto");
		expect(harness.session.getSessionMode()).toBe("plan");
	});

	it("/mode plan|auto|manual switches via the slash command, /mode alone shows current", async () => {
		const harness = await createHarness({});
		harnesses.push(harness);

		harness.setResponses([fauxAssistantMessage("ack")]);
		await harness.session.prompt("/mode manual");
		expect(harness.session.getSessionMode()).toBe("manual");

		await harness.session.prompt("/mode");
		expect(harness.session.getSessionMode()).toBe("manual");
	});

	function createRestartSession(harness: Harness): AgentSession {
		const sessionFile = harness.sessionManager.getSessionFile()!;
		expect(existsSync(sessionFile)).toBe(true);
		const newSessionManager = SessionManager.open(sessionFile);

		const reopenedBranch = newSessionManager.getBranch();
		const modeEntries = reopenedBranch.filter(
			(e: { type: string; customType?: string }) => e.type === "custom" && e.customType === "session_mode_state",
		);
		expect(modeEntries.length).toBeGreaterThan(0);

		const model = harness.getModel();
		const newAuth = AuthStorage.inMemory();
		newAuth.setRuntimeApiKey(model.provider, "faux-key");
		const newRegistry = ModelRegistry.inMemory(newAuth);
		const newSettings = SettingsManager.inMemory();

		const newAgent = new Agent({
			getApiKey: () => "faux-key",
			initialState: {
				model,
				systemPrompt: "You are a test assistant.",
				tools: [],
			},
		});

		return new AgentSession({
			agent: newAgent,
			sessionManager: newSessionManager,
			settingsManager: newSettings,
			cwd: harness.tempDir,
			modelRegistry: newRegistry,
			resourceLoader: createTestResourceLoader(),
		});
	}

	it("persists across session reopen", async () => {
		const harness = await createHarness({ persistSession: true });
		harnesses.push(harness);

		// Go through /mode (not setSessionMode directly) so the session file is
		// actually flushed to disk before restart, matching how goal persistence
		// is exercised in agent-session-goal.test.ts.
		harness.setResponses([fauxAssistantMessage("ack")]);
		await harness.session.prompt("/mode plan");

		const restarted = createRestartSession(harness);
		try {
			expect(restarted.getSessionMode()).toBe("plan");
		} finally {
			restarted.dispose();
		}
	});
});
