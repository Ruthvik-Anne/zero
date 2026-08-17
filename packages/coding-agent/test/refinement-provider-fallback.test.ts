import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AgentMessage } from "@zero-agent/agent-core";
import { fauxAssistantMessage, registerFauxProvider } from "@zero-agent/ai";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadHarnessState, planRefinement } from "../src/core/refinement/index.js";

/**
 * planRefinement's own LLM call gaining module G fallback coverage — a real
 * end-to-end exercise of routedCompleteSimple through refinement.ts, not the
 * mocked completeSimple used by refinement.test.ts (that mock only replaces
 * the @zero-agent/ai barrel export; the router calls completeSimple via
 * an internal same-package import that the barrel mock never sees).
 */
describe("planRefinement provider fallback (module C + G integration)", () => {
	let tempDir: string;
	let registrations: ReturnType<typeof registerFauxProvider>[] = [];

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "zero-refinement-fallback-test-"));
		registrations = [];
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true, force: true });
		for (const reg of registrations) reg.unregister();
	});

	function register(provider: string) {
		const reg = registerFauxProvider({ provider });
		registrations.push(reg);
		return reg;
	}

	function proposalMessage(summary: string) {
		return fauxAssistantMessage(JSON.stringify({ summary, rationale: "test", expectedOutcome: "test", edits: [] }));
	}

	function rateLimited() {
		const message = fauxAssistantMessage([], { stopReason: "error", errorMessage: "rate limited" });
		message.diagnostics = [
			{ type: "provider_stream_failure", timestamp: Date.now(), details: { kind: "rate_limit", status: 429 } },
		];
		return message;
	}

	it("uses the primary model directly when no fallback candidates are given (unchanged behavior)", async () => {
		const primary = register("primary");
		primary.setResponses([proposalMessage("from primary")]);
		const state = loadHarnessState(tempDir);

		const plan = await planRefinement(
			[{ role: "user", content: "test", timestamp: Date.now() } satisfies AgentMessage],
			state,
			[],
			primary.getModel(),
			"api-key",
			{},
		);

		expect(plan.proposal.summary).toBe("from primary");
		expect(primary.state.callCount).toBe(1);
	});

	it("falls back to the next candidate when the primary refinement call is rate-limited", async () => {
		const primary = register("primary");
		const fallback = register("fallback-provider");
		primary.setResponses([rateLimited()]);
		fallback.setResponses([proposalMessage("from fallback")]);
		const state = loadHarnessState(tempDir);

		const plan = await planRefinement(
			[{ role: "user", content: "test", timestamp: Date.now() } satisfies AgentMessage],
			state,
			[],
			primary.getModel(),
			"api-key",
			{},
			undefined,
			undefined,
			undefined,
			[{ model: fallback.getModel(), options: { apiKey: "fallback-key" } }],
		);

		expect(plan.proposal.summary).toBe("from fallback");
		expect(primary.state.callCount).toBe(1);
		expect(fallback.state.callCount).toBe(1);
	});
});
