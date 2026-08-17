import { fauxAssistantMessage, registerFauxProvider } from "@zero-agent/ai";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuthStorage } from "../src/core/auth-storage.js";
import { ModelRegistry } from "../src/core/model-registry.js";
import { createAgentSession } from "../src/core/sdk.js";
import { SessionManager } from "../src/core/session-manager.js";
import { SettingsManager } from "../src/core/settings-manager.js";

/**
 * End-to-end test of module G's integration into the real agent-creation path
 * (sdk.ts's streamFn), not just the router library in isolation: verifies that
 * setting `providerFallback` in settings actually causes createAgentSession's
 * wired-up agent to fail over to the next provider on a retryable error, and
 * that leaving it unset is a no-op (same call as before).
 */
describe("sdk.ts provider fallback wiring (module G)", () => {
	let registrations: ReturnType<typeof registerFauxProvider>[] = [];

	beforeEach(() => {
		registrations = [];
	});

	afterEach(() => {
		for (const reg of registrations) reg.unregister();
	});

	function registerAndAuth(providerName: string, authStorage: AuthStorage, modelRegistry: ModelRegistry) {
		const reg = registerFauxProvider({ provider: providerName });
		registrations.push(reg);
		authStorage.setRuntimeApiKey(providerName, "faux-key");
		modelRegistry.registerProvider(providerName, {
			baseUrl: reg.models[0].baseUrl,
			apiKey: "faux-key",
			api: reg.api,
			models: reg.models.map((m) => ({
				id: m.id,
				name: m.name,
				api: m.api,
				reasoning: m.reasoning,
				input: m.input,
				cost: m.cost,
				contextWindow: m.contextWindow,
				maxTokens: m.maxTokens,
				baseUrl: m.baseUrl,
			})),
		});
		return reg;
	}

	// Zero content blocks: a real rate-limit failure happens before any tokens
	// stream, which is also what lets the streaming router fall back silently
	// (see routedStreamGeneric's doc comment — it only retries pre-content).
	function rateLimited() {
		const message = fauxAssistantMessage([], { stopReason: "error", errorMessage: "rate limited" });
		message.diagnostics = [
			{ type: "provider_stream_failure", timestamp: Date.now(), details: { kind: "rate_limit", status: 429 } },
		];
		return message;
	}

	it("falls back to the configured provider on a rate-limit failure", async () => {
		const authStorage = AuthStorage.inMemory();
		const modelRegistry = ModelRegistry.inMemory(authStorage);
		const primary = registerAndAuth("primary", authStorage, modelRegistry);
		const fallback = registerAndAuth("fauxfallback", authStorage, modelRegistry);
		primary.setResponses([rateLimited()]);
		fallback.setResponses([fauxAssistantMessage("answer from fallback")]);

		const settingsManager = SettingsManager.inMemory({
			providerFallback: [{ provider: "fauxfallback", modelId: fallback.models[0].id }],
		});

		const { session } = await createAgentSession({
			cwd: process.cwd(),
			model: primary.getModel(),
			settingsManager,
			sessionManager: SessionManager.inMemory(),
			authStorage,
			modelRegistry,
		});

		await session.prompt("hello");

		expect(primary.state.callCount).toBe(1);
		expect(fallback.state.callCount).toBe(1);
		session.dispose();
	});

	it("tries the cheaper configured fallback before a pricier one, regardless of settings order", async () => {
		const authStorage = AuthStorage.inMemory();
		const modelRegistry = ModelRegistry.inMemory(authStorage);
		const primary = registerAndAuth("primary", authStorage, modelRegistry);
		const expensive = registerFauxProvider({
			provider: "pricey",
			models: [
				{
					id: "pricey-model",
					name: "Pricey Model",
					reasoning: false,
					input: ["text"],
					cost: { input: 10, output: 50, cacheRead: 0, cacheWrite: 0 },
					contextWindow: 128000,
					maxTokens: 8192,
				},
			],
		});
		registrations.push(expensive);
		authStorage.setRuntimeApiKey("pricey", "faux-key");
		modelRegistry.registerProvider("pricey", {
			baseUrl: expensive.models[0].baseUrl,
			apiKey: "faux-key",
			api: expensive.api,
			models: expensive.models.map((m) => ({
				id: m.id,
				name: m.name,
				api: m.api,
				reasoning: m.reasoning,
				input: m.input,
				cost: m.cost,
				contextWindow: m.contextWindow,
				maxTokens: m.maxTokens,
				baseUrl: m.baseUrl,
			})),
		});
		const cheap = registerAndAuth("fauxfallback", authStorage, modelRegistry); // cost 0, cheaper than "pricey"
		primary.setResponses([rateLimited()]);
		expensive.setResponses([fauxAssistantMessage("should never be called")]);
		cheap.setResponses([fauxAssistantMessage("answer from cheap fallback")]);

		// Settings list the pricier fallback FIRST — the router must still prefer the cheaper one.
		const settingsManager = SettingsManager.inMemory({
			providerFallback: [
				{ provider: "pricey", modelId: expensive.models[0].id },
				{ provider: "fauxfallback", modelId: cheap.models[0].id },
			],
		});

		const { session } = await createAgentSession({
			cwd: process.cwd(),
			model: primary.getModel(),
			settingsManager,
			sessionManager: SessionManager.inMemory(),
			authStorage,
			modelRegistry,
		});

		await session.prompt("hello");

		expect(cheap.state.callCount).toBe(1);
		expect(expensive.state.callCount).toBe(0);
		session.dispose();
	});

	it("prefers a same-tier fallback over a much cheaper but much weaker one (module G task #19: class + price)", async () => {
		const authStorage = AuthStorage.inMemory();
		const modelRegistry = ModelRegistry.inMemory(authStorage);
		// "GLM-5.2" is class S in the classification snapshot — naming the primary
		// this way is what lets rankFallbackCandidatesByClassAndPrice discriminate
		// by class distance instead of degrading to a pure price sort.
		const primary = registerFauxProvider({
			provider: "primary",
			models: [
				{
					id: "primary-model",
					name: "GLM-5.2",
					reasoning: false,
					input: ["text"],
					cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
					contextWindow: 128000,
					maxTokens: 8192,
				},
			],
		});
		registrations.push(primary);
		authStorage.setRuntimeApiKey("primary", "faux-key");
		modelRegistry.registerProvider("primary", {
			baseUrl: primary.models[0].baseUrl,
			apiKey: "faux-key",
			api: primary.api,
			models: primary.models.map((m) => ({
				id: m.id,
				name: m.name,
				api: m.api,
				reasoning: m.reasoning,
				input: m.input,
				cost: m.cost,
				contextWindow: m.contextWindow,
				maxTokens: m.maxTokens,
				baseUrl: m.baseUrl,
			})),
		});

		function registerNamedFallback(provider: string, name: string, outputCost: number) {
			const reg = registerFauxProvider({
				provider,
				models: [
					{
						id: `${provider}-model`,
						name,
						reasoning: false,
						input: ["text"],
						cost: { input: outputCost / 5, output: outputCost, cacheRead: 0, cacheWrite: 0 },
						contextWindow: 128000,
						maxTokens: 8192,
					},
				],
			});
			registrations.push(reg);
			authStorage.setRuntimeApiKey(provider, "faux-key");
			modelRegistry.registerProvider(provider, {
				baseUrl: reg.models[0].baseUrl,
				apiKey: "faux-key",
				api: reg.api,
				models: reg.models.map((m) => ({
					id: m.id,
					name: m.name,
					api: m.api,
					reasoning: m.reasoning,
					input: m.input,
					cost: m.cost,
					contextWindow: m.contextWindow,
					maxTokens: m.maxTokens,
					baseUrl: m.baseUrl,
				})),
			});
			return reg;
		}

		// class SS, one tier above primary's S — expensive, but classDistance=1.
		const strongExpensive = registerNamedFallback("apex-fallback", "Claude Opus 5", 50);
		// class B, two tiers below primary's S — cheap, but classDistance=2.
		const weakCheap = registerNamedFallback("budget-fallback", "GPT-5.4 Mini", 1);

		primary.setResponses([rateLimited()]);
		strongExpensive.setResponses([fauxAssistantMessage("answer from the strong fallback")]);
		weakCheap.setResponses([fauxAssistantMessage("should never be called — pure price would pick this first")]);

		// Settings list the cheap/weak one FIRST — class-distance must still win.
		const settingsManager = SettingsManager.inMemory({
			providerFallback: [
				{ provider: "budget-fallback", modelId: weakCheap.models[0].id },
				{ provider: "apex-fallback", modelId: strongExpensive.models[0].id },
			],
		});

		const { session } = await createAgentSession({
			cwd: process.cwd(),
			model: primary.getModel(),
			settingsManager,
			sessionManager: SessionManager.inMemory(),
			authStorage,
			modelRegistry,
		});

		await session.prompt("hello");

		expect(strongExpensive.state.callCount).toBe(1);
		expect(weakCheap.state.callCount).toBe(0);
		session.dispose();
	});

	it("makes no fallback call when providerFallback is unset", async () => {
		const authStorage = AuthStorage.inMemory();
		const modelRegistry = ModelRegistry.inMemory(authStorage);
		const primary = registerAndAuth("primary", authStorage, modelRegistry);
		const fallback = registerAndAuth("fauxfallback", authStorage, modelRegistry);
		primary.setResponses([rateLimited()]);
		fallback.setResponses([fauxAssistantMessage("should never be called")]);

		const settingsManager = SettingsManager.inMemory({});

		const { session } = await createAgentSession({
			cwd: process.cwd(),
			model: primary.getModel(),
			settingsManager,
			sessionManager: SessionManager.inMemory(),
			authStorage,
			modelRegistry,
		});

		await session.prompt("hello");

		// Agent-level retry (retry.enabled, default true) may retry the plain
		// streamSimple call itself on a transient failure — that's unrelated to
		// module G. What this test actually guards is that the fallback provider
		// is never touched when no fallback chain is configured.
		expect(fallback.state.callCount).toBe(0);
		session.dispose();
	});
});
