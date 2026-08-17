/**
 * Model / thinking-level / service-tier selection helpers for AgentSession.
 *
 * Extracted from agent-session.ts (audit plan doc category C9: the file is
 * the largest, most heavily-touched file in the codebase). AgentSession keeps
 * thin public wrapper methods (setModel, cycleModel, setThinkingLevel,
 * setServiceTier, cycleThinkingLevel, getAvailableThinkingLevels,
 * supportsThinking) that delegate to the functions below.
 *
 * The handful of AgentSession fields these helpers read/write
 * (`_serviceTierPreference`, `_modelSelectEmitQueue`, `_modelSelectEmitQueueIdle`,
 * `_modelSelectEmitContext`) and the `_emit` method had their `private`
 * modifier dropped so this sibling module can reach them. TypeScript's
 * `private` is a compile-time-only check that is erased at build time, so
 * this has no runtime effect - callers within agent-session.ts are unaffected.
 */

import type { ThinkingLevel } from "@zero-agent/agent-core";
import type { Model, ServiceTier } from "@zero-agent/ai";
import { clampThinkingLevel, getSupportedThinkingLevels, modelsAreEqual, supportsFastMode } from "@zero-agent/ai";
import type { AgentSession, ModelCycleResult, ModelSelectOptions } from "./agent-session.js";
import { THINKING_LEVELS } from "./agent-session.js";
import { DEFAULT_THINKING_LEVEL } from "./defaults.js";

async function emitModelSelect(
	session: AgentSession,
	nextModel: Model<any>,
	previousModel: Model<any> | undefined,
	source: "set" | "cycle" | "restore",
): Promise<void> {
	if (modelsAreEqual(previousModel, nextModel)) return;
	await session.extensionRunner.emit({
		type: "model_select",
		model: nextModel,
		previousModel,
		source,
	});
}

function queueModelSelectEmit(
	session: AgentSession,
	nextModel: Model<any>,
	previousModel: Model<any> | undefined,
	source: "set" | "cycle" | "restore",
): Promise<void> {
	const emit = () =>
		session._modelSelectEmitContext.run(true, () => emitModelSelect(session, nextModel, previousModel, source));
	session._modelSelectEmitQueueIdle = false;
	const promise = session._modelSelectEmitQueue.then(emit, emit);
	const queued = promise.catch(() => {});
	session._modelSelectEmitQueue = queued;
	void queued.finally(() => {
		if (session._modelSelectEmitQueue === queued) {
			session._modelSelectEmitQueueIdle = true;
		}
	});
	return promise;
}

function trackModelSelectEmitError(session: AgentSession, emitPromise: Promise<void>): void {
	void emitPromise.catch((error) => {
		session.extensionRunner.emitError({
			extensionPath: "<internal>",
			event: "model_select",
			error: error instanceof Error ? error.message : String(error),
			stack: error instanceof Error ? error.stack : undefined,
		});
	});
}

function shouldWaitForModelSelectEmit(session: AgentSession, options: ModelSelectOptions): boolean {
	return options.waitForExtensions !== false && !session._modelSelectEmitContext.getStore();
}

/** Body of AgentSession#_pendingModelSelectEmit. */
export function pendingModelSelectEmit(session: AgentSession): Promise<void> | undefined {
	if (!session._modelSelectEmitContext.getStore() && !session._modelSelectEmitQueueIdle) {
		return session._modelSelectEmitQueue;
	}
	return undefined;
}

/**
 * Body of AgentSession#setModel.
 * Validates that the model is available, saves to session and settings.
 * @throws Error if the model is not available
 */
export async function setModelOnSession(
	session: AgentSession,
	model: Model<any>,
	options: ModelSelectOptions = {},
): Promise<void> {
	if (!session.modelRegistry.hasConfiguredAuth(model)) {
		throw new Error(`No API key for ${model.provider}/${model.id}`);
	}
	if (!(await session.modelRegistry.canUseModel(model))) {
		throw new Error(`Model "${model.provider}/${model.id}" is not available for the current Prime team.`);
	}

	const previousModel = session.model;
	const thinkingLevel = getThinkingLevelForModelSwitch(session);
	const serviceTier = getServiceTierForModelSwitch(session);
	session.agent.state.model = model;
	session.sessionManager.appendModelChange(model.provider, model.id);
	session.settingsManager.setDefaultModelAndProvider(model.provider, model.id);

	// Re-clamp thinking level for new model's capabilities
	session.setThinkingLevel(thinkingLevel);
	clampServiceTierForModel(session, serviceTier);

	const emitPromise = queueModelSelectEmit(session, model, previousModel, "set");
	if (shouldWaitForModelSelectEmit(session, options)) {
		await emitPromise;
	} else {
		trackModelSelectEmitError(session, emitPromise);
	}
}

/**
 * Body of AgentSession#cycleModel.
 * Uses scoped models (from --models flag) if available, otherwise all available models.
 */
export async function cycleModelOnSession(
	session: AgentSession,
	direction: "forward" | "backward" = "forward",
	options: ModelSelectOptions = {},
): Promise<ModelCycleResult | undefined> {
	if (session.scopedModels.length > 0) {
		return cycleScopedModel(session, direction, options);
	}
	return cycleAvailableModel(session, direction, options);
}

async function cycleScopedModel(
	session: AgentSession,
	direction: "forward" | "backward",
	options: ModelSelectOptions,
): Promise<ModelCycleResult | undefined> {
	const availableModels = await session.modelRegistry.refreshAvailableModels();
	const scopedModels = session.scopedModels.filter((scoped) =>
		availableModels.some((model) => modelsAreEqual(model, scoped.model)),
	);
	if (scopedModels.length <= 1) return undefined;

	const currentModel = session.model;
	let currentIndex = scopedModels.findIndex((sm) => modelsAreEqual(sm.model, currentModel));

	if (currentIndex === -1) currentIndex = 0;
	const len = scopedModels.length;
	const nextIndex = direction === "forward" ? (currentIndex + 1) % len : (currentIndex - 1 + len) % len;
	const next = scopedModels[nextIndex];
	const thinkingLevel = getThinkingLevelForModelSwitch(session, next.thinkingLevel);
	const serviceTier = getServiceTierForModelSwitch(session);

	// Apply model
	session.agent.state.model = next.model;
	session.sessionManager.appendModelChange(next.model.provider, next.model.id);
	session.settingsManager.setDefaultModelAndProvider(next.model.provider, next.model.id);

	// Apply thinking level.
	// - Explicit scoped model thinking level overrides current session level
	// - Undefined scoped model thinking level inherits the current session preference
	// setThinkingLevel clamps to model capabilities.
	session.setThinkingLevel(thinkingLevel);
	clampServiceTierForModel(session, serviceTier);

	const emitPromise = queueModelSelectEmit(session, next.model, currentModel, "cycle");
	if (shouldWaitForModelSelectEmit(session, options)) {
		await emitPromise;
	} else {
		trackModelSelectEmitError(session, emitPromise);
	}

	return {
		model: next.model,
		thinkingLevel: session.thinkingLevel,
		serviceTier: session.serviceTier,
		isScoped: true,
	};
}

async function cycleAvailableModel(
	session: AgentSession,
	direction: "forward" | "backward",
	options: ModelSelectOptions,
): Promise<ModelCycleResult | undefined> {
	const availableModels = await session.modelRegistry.refreshAvailableModels();
	if (availableModels.length <= 1) return undefined;

	const currentModel = session.model;
	let currentIndex = availableModels.findIndex((m) => modelsAreEqual(m, currentModel));

	if (currentIndex === -1) currentIndex = 0;
	const len = availableModels.length;
	const nextIndex = direction === "forward" ? (currentIndex + 1) % len : (currentIndex - 1 + len) % len;
	const nextModel = availableModels[nextIndex];

	const thinkingLevel = getThinkingLevelForModelSwitch(session);
	const serviceTier = getServiceTierForModelSwitch(session);
	session.agent.state.model = nextModel;
	session.sessionManager.appendModelChange(nextModel.provider, nextModel.id);
	session.settingsManager.setDefaultModelAndProvider(nextModel.provider, nextModel.id);

	// Re-clamp thinking level for new model's capabilities
	session.setThinkingLevel(thinkingLevel);
	clampServiceTierForModel(session, serviceTier);

	const emitPromise = queueModelSelectEmit(session, nextModel, currentModel, "cycle");
	if (shouldWaitForModelSelectEmit(session, options)) {
		await emitPromise;
	} else {
		trackModelSelectEmitError(session, emitPromise);
	}

	return {
		model: nextModel,
		thinkingLevel: session.thinkingLevel,
		serviceTier: session.serviceTier,
		isScoped: false,
	};
}

/**
 * Body of AgentSession#setThinkingLevel.
 * Clamps to model capabilities based on available thinking levels.
 * Saves to session and settings only if the level actually changes.
 */
export function setThinkingLevelOnSession(session: AgentSession, level: ThinkingLevel): void {
	const availableLevels = session.getAvailableThinkingLevels();
	const effectiveLevel = availableLevels.includes(level)
		? level
		: clampThinkingLevelValue(session, level, availableLevels);

	// Only persist if actually changing
	const previousLevel = session.agent.state.thinkingLevel;
	const isChanging = effectiveLevel !== previousLevel;

	session.agent.state.thinkingLevel = effectiveLevel;

	if (isChanging) {
		session.sessionManager.appendThinkingLevelChange(effectiveLevel);
		if (session.supportsThinking() || effectiveLevel !== "off") {
			session.settingsManager.setDefaultThinkingLevel(effectiveLevel);
		}
		session._emit({ type: "thinking_level_changed", level: effectiveLevel });
		void session.extensionRunner.emit({
			type: "thinking_level_select",
			level: effectiveLevel,
			previousLevel,
		});
	}
}

/** Body of AgentSession#setServiceTier. */
export function setServiceTierOnSession(session: AgentSession, serviceTier: ServiceTier): void {
	const effectiveServiceTier = getEffectiveServiceTier(session, serviceTier);
	const preferenceChanged = effectiveServiceTier !== session._serviceTierPreference;
	const effectiveTierChanged = effectiveServiceTier !== session.agent.state.serviceTier;
	if (!preferenceChanged && !effectiveTierChanged) {
		return;
	}
	session._serviceTierPreference = effectiveServiceTier;
	if (preferenceChanged) {
		session.sessionManager.appendServiceTierChange(effectiveServiceTier);
		if (session.model && supportsFastMode(session.model)) {
			session.settingsManager.setDefaultServiceTier(effectiveServiceTier);
		}
	}
	if (effectiveTierChanged) {
		session.agent.state.serviceTier = effectiveServiceTier;
		session._emit({
			type: "service_tier_changed",
			serviceTier: effectiveServiceTier,
		});
	}
}

function getEffectiveServiceTier(session: AgentSession, serviceTier: ServiceTier): ServiceTier {
	return serviceTier === "priority" && (!session.model || !supportsFastMode(session.model)) ? "default" : serviceTier;
}

function getServiceTierForModelSwitch(session: AgentSession): ServiceTier {
	return session._serviceTierPreference;
}

function clampServiceTierForModel(session: AgentSession, serviceTier: ServiceTier = session.serviceTier): void {
	const effectiveServiceTier = getEffectiveServiceTier(session, serviceTier);
	if (effectiveServiceTier === session.agent.state.serviceTier) {
		return;
	}
	session.agent.state.serviceTier = effectiveServiceTier;
	session._emit({
		type: "service_tier_changed",
		serviceTier: effectiveServiceTier,
	});
}

/**
 * Body of AgentSession#cycleThinkingLevel.
 * @returns New level, or undefined if model doesn't support thinking
 */
export function cycleThinkingLevelOnSession(session: AgentSession): ThinkingLevel | undefined {
	if (!session.supportsThinking()) return undefined;

	const levels = session.getAvailableThinkingLevels();
	const currentIndex = levels.indexOf(session.thinkingLevel);
	const nextIndex = (currentIndex + 1) % levels.length;
	const nextLevel = levels[nextIndex];

	session.setThinkingLevel(nextLevel);
	return nextLevel;
}

/**
 * Body of AgentSession#getAvailableThinkingLevels.
 * The provider will clamp to what the specific model supports internally.
 */
export function getAvailableThinkingLevelsForSession(session: AgentSession): ThinkingLevel[] {
	if (!session.model) return THINKING_LEVELS;
	return getSupportedThinkingLevels(session.model) as ThinkingLevel[];
}

/** Body of AgentSession#supportsThinking. */
export function supportsThinkingForSession(session: AgentSession): boolean {
	return !!session.model?.reasoning;
}

function getThinkingLevelForModelSwitch(session: AgentSession, explicitLevel?: ThinkingLevel): ThinkingLevel {
	if (explicitLevel !== undefined) {
		return explicitLevel;
	}
	if (!session.supportsThinking()) {
		return session.settingsManager.getDefaultThinkingLevel() ?? DEFAULT_THINKING_LEVEL;
	}
	return session.thinkingLevel;
}

function clampThinkingLevelValue(
	session: AgentSession,
	level: ThinkingLevel,
	_availableLevels: ThinkingLevel[],
): ThinkingLevel {
	return session.model ? (clampThinkingLevel(session.model, level) as ThinkingLevel) : "off";
}
