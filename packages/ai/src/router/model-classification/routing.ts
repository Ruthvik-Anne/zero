import type { Api, Model } from "../../types.js";
import type { ProviderCandidate } from "../index.js";
import { type ClassificationStore, normalizeName } from "./store.js";
import type { ModelClass, ModelClassification } from "./types.js";

export interface SameClassRoutingOptions {
	/**
	 * Subagent opt-in (task #19): when true, search progressively smaller
	 * classes too once the same class has no available match, rather than
	 * refusing to route at all. Same-class candidates always rank ahead of any
	 * smaller-class ones regardless of price.
	 */
	allowSmallerClass?: boolean;
}

export interface RankedModelCandidate<TApi extends Api = Api> {
	model: Model<TApi>;
	classification: ModelClassification;
	/** Class-distance from the target model's class: 0 = same class, 1+ = that many tiers smaller. */
	classDistance: number;
}

const CLASS_RANK: Record<ModelClass, number> = { SS: 0, S: 1, A: 2, B: 3, C: 4, D: 5, E: 99 };

/** Finds every entry in `availableModels` whose display name fuzzy-matches this classification entry's name.
 * (D13) Shares store.ts's normalizeName rather than its own separately-drifting copy — that fix (token-
 * boundary-preserving normalization, so a short seed name like "gpt5" can't swallow "gpt-5.2-codex") applies here too. */
function resolveAvailableModels<TApi extends Api>(
	classification: ModelClassification,
	availableModels: readonly Model<TApi>[],
): Model<TApi>[] {
	const target = normalizeName(classification.name);
	return availableModels.filter((model) => {
		const candidate = normalizeName(model.name);
		return candidate === target || candidate.includes(target) || target.includes(candidate);
	});
}

/**
 * Same-class routing algorithm (task #19): given the model a caller is
 * currently using and a list of live-available models (already filtered to
 * configured/authenticated candidates by the caller — this function never
 * makes a network call itself), returns every available model in the same
 * classification class as `targetModelName`, and — if `allowSmallerClass` is
 * set — progressively smaller classes too, ranked:
 *   1. same class before any smaller class (classDistance ascending)
 *   2. cheaper output cost before more expensive, within a class
 * "E" (Specialized) is excluded entirely unless the target itself is class
 * E — it's not a demotion target for a generalist model, and a generalist
 * isn't a substitute for a domain-titan video/image model either.
 */
export function rankSameClassModels<TApi extends Api>(
	store: ClassificationStore,
	targetModelName: string,
	availableModels: readonly Model<TApi>[],
	options: SameClassRoutingOptions = {},
): RankedModelCandidate<TApi>[] {
	const target = store.findByName(targetModelName);
	if (!target) return [];

	const classesToSearch: Array<{ modelClass: ModelClass; distance: number }> = [
		{ modelClass: target.class, distance: 0 },
	];
	if (options.allowSmallerClass) {
		const smaller = store.smallerClasses(target.class);
		for (let i = 0; i < smaller.length; i++) {
			classesToSearch.push({ modelClass: smaller[i], distance: i + 1 });
		}
	}

	// (D13) Two distinct classification entries in the same class (or, with
	// allowSmallerClass, across classes) can each fuzzy-match the same live
	// model — without this, "fallback" would retry the identical endpoint.
	// Keyed on provider+id, not the fuzzy-matched name, since that's the
	// actual dispatch identity.
	const seenModelKeys = new Set<string>();
	const results: RankedModelCandidate<TApi>[] = [];
	for (const { modelClass, distance } of classesToSearch) {
		for (const classification of store.listByClass(modelClass)) {
			if (!classification.modality.includes("text")) continue; // Not a generalist candidate.
			for (const model of resolveAvailableModels(classification, availableModels)) {
				const key = `${model.provider}:${model.id}`;
				if (seenModelKeys.has(key)) continue;
				seenModelKeys.add(key);
				results.push({ model, classification, classDistance: distance });
			}
		}
	}

	results.sort((a, b) => {
		if (a.classDistance !== b.classDistance) return a.classDistance - b.classDistance;
		if (a.model.cost.output !== b.model.cost.output) return a.model.cost.output - b.model.cost.output;
		if (a.model.cost.input !== b.model.cost.input) return a.model.cost.input - b.model.cost.input;
		return a.model.name.localeCompare(b.model.name);
	});
	return results;
}

/** Convenience wrapper: same ranking, mapped directly into router-ready ProviderCandidate entries. */
export function buildSameClassProviderCandidates<TApi extends Api>(
	store: ClassificationStore,
	targetModelName: string,
	availableModels: readonly Model<TApi>[],
	options?: SameClassRoutingOptions,
): ProviderCandidate<TApi>[] {
	return rankSameClassModels(store, targetModelName, availableModels, options).map((ranked) => ({
		model: ranked.model,
		label: `${ranked.classification.class}:${ranked.classification.name}`,
	}));
}

/**
 * Orders an already-configured fallback chain (task #19: "autorouting needs
 * to be pricing AND class based") — unlike rankSameClassModels, this never
 * drops a candidate; it only reorders the ones the caller already decided to
 * include. Primary sort key is class-distance from the primary model's class
 * (closer/equal-quality fallbacks tried before a steep downgrade), price
 * ascending as the tiebreaker within equal class-distance. If the primary
 * model isn't in the classification snapshot at all (unrecognized/custom
 * model), class can't discriminate anything, so this degrades gracefully to
 * a pure price sort — the same behavior as before class-awareness existed.
 * A fallback candidate that itself isn't recognized sorts after every
 * classified one, on the same "don't guess" principle as findByName.
 */
export function rankFallbackCandidatesByClassAndPrice<TApi extends Api>(
	store: ClassificationStore,
	primaryModelName: string,
	candidates: readonly ProviderCandidate<TApi>[],
): ProviderCandidate<TApi>[] {
	const primaryRank = store.findByName(primaryModelName)?.class;
	const primaryClassRank = primaryRank ? CLASS_RANK[primaryRank] : undefined;

	const classDistance = (candidate: ProviderCandidate<TApi>): number => {
		if (primaryClassRank === undefined) return 0; // Primary is unclassified — price alone decides.
		const classification = store.findByName(candidate.model.name);
		if (!classification) return Number.POSITIVE_INFINITY;
		return Math.abs(CLASS_RANK[classification.class] - primaryClassRank);
	};

	return [...candidates].sort((a, b) => {
		const distanceDelta = classDistance(a) - classDistance(b);
		if (distanceDelta !== 0) return distanceDelta;
		if (a.model.cost.output !== b.model.cost.output) return a.model.cost.output - b.model.cost.output;
		return a.model.cost.input - b.model.cost.input;
	});
}

export { CLASS_RANK };
