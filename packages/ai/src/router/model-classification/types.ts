/**
 * Module G: dynamic model-class tiers (task #19). Letter classes are ranked
 * generalist-quality tiers (SS best); "E" is orthogonal ("Specialized" —
 * domain-titan models like video/image generation that outrank generalists
 * on their one task but aren't comparable on coding/reasoning at all), so it
 * is never treated as a demotion target for a non-E model and vice versa.
 * "C"/"D" are reserved letters between B and A's neighbors for future
 * snapshots where the percentile bins produce a populated tier there — the
 * 2026-08-08 snapshot has no models landing in either.
 */
export type ModelClass = "SS" | "S" | "A" | "B" | "C" | "D" | "E";

export const MODEL_CLASS_ORDER: readonly ModelClass[] = ["SS", "S", "A", "B", "C", "D"];

/** Output-modality tags — dynamic, derived from classification data, and overridable per model. */
export type ModalityTag = "text" | "vision" | "video-generation" | "image-generation" | "security";

export interface ClassificationBenchmarks {
	relativeGrade: number | string;
	benchmarks: Record<string, number>;
}

export interface ClassificationPricing {
	inputPer1m: number | null;
	outputPer1m: number | null;
	notes?: string;
}

export interface ModelClassification {
	name: string;
	provider: string;
	parameters?: string;
	weightsType?: string;
	hostedBy?: string;
	class: ModelClass;
	className: string;
	coding?: ClassificationBenchmarks;
	reasoning?: ClassificationBenchmarks;
	instructionFollowing?: Record<string, number>;
	pricing: ClassificationPricing;
	rationale?: string;
	/** Dynamic, overridable. Derived by default; see modality.ts. */
	modality: ModalityTag[];
}

export interface ClassificationMetadata {
	date: string;
	methodology: {
		codingWeight: string;
		reasoningWeight: string;
		instructionFollowingWeight: string;
		gradingMethod: string;
		demotionRule: string;
		dataSources: string[];
		notation: string;
	};
}

export interface ClassificationSnapshot {
	metadata: ClassificationMetadata;
	models: ModelClassification[];
}
