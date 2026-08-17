import { readFile, writeFile } from "node:fs/promises";
import { loadSeedSnapshot } from "./seed.js";
import {
	type ClassificationSnapshot,
	MODEL_CLASS_ORDER,
	type ModalityTag,
	type ModelClass,
	type ModelClassification,
} from "./types.js";

export type ClassificationOverride = Partial<Omit<ModelClassification, "name">>;

// (D13) Was stripping separators entirely (`[^a-z0-9]+` -> ""), which merged
// adjacent tokens into one run — "gpt-5.2-codex" normalized to "gpt52codex",
// a literal superstring of the seed name "gpt5" normalized to "gpt5". The
// fuzzy substring fallback below then matched a short unrelated seed name
// against a longer live one. Keeping a single space as the token separator
// means normalizeName("claude-sonnet-5") and normalizeName("Claude Sonnet 5")
// still collide (the legitimate case this fallback exists for), while
// "gpt 5 2 codex" no longer contains the literal substring "gpt5".
export function normalizeName(name: string): string {
	return name
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, " ")
		.trim();
}

/**
 * Mutable, file-backed overlay on top of the immutable bundled seed (task
 * #19). Seed entries are never mutated in place; overrides are stored
 * separately and merged on read, so `resetOverrides()`/a missing overrides
 * file always falls back to exactly the shipped snapshot. This mirrors the
 * router's usage-ledger.ts convention: the caller supplies the path, the
 * module has no hardcoded location of its own.
 */
export class ClassificationStore {
	private readonly seed: ClassificationSnapshot;
	private readonly byNormalizedName = new Map<string, ModelClassification>();
	private readonly overrides = new Map<string, ClassificationOverride>();

	constructor(seed: ClassificationSnapshot = loadSeedSnapshot()) {
		this.seed = seed;
		for (const model of seed.models) {
			this.byNormalizedName.set(normalizeName(model.name), model);
		}
	}

	get metadata() {
		return this.seed.metadata;
	}

	private materialize(model: ModelClassification): ModelClassification {
		const override = this.overrides.get(normalizeName(model.name));
		return override ? { ...model, ...override } : model;
	}

	getAll(): ModelClassification[] {
		return this.seed.models.map((model) => this.materialize(model));
	}

	/**
	 * Fuzzy lookup: exact normalized match first, then substring in either
	 * direction (registry model names and classification display names don't
	 * always match verbatim, e.g. registry "claude-sonnet-5" vs. classification
	 * "Claude Sonnet 5"). Returns undefined rather than guessing when nothing
	 * matches even loosely.
	 */
	findByName(name: string): ModelClassification | undefined {
		const normalized = normalizeName(name);
		if (!normalized) return undefined;
		const exact = this.byNormalizedName.get(normalized);
		if (exact) return this.materialize(exact);
		for (const [key, model] of this.byNormalizedName) {
			if (key.includes(normalized) || normalized.includes(key)) {
				return this.materialize(model);
			}
		}
		return undefined;
	}

	listByClass(modelClass: ModelClass): ModelClassification[] {
		return this.getAll().filter((model) => model.class === modelClass);
	}

	listByModality(tag: ModalityTag): ModelClassification[] {
		return this.getAll().filter((model) => model.modality.includes(tag));
	}

	/** Classes ranked strictly worse than `modelClass`, in descending-quality order. "E" has no ordering relative to the generalist tiers. */
	smallerClasses(modelClass: ModelClass): ModelClass[] {
		if (modelClass === "E") return [];
		const index = MODEL_CLASS_ORDER.indexOf(modelClass);
		if (index === -1) return [];
		return MODEL_CLASS_ORDER.slice(index + 1);
	}

	setOverride(name: string, patch: ClassificationOverride): void {
		const existing = this.findByName(name);
		const key = existing ? normalizeName(existing.name) : normalizeName(name);
		this.overrides.set(key, { ...this.overrides.get(key), ...patch });
	}

	setModalityOverride(name: string, modality: ModalityTag[]): void {
		this.setOverride(name, { modality });
	}

	removeOverride(name: string): void {
		this.overrides.delete(normalizeName(name));
	}

	resetOverrides(): void {
		this.overrides.clear();
	}

	getOverrides(): Record<string, ClassificationOverride> {
		return Object.fromEntries(this.overrides);
	}

	async loadOverridesFromFile(path: string): Promise<void> {
		let raw: string;
		try {
			raw = await readFile(path, "utf8");
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "ENOENT") return; // No overrides yet — not an error.
			throw error;
		}
		const parsed: Record<string, ClassificationOverride> = raw.trim() ? JSON.parse(raw) : {};
		this.overrides.clear();
		for (const [key, patch] of Object.entries(parsed)) {
			this.overrides.set(key, patch);
		}
	}

	async saveOverridesToFile(path: string): Promise<void> {
		await writeFile(path, `${JSON.stringify(this.getOverrides(), null, "\t")}\n`, "utf8");
	}
}
