import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { INTEGRATED_CLASSIFICATION_DATA } from "../src/router/model-classification/data.js";
import {
	buildSameClassProviderCandidates,
	ClassificationStore,
	loadSeedSnapshot,
	rankSameClassModels,
} from "../src/router/model-classification/index.js";
import { normalizeName } from "../src/router/model-classification/store.js";
import type { Api, Model } from "../src/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

function fakeModel(overrides: Partial<Model<Api>> & { id: string; name: string }): Model<Api> {
	return {
		api: "openai-completions",
		provider: "test-provider",
		baseUrl: "https://example.test",
		reasoning: false,
		input: ["text"],
		contextWindow: 128000,
		maxTokens: 8192,
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		...overrides,
	} as Model<Api>;
}

describe("model classification seed (module G, task #19)", () => {
	it("loads every class from the bundled snapshot", () => {
		const snapshot = loadSeedSnapshot();
		const classes = new Set(snapshot.models.map((m) => m.class));
		expect(classes).toEqual(new Set(["SS", "S", "A", "B", "E"]));
		expect(snapshot.metadata.methodology.demotionRule).toContain("demoted one class");
	});

	it("data.ts (the compiled literal actually loaded at runtime) matches the canonical JSON it is generated from", async () => {
		// data.ts is a checked-in generated artifact (scripts/generate-model-classification.ts),
		// not a live import of the JSON (see that script's header comment for why:
		// native `with {type:"json"}` imports fail under this repo's root
		// tsconfig `module: "Node16"`). Nothing enforces the two stay in sync
		// except this test — a hand-edit to the JSON with no regeneration run
		// would otherwise have zero runtime effect and zero other test failures.
		const jsonPath = join(
			__dirname,
			"..",
			"src",
			"router",
			"model-classification",
			"data",
			"model-classification.json",
		);
		const canonicalJson = JSON.parse(await readFile(jsonPath, "utf8"));
		expect(INTEGRATED_CLASSIFICATION_DATA).toEqual(canonicalJson);
	});

	it("tags generalist classes as text, and derives modality tags for class E from the rationale", () => {
		const snapshot = loadSeedSnapshot();
		const opus5 = snapshot.models.find((m) => m.name === "Claude Opus 5");
		expect(opus5?.modality).toEqual(["text"]);

		const veo = snapshot.models.find((m) => m.name === "Veo 3.1");
		expect(veo?.class).toBe("E");
		expect(veo?.modality).toContain("video-generation");

		const qwenVl = snapshot.models.find((m) => m.name === "Qwen3-VL-235B-A22B");
		expect(qwenVl?.modality).toContain("vision");

		const cyberGemini = snapshot.models.find((m) => m.name === "Gemini 3.5 Flash Cyber");
		expect(cyberGemini?.modality).toContain("security");
	});
});

describe("ClassificationStore", () => {
	let store: ClassificationStore;

	beforeEach(() => {
		store = new ClassificationStore();
	});

	it("finds a model by exact and fuzzy (case/punctuation-insensitive) name", () => {
		expect(store.findByName("Claude Opus 5")?.class).toBe("SS");
		expect(store.findByName("claude opus 5")?.class).toBe("SS");
		expect(store.findByName("claude-opus-5")?.class).toBe("SS");
		expect(store.findByName("nonexistent-model-xyz")).toBeUndefined();
	});

	// D13: normalizeName used to strip separators entirely, so "gpt5" (short
	// seed name) became a literal substring of "gpt-5.2-codex" (longer live
	// name) once both were reduced to "gpt5"/"gpt52codex". Token-preserving
	// normalization (spaces instead of deletion) must not collide these.
	it("does not let a short seed name swallow an unrelated longer live name", () => {
		expect(normalizeName("gpt-5.2-codex")).not.toContain(normalizeName("gpt5"));
		expect(normalizeName("gpt5")).not.toBe(normalizeName("gpt-5.2-codex"));
	});

	it("still collides the legitimate case: hyphenated registry id vs. spaced display name", () => {
		expect(normalizeName("claude-sonnet-5")).toBe(normalizeName("Claude Sonnet 5"));
	});

	it("ranks smaller classes strictly worse than the given class, excluding E", () => {
		expect(store.smallerClasses("SS")).toEqual(["S", "A", "B", "C", "D"]);
		expect(store.smallerClasses("A")).toEqual(["B", "C", "D"]);
		expect(store.smallerClasses("D")).toEqual([]);
		expect(store.smallerClasses("E")).toEqual([]);
	});

	it("applies an override without mutating the underlying seed", () => {
		store.setOverride("Claude Opus 5", { class: "S" });
		expect(store.findByName("Claude Opus 5")?.class).toBe("S");
		expect(loadSeedSnapshot().models.find((m) => m.name === "Claude Opus 5")?.class).toBe("SS");

		store.removeOverride("Claude Opus 5");
		expect(store.findByName("Claude Opus 5")?.class).toBe("SS");
	});

	it("setModalityOverride retags a model's output modality", () => {
		store.setModalityOverride("Claude Opus 5", ["text", "vision"]);
		expect(store.findByName("Claude Opus 5")?.modality).toEqual(["text", "vision"]);
	});

	it("resetOverrides clears every override at once", () => {
		store.setOverride("Claude Opus 5", { class: "S" });
		store.setOverride("Kimi K3", { class: "SS" });
		store.resetOverrides();
		expect(store.findByName("Claude Opus 5")?.class).toBe("SS");
		expect(store.findByName("Kimi K3")?.class).toBe("S");
	});

	describe("file-backed persistence", () => {
		let dir: string;

		beforeEach(async () => {
			dir = await mkdtemp(join(tmpdir(), "zero-model-classification-test-"));
		});

		afterEach(async () => {
			await rm(dir, { recursive: true, force: true });
		});

		it("round-trips overrides through save/load", async () => {
			const path = join(dir, "overrides.json");
			store.setOverride("Claude Opus 5", { class: "S" });
			await store.saveOverridesToFile(path);

			const reloaded = new ClassificationStore();
			await reloaded.loadOverridesFromFile(path);
			expect(reloaded.findByName("Claude Opus 5")?.class).toBe("S");
		});

		it("loading a missing overrides file is a no-op, not an error", async () => {
			await expect(store.loadOverridesFromFile(join(dir, "does-not-exist.json"))).resolves.toBeUndefined();
			expect(store.findByName("Claude Opus 5")?.class).toBe("SS");
		});
	});
});

describe("same-class routing (task #19)", () => {
	let store: ClassificationStore;

	beforeEach(() => {
		store = new ClassificationStore();
	});

	it("returns only same-class, available candidates by default, cheapest first", () => {
		// GLM-5.2 and Claude Opus 4.8 are both class S; Kimi K3 is also class S.
		const available = [
			fakeModel({
				id: "glm-5-2",
				name: "GLM-5.2",
				cost: { input: 0.68, output: 2.14, cacheRead: 0, cacheWrite: 0 },
			}),
			fakeModel({
				id: "claude-opus-4-8",
				name: "Claude Opus 4.8",
				cost: { input: 5, output: 25, cacheRead: 0, cacheWrite: 0 },
			}),
			// Class A model — must not appear without allowSmallerClass.
			fakeModel({
				id: "claude-sonnet-5",
				name: "Claude Sonnet 5",
				cost: { input: 2, output: 10, cacheRead: 0, cacheWrite: 0 },
			}),
		];

		const ranked = rankSameClassModels(store, "Claude Opus 4.8", available);

		expect(ranked.every((r) => r.classDistance === 0)).toBe(true);
		expect(ranked.map((r) => r.model.name)).toEqual(["GLM-5.2", "Claude Opus 4.8"]);
		expect(ranked.map((r) => r.model.name)).not.toContain("Claude Sonnet 5");
	});

	it("falls back to smaller classes, ranked after same-class, when allowSmallerClass is set (subagent opt-in)", () => {
		const available = [
			fakeModel({
				id: "claude-sonnet-5",
				name: "Claude Sonnet 5", // class A
				cost: { input: 2, output: 10, cacheRead: 0, cacheWrite: 0 },
			}),
			fakeModel({
				id: "claude-opus-4-8",
				name: "Claude Opus 4.8", // class S — the target's own class
				cost: { input: 5, output: 25, cacheRead: 0, cacheWrite: 0 },
			}),
		];

		const ranked = rankSameClassModels(store, "Claude Opus 4.8", available, { allowSmallerClass: true });

		expect(ranked.map((r) => r.model.name)).toEqual(["Claude Opus 4.8", "Claude Sonnet 5"]);
		expect(ranked[0]?.classDistance).toBe(0);
		expect(ranked[1]?.classDistance).toBeGreaterThan(0);
	});

	it("never substitutes a class-E specialized model for a generalist target, or vice versa", () => {
		const available = [fakeModel({ id: "veo-3-1", name: "Veo 3.1" })];
		const ranked = rankSameClassModels(store, "Claude Opus 5", available, { allowSmallerClass: true });
		expect(ranked).toEqual([]);
	});

	it("returns nothing for an unrecognized target model rather than guessing", () => {
		const available = [fakeModel({ id: "x", name: "Some Unknown Model" })];
		expect(rankSameClassModels(store, "Totally Unknown Model", available)).toEqual([]);
	});

	it("builds router-ready ProviderCandidate entries with a class-labeled tag", () => {
		const available = [
			fakeModel({
				id: "glm-5-2",
				name: "GLM-5.2",
				cost: { input: 0.68, output: 2.14, cacheRead: 0, cacheWrite: 0 },
			}),
		];
		const candidates = buildSameClassProviderCandidates(store, "GLM-5.2", available);
		expect(candidates).toHaveLength(1);
		expect(candidates[0]?.model.name).toBe("GLM-5.2");
		expect(candidates[0]?.label).toBe("S:GLM-5.2");
	});
});
