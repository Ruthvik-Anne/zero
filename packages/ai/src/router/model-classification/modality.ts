import type { ModalityTag, ModelClass } from "./types.js";

/**
 * The classification snapshot has no explicit modality field — "E" (Specialized)
 * entries carry a "Task: <label>" prefix in their rationale instead (e.g.
 * "Task: Video Generation. Rated best all-rounder 2026."). Every generalist
 * class (SS/S/A/B/C/D) is a text in/out coding+reasoning model by construction
 * (that's what the coding/reasoning grades measure), so those are tagged
 * "text" outright without needing to parse anything.
 */
const TASK_LABEL_PATTERN = /^Task:\s*([^.]+)\./;

const TASK_KEYWORD_TAGS: ReadonlyArray<{ pattern: RegExp; tag: ModalityTag }> = [
	{ pattern: /video generation/i, tag: "video-generation" },
	{ pattern: /image generation/i, tag: "image-generation" },
	{ pattern: /ocr|document understanding|visual|vision/i, tag: "vision" },
	{ pattern: /security|vulnerability/i, tag: "security" },
];

export function deriveModalityTags(modelClass: ModelClass, rationale: string | undefined): ModalityTag[] {
	if (modelClass !== "E") {
		return ["text"];
	}
	const label = rationale ? (TASK_LABEL_PATTERN.exec(rationale)?.[1] ?? rationale) : "";
	const tags = new Set<ModalityTag>();
	for (const { pattern, tag } of TASK_KEYWORD_TAGS) {
		if (pattern.test(label)) tags.add(tag);
	}
	// A specialized model with no recognized task keyword still isn't a
	// generalist text model — leave modality empty rather than guessing "text".
	return [...tags];
}
