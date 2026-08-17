import { INTEGRATED_CLASSIFICATION_DATA } from "./data.js";
import type { ClassificationSnapshot } from "./types.js";

let cachedSnapshot: ClassificationSnapshot | undefined;

/**
 * Loads the bundled, already-integrated classification data (see data.ts /
 * data/model-classification.json) once and caches it — the shipped snapshot
 * is immutable at runtime; ClassificationStore layers mutable overrides on
 * top rather than mutating this.
 */
export function loadSeedSnapshot(): ClassificationSnapshot {
	if (cachedSnapshot) return cachedSnapshot;
	cachedSnapshot = INTEGRATED_CLASSIFICATION_DATA as unknown as ClassificationSnapshot;
	return cachedSnapshot;
}
