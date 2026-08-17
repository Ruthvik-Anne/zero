#!/usr/bin/env node
// (C3) packages/ai's build used to run generate-models (a live fetch against
// models.dev, OpenRouter, and the Vercel AI Gateway) unconditionally on every
// invocation. models.generated.ts is a committed, tracked file — a normal
// build has no reason to re-fetch it from the network every time. Run
// `npm run generate-models` explicitly when you actually want to refresh the
// catalog; `npm run build` only falls back to generating it when it's
// missing entirely (a fresh clone before any build has ever run).
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const generatedPath = join(packageRoot, "src", "models.generated.ts");

if (existsSync(generatedPath)) {
	process.exit(0);
}

console.log("models.generated.ts is missing — running generate-models once...");
const result = spawnSync("npx", ["tsx", "scripts/generate-models.ts"], {
	cwd: packageRoot,
	stdio: "inherit",
	shell: process.platform === "win32",
	windowsHide: true,
});
process.exit(result.status ?? 1);
