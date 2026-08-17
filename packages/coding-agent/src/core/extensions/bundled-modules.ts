/**
 * Modules made available to extensions via jiti virtualModules in the compiled
 * Bun binary.
 *
 * These imports MUST be static so Bun bundles them into the compiled binary;
 * the module itself is loaded lazily (dynamic import with a literal specifier,
 * which Bun also bundles) so that merely importing the extension loader does
 * not pull in the entire package graph at startup.
 */

import * as _bundledPiAgentCore from "@zero-agent/agent-core";
import * as _bundledPiAi from "@zero-agent/ai";
import * as _bundledPiAiOauth from "@zero-agent/ai/oauth";
import * as _bundledPiTui from "@zero-agent/tui";
import * as _bundledTypebox from "typebox";
import * as _bundledTypeboxCompile from "typebox/compile";
import * as _bundledTypeboxValue from "typebox/value";
// NOTE: This import works because loader.ts exports are NOT re-exported from index.ts,
// avoiding a circular dependency. Extensions can import from @zero-agent/coding-agent.
import * as _bundledPiCodingAgent from "../../index.js";

export const VIRTUAL_MODULES: Record<string, unknown> = {
	typebox: _bundledTypebox,
	"typebox/compile": _bundledTypeboxCompile,
	"typebox/value": _bundledTypeboxValue,
	"@sinclair/typebox": _bundledTypebox,
	"@sinclair/typebox/compile": _bundledTypeboxCompile,
	"@sinclair/typebox/value": _bundledTypeboxValue,
	"@zero-agent/agent-core": _bundledPiAgentCore,
	"@zero-agent/tui": _bundledPiTui,
	"@zero-agent/ai": _bundledPiAi,
	"@zero-agent/ai/oauth": _bundledPiAiOauth,
	"@zero-agent/coding-agent": _bundledPiCodingAgent,
	"@mariozechner/pi-agent-core": _bundledPiAgentCore,
	"@mariozechner/pi-tui": _bundledPiTui,
	"@mariozechner/pi-ai": _bundledPiAi,
	"@mariozechner/pi-ai/oauth": _bundledPiAiOauth,
	"@mariozechner/pi-coding-agent": _bundledPiCodingAgent,
};
