import { scanLayer1 } from "../safety/harm-check.js";

/**
 * Native plan/auto/manual mode system (module I).
 *
 * Deliberately thin: plan/auto/manual mostly configure existing knobs (module F's
 * harm-check gate here, `autonomous.ts`'s continuation policy elsewhere) rather than
 * being their own enforcement engine.
 *
 * - "plan": no mutation at all. Anything module F's Layer 1 would flag, plus a
 *   broader plan-mode-only denylist of benign-but-mutating operations (git commit,
 *   npm install, mkdir, editors, ...) that Layer 1 doesn't bother flagging because
 *   they aren't dangerous, gets blocked outright — no confirm prompt, since the
 *   point of plan mode is that nothing executes until the user leaves it.
 * - "auto": full tool access, no blanket per-call confirmation, but module F's
 *   soft-block still pauses for confirmation (guardrail-in-autonomy).
 * - "manual": every tool call requires confirmation, even ones module F would
 *   otherwise `allow` outright (a superset of soft-block).
 */

export type SessionMode = "plan" | "auto" | "manual";

export const SESSION_MODES: readonly SessionMode[] = ["plan", "auto", "manual"];

export const DEFAULT_SESSION_MODE: SessionMode = "auto";

/** module H convention: session-scoped state persisted as a custom session entry. */
export const SESSION_MODE_CUSTOM_TYPE = "session_mode_state";

export interface PersistedSessionMode {
	mode: SessionMode;
}

export function isSessionMode(value: unknown): value is SessionMode {
	return typeof value === "string" && (SESSION_MODES as readonly string[]).includes(value);
}

export function isPersistedSessionMode(value: unknown): value is PersistedSessionMode {
	return typeof value === "object" && value !== null && isSessionMode((value as { mode?: unknown }).mode);
}

/**
 * Plan-mode-only denylist: operations that are perfectly legitimate in auto/manual
 * mode and are NOT flagged by module F's harm-check (they aren't dangerous), but are
 * still mutations that must not happen while the model is only supposed to be
 * gathering information and proposing a plan.
 */
const PLAN_MODE_EXTRA_DENYLIST: RegExp[] = [
	/\bgit\s+(add|commit|push|merge|rebase|reset|checkout\s+-b|stash\s+(pop|drop)|worktree\s+add)\b/i,
	/\b(npm|pnpm|yarn)\s+(install|i|add|remove|uninstall|update|upgrade)\b/i,
	/\b(pip3?|uv)\s+(install|uninstall)\b/i,
	// (D13) A bare `rm file` (no -rf) wasn't covered by harm-check's own Layer 1
	// (that only flags the -rf/-fr combo) or by this list — plan mode must
	// block any deletion outright, not just the recursive-force case.
	/\brm\s+/i,
	/\bsed\s+(-[a-z]*i[a-z]*\b|--in-place\b)/i,
	/\bpython3?\s+-c\b/i,
	/\bnode\s+-e\b/i,
	/\bmkdir\b/i,
	/\btouch\b/i,
	/\bmv\s/i,
	/\bcp\s+-[a-z]*r/i,
	/\b(vim|vi|nano|emacs|code|subl)\s+\S/i,
];

// (D13) Shell output redirection (`>`/`>>` to a file) is a mutation, but the
// bare-character check below must not fire on a `>` that only appears inside a
// quoted string (e.g. `grep "a > b"` is read-only). Stripping quoted segments
// first is a heuristic, not a real shell parser — good enough to stop the
// worst false positive (any quoted `>`) without pretending to fully parse shell.
const REDIRECTION_RE = />>?\s*[^&|]/;
const QUOTED_SEGMENT_RE = /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g;

function hasUnquotedRedirection(source: string): boolean {
	return REDIRECTION_RE.test(source.replace(QUOTED_SEGMENT_RE, ""));
}

/**
 * True when `source` is safe to run in plan mode: no module-F Layer-1 flag, and no
 * plan-mode-specific mutation pattern. False means block outright (see
 * tool-definition-wrapper.ts's guardHarm, which consults this before module F).
 */
export function isPlanModeSafe(source: string, kind: "ipython" | "bash"): boolean {
	if (scanLayer1(source, kind).length > 0) return false;
	if (hasUnquotedRedirection(source)) return false;
	return !PLAN_MODE_EXTRA_DENYLIST.some((re) => re.test(source));
}

export interface ParsedModeCommand {
	kind: "show" | "set";
	mode?: SessionMode;
}

/** Parses `/mode`, `/mode plan`, `/mode auto`, `/mode manual`. */
export function parseModeSlashCommand(text: string): ParsedModeCommand | undefined {
	const trimmed = text.trim();
	if (trimmed === "") return { kind: "show" };
	const candidate = trimmed.toLowerCase();
	if (!isSessionMode(candidate)) return undefined;
	return { kind: "set", mode: candidate };
}
