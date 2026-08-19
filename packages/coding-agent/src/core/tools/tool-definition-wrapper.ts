import { join } from "node:path";
import type { AgentTool, AgentToolResult } from "@zero-agent/agent-core";
import { appendAuditLog, auditEntry } from "../audit/audit-log.js";
import { createCheckpoint, isPathTrackedByGit } from "../checkpoint/checkpoint.js";
import type { ExtensionContext, ToolDefinition, VaultPlaceholderResolver } from "../extensions/types.js";
import { isPlanModeSafe } from "../mode/session-mode.js";
import { getLocalHarnessStateDir, recordGuardrailPrecedent } from "../refinement/refinement.js";
import { checkHarm, type HarmCheckKind, type HarmVerdict } from "../safety/harm-check.js";
import { getSessionArtifactPath } from "../session-manager.js";

const HARM_CHECKED_TOOLS: Record<string, { kind: HarmCheckKind; sourceKey: string }> = {
	ipython: { kind: "ipython", sourceKey: "code" },
	bash: { kind: "bash", sourceKey: "command" },
};

/**
 * (D4) Tools that always mutate state and have no "source code" for module F's
 * Layer 1 to scan — so they never appear in HARM_CHECKED_TOOLS, and the plan-mode
 * gate below (which previously only ran for tools with a harm-check kind) never
 * saw them at all: `edit` ran unblocked, unconfirmed, and unaudited in plan mode.
 * Plan mode's rule is unconditional — nothing mutating runs, ever — so these are
 * blocked outright, with no scan needed to know that.
 */
const PLAN_MODE_ALWAYS_BLOCKED_TOOLS = new Set(["edit"]);

function resolveSessionArtifactDir(ctx: ExtensionContext): string | undefined {
	// Audit/guardrail logging must never block or fail a tool call (see
	// logAudit/recordGuardrailForVerdict below) — degrade the same way a
	// missing sessionDir/sessionId already does if sessionManager itself
	// is absent, rather than throwing.
	const sessionDir = ctx.sessionManager?.getSessionDir();
	const sessionId = ctx.sessionManager?.getSessionId();
	if (!sessionDir || !sessionId) return undefined;
	return getSessionArtifactPath(sessionDir, sessionId);
}

/** module H convention: session-artifacts/<id>/audit/audit.jsonl, sibling to harness/kernel state. */
function resolveAuditLogPath(ctx: ExtensionContext): string | undefined {
	const artifactDir = resolveSessionArtifactDir(ctx);
	return artifactDir ? join(artifactDir, "audit", "audit.jsonl") : undefined;
}

/** module F → module C: record every non-allow verdict as durable guardrail precedent. */
function recordGuardrailForVerdict(
	ctx: ExtensionContext | undefined,
	toolName: string,
	verdict: HarmVerdict,
	approved?: boolean,
): void {
	if (!ctx || verdict.action === "allow") return;
	const harnessStateDir = getLocalHarnessStateDir(resolveSessionArtifactDir(ctx));
	if (!harnessStateDir) return;
	try {
		recordGuardrailPrecedent(harnessStateDir, {
			toolName,
			matchedPatterns: verdict.matchedPatterns,
			action: verdict.action,
			approved,
			scope: verdict.scope,
		});
	} catch {
		// Guardrail-memory recording must never block or fail a tool call.
	}
}

async function logAudit(
	ctx: ExtensionContext | undefined,
	type: Parameters<typeof auditEntry>[0],
	detail: Record<string, unknown>,
): Promise<void> {
	if (!ctx) return;
	const auditLogPath = resolveAuditLogPath(ctx);
	if (!auditLogPath) return;
	try {
		await appendAuditLog(auditLogPath, auditEntry(type, detail));
	} catch {
		// Audit logging must never block or fail a tool call.
	}
}

/**
 * Native harm-check gate (module F), applied at the single choke point every tool
 * call passes through — reached uniformly by the root session, RLM children, and
 * worktree-isolated children, since none of them run a separate CLI process.
 */
/** module I: no-mutation plan-mode block. Distinct from a HarmVerdict — nothing to confirm, it's just not allowed yet. */
function planModeVerdict(reason: string): HarmVerdict {
	return {
		action: "hard_block",
		reason,
		consequence: "Plan mode does not execute mutating or risky actions — present findings or a plan instead.",
		reversible: true,
		scope: "workspace",
		matchedPatterns: [],
	};
}

async function guardHarm(
	toolName: string,
	params: unknown,
	ctx: ExtensionContext | undefined,
): Promise<{ blocked: true; verdict: HarmVerdict } | { blocked: false }> {
	if (ctx?.mode === "plan" && PLAN_MODE_ALWAYS_BLOCKED_TOOLS.has(toolName)) {
		const verdict = planModeVerdict(`Blocked in plan mode: ${toolName} always mutates state.`);
		await logAudit(ctx, "harm_verdict", {
			toolName,
			action: verdict.action,
			reason: verdict.reason,
			scope: verdict.scope,
		});
		ctx.ui.notify(verdict.reason, "warning");
		return { blocked: true, verdict };
	}

	const spec = HARM_CHECKED_TOOLS[toolName];
	if (!spec) return { blocked: false };
	const source = (params as Record<string, unknown> | undefined)?.[spec.sourceKey];
	if (typeof source !== "string" || !ctx) return { blocked: false };

	// module I "plan" mode: nothing mutating or risky runs at all, no confirm offered —
	// the point of plan mode is that execution waits until the user leaves it.
	if (ctx.mode === "plan" && !isPlanModeSafe(source, spec.kind)) {
		const verdict = planModeVerdict(`Blocked in plan mode: ${toolName} would mutate state or run a risky operation.`);
		await logAudit(ctx, "harm_verdict", {
			toolName,
			action: verdict.action,
			reason: verdict.reason,
			scope: verdict.scope,
		});
		ctx.ui.notify(verdict.reason, "warning");
		return { blocked: true, verdict };
	}

	// (D8) "Reversible" must answer for THIS target, not "does any checkpoint
	// exist anywhere" — that stayed true forever after the session's first
	// approval, regardless of relevance. A future checkpoint (created below,
	// after approval) can only restore tracked content, so an untracked target
	// is honestly unreversible no matter when it's taken.
	const verdict = checkHarm(source, spec.kind, {
		cwd: ctx.cwd,
		hasCheckpoint: (targetPath) => (targetPath ? isPathTrackedByGit(ctx.cwd, targetPath) : false),
	});
	await logAudit(ctx, "harm_verdict", {
		toolName,
		action: verdict.action,
		reason: verdict.reason,
		scope: verdict.scope,
		// (D10) So an approval is attributable to an explicit caller declaration,
		// not indistinguishable from a real human confirm in the audit trail.
		allowRiskyActions: ctx.allowRiskyActions ?? true,
	});

	if (verdict.action === "allow") {
		// module I "manual" mode: every tool call is confirmed, even ones the harm-check
		// itself would allow outright — a superset of soft-block, not a harm-check concept.
		if (ctx.mode === "manual") {
			if (!ctx.hasUI)
				return {
					blocked: true,
					verdict: planModeVerdict("Manual mode requires confirmation, but no UI is attached."),
				};
			const approved = await ctx.ui.confirm("Confirm action (manual mode)", `Run ${toolName}?`);
			if (!approved) return { blocked: true, verdict: planModeVerdict(`Declined in manual mode: ${toolName}.`) };
		}
		return { blocked: false };
	}

	if (verdict.action === "hard_block") {
		ctx.ui.notify(`Blocked: ${verdict.reason} ${verdict.consequence}`, "error");
		recordGuardrailForVerdict(ctx, toolName, verdict);
		return { blocked: true, verdict };
	}

	// soft_block: ask the user, with a plain-language consequence line — never a bare y/n.
	// Fail-closed when no UI is attached (headless/non-interactive), matching the
	// existing permission-gate pattern for unattended runs — OR (D10) when this
	// session has been explicitly denied risk-approval authority. module J (MCP
	// server mode) binds a real UI context so ask_user round-trips work, but that
	// context's confirm() answer comes from whatever called the `answer` MCP
	// tool — which cannot be verified as a human who reviewed the consequence
	// line below, unlike every other mode's real interactive UI. Defaults to
	// allowed (`?? true`) so every existing caller that never sets this field is
	// completely unaffected.
	if (!ctx.hasUI || ctx.allowRiskyActions === false) {
		recordGuardrailForVerdict(ctx, toolName, verdict, false);
		return { blocked: true, verdict };
	}
	const message = `${verdict.consequence}${
		verdict.reversible ? " This can be undone via checkpoint/rollback." : " This cannot be undone."
	}`;
	const approved = await ctx.ui.confirm("Confirm risky action", message);
	recordGuardrailForVerdict(ctx, toolName, verdict, approved);
	if (!approved) {
		return { blocked: true, verdict };
	}
	// Approved: snapshot the workspace now, before the risky action executes, so a
	// later /rollback can actually restore pre-action state (module H checkpoint).
	createCheckpoint(ctx.cwd);
	return { blocked: false };
}

const AUDIT_PARAMS_SUMMARY_MAX_CHARS = 500;

// (D7) The audit log previously had no redaction at all despite its own comment
// claiming otherwise — a bash/ipython param containing a bearer token, API key,
// or exported secret env var was persisted to session-artifacts/<id>/audit/audit.jsonl
// in cleartext. Two passes: structured params with a sensitive key name (an
// object field literally called "apiKey"/"token"/...), and secrets embedded
// inside free-form string values (a command/code string) that a key-name check
// can't see.
const SENSITIVE_KEY_RE =
	/^(api[_-]?key|apikey|token|secret|password|passwd|credential|authorization|auth|access[_-]?key|private[_-]?key)$/i;

function redactSensitiveKeys(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(redactSensitiveKeys);
	if (value && typeof value === "object") {
		const redacted: Record<string, unknown> = {};
		for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
			redacted[key] = SENSITIVE_KEY_RE.test(key) ? "[redacted]" : redactSensitiveKeys(val);
		}
		return redacted;
	}
	return value;
}

const SECRET_VALUE_PATTERNS: RegExp[] = [
	/Bearer\s+[A-Za-z0-9\-_.=]{10,}/gi,
	/\bsk-(ant-)?[A-Za-z0-9-_]{10,}\b/gi,
	/\bAKIA[0-9A-Z]{16}\b/g,
	/\b(AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN|GH_TOKEN)\s*=\s*\S+/gi,
	/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
];

function redactSecretPatterns(text: string): string {
	let redacted = text;
	for (const pattern of SECRET_VALUE_PATTERNS) {
		redacted = redacted.replace(pattern, "[redacted]");
	}
	return redacted;
}

/** Truncated, redacted summary of tool params — never the full raw payload verbatim. */
function summarizeParamsForAudit(params: unknown): string {
	let text: string;
	try {
		text = JSON.stringify(redactSensitiveKeys(params)) ?? "";
	} catch {
		text = String(params);
	}
	text = redactSecretPatterns(text);
	return text.length > AUDIT_PARAMS_SUMMARY_MAX_CHARS ? `${text.slice(0, AUDIT_PARAMS_SUMMARY_MAX_CHARS)}…` : text;
}

/**
 * `details.harmBlocked`/`details.action` let downstream code (module D's
 * autonomous-mode gating) detect a hard-block from the tool-result message
 * alone, without re-running the check or reading the audit log.
 */
function harmBlockedResult(verdict: HarmVerdict) {
	return {
		content: [{ type: "text" as const, text: `${verdict.reason}\n${verdict.consequence}` }],
		isError: true,
		details: { harmBlocked: true, action: verdict.action },
	};
}

/**
 * (task #78) Vault placeholder substitution — the critical security boundary
 * between harm-check and actual execution. Only ever touches the same
 * bash/ipython `sourceKey` HARM_CHECKED_TOOLS already scans, and only runs
 * AFTER `guardHarm` has already returned unblocked, so Layer 1/Layer 2 always
 * see placeholder-only text, never the resolved secret. Returns the original
 * `params` object unchanged (same reference) when there's nothing to
 * substitute, so the caller's audit-log summary of the original params is
 * never accidentally built from a clone.
 */
async function resolveVaultParamsForExecution(
	toolName: string,
	params: unknown,
	ctx: ExtensionContext | undefined,
): Promise<unknown> {
	const spec = HARM_CHECKED_TOOLS[toolName];
	if (!spec || !ctx?.vault) return params;
	const source = (params as Record<string, unknown> | undefined)?.[spec.sourceKey];
	if (typeof source !== "string") return params;
	const resolved = await ctx.vault.resolvePlaceholders(source);
	if (resolved === source) return params;
	return { ...(params as Record<string, unknown>), [spec.sourceKey]: resolved };
}

/** Bound on how deep `scrubToolResultForVault` recurses into a tool result's `details` when looking for string leaves to scrub — real detail shapes (e.g. ipython's `{ error: { evalue, traceback: [...] } }`) only nest a couple of levels deep; this is headroom, not a tight fit. */
const SCRUB_DETAILS_MAX_DEPTH = 4;

/** Recursively scrub every string value found in `value`, up to `SCRUB_DETAILS_MAX_DEPTH`. Structural (walks by shape, not by field name) so it works across every tool's own `details` type without the generic wrapper having to know each tool's specific fields. */
async function scrubStringsDeep(vault: VaultPlaceholderResolver, value: unknown, depth = 0): Promise<unknown> {
	if (depth > SCRUB_DETAILS_MAX_DEPTH) return value;
	if (typeof value === "string") return vault.scrubKnownSecrets(value);
	if (Array.isArray(value)) return Promise.all(value.map((item) => scrubStringsDeep(vault, item, depth + 1)));
	if (value && typeof value === "object" && !Buffer.isBuffer(value) && !(value instanceof Date)) {
		const entries = await Promise.all(
			Object.entries(value as Record<string, unknown>).map(
				async ([key, val]) => [key, await scrubStringsDeep(vault, val, depth + 1)] as const,
			),
		);
		return Object.fromEntries(entries);
	}
	return value;
}

/**
 * (task #84) Best-effort output scrubbing — the second half of the vault's
 * substitution boundary. `resolveVaultParamsForExecution` above resolves a
 * placeholder to its real secret immediately before execution; this runs
 * AFTER execution, scrubbing the *returned* result's text content and detail
 * fields so a secret that got echoed back into the tool's own output (stdout
 * reflecting a submitted value, an error message, etc) is replaced with its
 * placeholder before this result is returned up the chain — which is what
 * feeds the transcript (and, via `logAudit` right after, would otherwise
 * feed the audit log too).
 *
 * Known gap: any partial results already delivered via `onUpdate` during
 * execution (bash/ipython stream output as it runs) reach the UI before this
 * scrub ever sees them — this only scrubs the final settled result.
 */
async function scrubToolResultForVault<TDetails>(
	result: AgentToolResult<TDetails>,
	vault: VaultPlaceholderResolver,
): Promise<AgentToolResult<TDetails>> {
	const content = await Promise.all(
		result.content.map(async (item) =>
			item.type === "text" ? { ...item, text: await vault.scrubKnownSecrets(item.text) } : item,
		),
	);
	const details = (await scrubStringsDeep(vault, result.details)) as TDetails;
	return { ...result, content, details };
}

/** Wrap a ToolDefinition into an AgentTool for the core runtime. */
export function wrapToolDefinition<TDetails = unknown>(
	definition: ToolDefinition<any, TDetails>,
	ctxFactory?: () => ExtensionContext,
): AgentTool<any, TDetails> {
	return {
		name: definition.name,
		label: definition.label,
		description: definition.description,
		parameters: definition.parameters,
		prepareArguments: definition.prepareArguments,
		executionMode: definition.executionMode,
		execute: async (toolCallId, params, signal, onUpdate) => {
			const ctx = ctxFactory?.() as ExtensionContext | undefined;
			const guard = await guardHarm(definition.name, params, ctx);
			if (guard.blocked) {
				await logAudit(ctx, "tool_call", { toolName: definition.name, outcome: "blocked" });
				return harmBlockedResult(guard.verdict) as any;
			}
			// Substitution happens strictly after the guard above, on a fresh params
			// object — `params` (used for the audit summary below) is never mutated.
			const executionParams = await resolveVaultParamsForExecution(definition.name, params, ctx);
			const rawResult = await definition.execute(
				toolCallId,
				executionParams,
				signal,
				onUpdate,
				ctx as ExtensionContext,
			);
			const result = ctx?.vault ? await scrubToolResultForVault(rawResult, ctx.vault) : rawResult;
			await logAudit(ctx, "tool_call", {
				toolName: definition.name,
				outcome: (result as { isError?: boolean } | undefined)?.isError ? "error" : "ok",
				paramsSummary: summarizeParamsForAudit(params),
			});
			return result;
		},
	};
}

/** Wrap multiple ToolDefinitions into AgentTools for the core runtime. */
export function wrapToolDefinitions(
	definitions: ToolDefinition<any, any>[],
	ctxFactory?: () => ExtensionContext,
): AgentTool<any>[] {
	return definitions.map((definition) => wrapToolDefinition(definition, ctxFactory));
}

/**
 * Synthesize a minimal ToolDefinition from an AgentTool.
 *
 * This keeps AgentSession's internal registry definition-first even when a caller
 * provides plain AgentTool overrides that do not include prompt metadata or renderers.
 */
export function createToolDefinitionFromAgentTool(tool: AgentTool<any>): ToolDefinition<any, unknown> {
	return {
		name: tool.name,
		label: tool.label,
		description: tool.description,
		parameters: tool.parameters as any,
		prepareArguments: tool.prepareArguments,
		executionMode: tool.executionMode,
		execute: async (toolCallId, params, signal, onUpdate) => tool.execute(toolCallId, params, signal, onUpdate),
	};
}
