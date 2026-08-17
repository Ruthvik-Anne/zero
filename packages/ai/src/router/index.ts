import { complete, completeSimple, stream, streamSimple } from "../stream.js";
import type {
	Api,
	AssistantMessage,
	AssistantMessageEvent,
	AssistantMessageEventStream,
	Context,
	Model,
	ProviderStreamOptions,
	SimpleStreamOptions,
} from "../types.js";
import { createAssistantMessageEventStream } from "../utils/event-stream.js";
import { computeRetryDelayMs, delayForRetry } from "./retry-backoff.js";
import { appendUsageLedger, type UsageLedgerEntry } from "./usage-ledger.js";

export * from "./model-classification/index.js";
export type { UsageLedgerEntry } from "./usage-ledger.js";

/**
 * Unified multi-provider router (module G) — one cohesive module owning candidate
 * selection, fallback, and usage tracking. Not a decorator around stream()/complete():
 * callers pass an ordered candidate list and get back one call that either succeeds
 * or exhausts the list, using the SAME error-classification data every provider
 * already writes onto a failed AssistantMessage (see utils/stream-failure.ts's
 * `recordStreamFailure`) — no new classification logic duplicated here.
 */

export interface ProviderCandidate<TApi extends Api = Api> {
	model: Model<TApi>;
	/** Per-candidate option overrides (e.g. a different apiKey), merged over the shared options. */
	options?: ProviderStreamOptions;
	/** Human-readable label for logging/audit (module H), e.g. "primary", "openrouter-fallback". */
	label?: string;
}

export interface RouterOptions extends SimpleStreamOptions {
	/** Append-only usage ledger path (module G convention: session-artifacts/<id>/usage/<date>.jsonl). */
	ledgerPath?: string;
	/** Fires after every attempt (success or failure), before advancing to the next candidate. */
	onAttempt?: (entry: UsageLedgerEntry) => void;
}

/** Failure kinds worth retrying against the next candidate — transient/capacity issues, not bad requests. */
// (D12) "network_error" (ECONNRESET, ETIMEDOUT, "fetch failed", "socket hang
// up", ...) added — a dropped connection mid-handshake is exactly the
// transient case this module's fallback chain exists for, and previously
// classified as "unknown" here, which never retried.
const RETRYABLE_FAILURE_KINDS = new Set(["rate_limit", "overloaded", "server_error", "network_error"]);

interface ClassifiedFailure {
	kind: string;
	/** Provider-supplied Retry-After, in ms, if the classifier found one (see stream-failure.ts). */
	retryAfterMs?: number;
}

/**
 * Reads the classification a provider already recorded on a failed message via
 * `recordStreamFailure` (type: "provider_stream_failure", details: StreamFailureInfo).
 * Returns undefined when the message did not fail.
 */
function classifyCompletionFailure(message: AssistantMessage): ClassifiedFailure | undefined {
	if (message.stopReason !== "error") return undefined;
	const diagnostics = message.diagnostics ?? [];
	const diagnostic = [...diagnostics].reverse().find((d) => d.type === "provider_stream_failure");
	const details = diagnostic?.details as { kind?: string; retryAfterMs?: unknown } | undefined;
	const retryAfterMs = typeof details?.retryAfterMs === "number" ? details.retryAfterMs : undefined;
	return { kind: details?.kind ?? "unknown", retryAfterMs };
}

async function recordAttempt(
	candidate: ProviderCandidate,
	message: AssistantMessage,
	options: RouterOptions | undefined,
): Promise<ClassifiedFailure | undefined> {
	const failure = classifyCompletionFailure(message);
	const entry: UsageLedgerEntry = {
		timestamp: Date.now(),
		provider: candidate.model.provider,
		model: candidate.model.id,
		outcome: failure ? "error" : "success",
		failureKind: failure?.kind,
		usage: message.usage,
	};
	options?.onAttempt?.(entry);
	if (options?.ledgerPath) {
		await appendUsageLedger(options.ledgerPath, entry);
	}
	return failure;
}

async function runCandidates(
	callOne: (candidate: ProviderCandidate) => Promise<AssistantMessage>,
	candidates: readonly ProviderCandidate[],
	options?: RouterOptions,
): Promise<AssistantMessage> {
	if (candidates.length === 0) {
		throw new Error("Provider router requires at least one candidate");
	}
	let lastMessage: AssistantMessage | undefined;
	for (let i = 0; i < candidates.length; i++) {
		const candidate = candidates[i];
		const isLast = i === candidates.length - 1;
		const message = await callOne(candidate);
		const failure = await recordAttempt(candidate, message, options);
		if (!failure) {
			return message;
		}
		lastMessage = message;
		if (isLast || !RETRYABLE_FAILURE_KINDS.has(failure.kind)) {
			// Non-retryable (bad request, auth, refusal, ...) or candidates exhausted:
			// surface the failed message as-is, same contract every caller already handles.
			return message;
		}
		// Retryable failure with candidates remaining — advance to the next one, honoring
		// a Retry-After-aware backoff for rate_limit/overloaded (0 for every other kind).
		await delayForRetry(computeRetryDelayMs(failure.kind, failure.retryAfterMs, i + 1), options?.signal);
	}
	// Unreachable (the loop always returns on its last iteration), kept for type-safety.
	return lastMessage as AssistantMessage;
}

/** Non-streaming completion with automatic multi-candidate fallback. */
export async function routedComplete(
	candidates: readonly ProviderCandidate[],
	context: Context,
	options?: RouterOptions,
): Promise<AssistantMessage> {
	return runCandidates(
		(candidate) => complete(candidate.model, context, { ...options, ...candidate.options }),
		candidates,
		options,
	);
}

/** Non-streaming completion (with reasoning/thinkingBudgets support) with automatic multi-candidate fallback. */
export async function routedCompleteSimple(
	candidates: readonly ProviderCandidate[],
	context: Context,
	options?: RouterOptions,
): Promise<AssistantMessage> {
	return runCandidates(
		(candidate) => completeSimple(candidate.model, context, { ...options, ...candidate.options }),
		candidates,
		options,
	);
}

function buildFallbackErrorMessage(candidate: ProviderCandidate | undefined, error: unknown): AssistantMessage {
	return {
		role: "assistant",
		content: [],
		api: candidate?.model.api ?? "unknown",
		provider: candidate?.model.provider ?? "unknown",
		model: candidate?.model.id ?? "unknown",
		usage: {
			input: 0,
			output: 0,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 0,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		},
		stopReason: "error",
		errorMessage: error instanceof Error ? error.message : String(error),
		timestamp: Date.now(),
	};
}

/**
 * Streaming completion with automatic multi-candidate fallback.
 *
 * Streaming fallback has one hard constraint a non-streaming router doesn't:
 * once a delta has been relayed to the consumer (rendered in a TUI, appended
 * to a transcript), it cannot be un-rendered — so this only falls back to the
 * next candidate while a candidate's stream has produced NOTHING but its
 * opening `start` event. The moment any real content event arrives (a
 * text/thinking/toolcall start, delta, or end), this candidate's outcome is
 * final and gets relayed through to completion, success or failure.
 */
function routedStreamGeneric(
	streamOne: (candidate: ProviderCandidate) => AssistantMessageEventStream,
	candidates: readonly ProviderCandidate[],
	options?: RouterOptions,
): AssistantMessageEventStream {
	const outer = createAssistantMessageEventStream();
	if (candidates.length === 0) {
		const error = new Error("Provider router requires at least one candidate");
		outer.push({ type: "error", reason: "error", error: buildFallbackErrorMessage(candidates[0], error) });
		outer.end();
		return outer;
	}

	void (async () => {
		for (let i = 0; i < candidates.length; i++) {
			const candidate = candidates[i];
			const isLast = i === candidates.length - 1;
			const inner = streamOne(candidate);

			let committed = false;
			const buffered: AssistantMessageEvent[] = [];
			for await (const event of inner) {
				if (committed) {
					outer.push(event);
					continue;
				}
				if (event.type === "start") {
					buffered.push(event);
					continue;
				}
				if (event.type === "error") {
					// Nothing relayed yet — handled below via the final message, without
					// pushing this event, so a retried candidate doesn't leave a stray
					// error frame in the consumer's stream.
					break;
				}
				// Any other event type is real content: commit and flush what was buffered.
				committed = true;
				for (const b of buffered) outer.push(b);
				outer.push(event);
			}

			const finalMessage = await inner.result();
			const failure = await recordAttempt(candidate, finalMessage, options);

			if (committed) {
				// Already relayed to the consumer — this candidate's outcome is final either way.
				outer.end(finalMessage);
				return;
			}
			if (!failure || isLast || !RETRYABLE_FAILURE_KINDS.has(failure.kind)) {
				// Nothing was shown yet, and either it succeeded pre-content (unexpected but
				// handled), or this failure isn't worth retrying, or candidates are exhausted:
				// relay the buffered start (if any) and the terminal event, then end.
				for (const b of buffered) outer.push(b);
				outer.push(
					finalMessage.stopReason === "error" || finalMessage.stopReason === "aborted"
						? { type: "error", reason: finalMessage.stopReason, error: finalMessage }
						: { type: "done", reason: finalMessage.stopReason, message: finalMessage },
				);
				outer.end(finalMessage);
				return;
			}
			// Retryable failure with zero content relayed and candidates remaining:
			// silently advance to the next candidate (after the same Retry-After-aware
			// backoff as the non-streaming path). The consumer never saw this attempt.
			await delayForRetry(computeRetryDelayMs(failure.kind, failure.retryAfterMs, i + 1), options?.signal);
		}
	})().catch((error) => {
		const message = buildFallbackErrorMessage(candidates[candidates.length - 1], error);
		outer.push({ type: "error", reason: "error", error: message });
		outer.end(message);
	});

	return outer;
}

/** Streaming completion with automatic multi-candidate fallback (see routedStreamGeneric doc). */
export function routedStream(
	candidates: readonly ProviderCandidate[],
	context: Context,
	options?: RouterOptions,
): AssistantMessageEventStream {
	return routedStreamGeneric(
		(candidate) => stream(candidate.model, context, { ...options, ...candidate.options }),
		candidates,
		options,
	);
}

/** Streaming completion (with reasoning/thinkingBudgets support) with automatic multi-candidate fallback. */
export function routedStreamSimple(
	candidates: readonly ProviderCandidate[],
	context: Context,
	options?: RouterOptions,
): AssistantMessageEventStream {
	return routedStreamGeneric(
		(candidate) => streamSimple(candidate.model, context, { ...options, ...candidate.options }),
		candidates,
		options,
	);
}
