import { getLogger } from "../log.js";

const log = getLogger("ai.router");

/**
 * Retry-timing policy for the provider router (module G). Kept in its own
 * module so the pure delay math can be unit-tested without fake timers.
 */

/** Failure kinds this policy applies to. Other retryable kinds (server_error,
 * network_error — see router/index.ts's RETRYABLE_FAILURE_KINDS) keep
 * advancing to the next candidate instantly, unchanged from before this
 * module existed: retrying immediately after a dropped connection or a 5xx
 * makes sense, waiting out a capacity limit does not. */
export const BACKOFF_FAILURE_KINDS = new Set(["rate_limit", "overloaded"]);

/** Never honor a provider Retry-After longer than this, however it's spelled
 * (header, seconds, HTTP-date, ...) — a buggy or hostile value must not stall
 * the whole router for an unbounded amount of time. */
export const MAX_RETRY_AFTER_MS = 60_000;

/** Base and cap for the jitter fallback used when no Retry-After is present. */
const BACKOFF_BASE_MS = 1_000;
const BACKOFF_CAP_MS = 30_000;

/**
 * "Equal jitter" backoff (one of the family described in AWS's "Exponential
 * Backoff and Jitter"): half of the exponential value is fixed, half is
 * randomized, so attempt n's delay falls in [c/2, c] where
 * c = min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * 2^n). This is deliberately NOT
 * "full jitter" ([0, c]): full jitter can degrade to ~0 on an unlucky draw,
 * which would mean "no backoff at all" for a rate-limited provider. Equal
 * jitter guarantees a growing floor per attempt while still spreading
 * concurrent retries out (avoiding a thundering herd re-hitting the
 * provider at the exact same instant a fixed delay would produce).
 */
function equalJitterMs(attempt: number): number {
	const capped = Math.min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * 2 ** attempt);
	return capped / 2 + Math.random() * (capped / 2);
}

/** Clamp a provider-supplied Retry-After to the sane cap, logging when it fires. */
export function clampRetryAfterMs(retryAfterMs: number): number {
	if (retryAfterMs <= MAX_RETRY_AFTER_MS) return retryAfterMs;
	log.warn("clamping provider Retry-After value to the router's cap", {
		retryAfterMs,
		clampedToMs: MAX_RETRY_AFTER_MS,
	});
	return MAX_RETRY_AFTER_MS;
}

/**
 * Delay to wait before the router's next attempt, given a classified failure
 * kind, an optional provider-supplied Retry-After (ms), and the 1-based
 * count of retryable failures seen so far in this router call. Returns 0 for
 * any kind outside BACKOFF_FAILURE_KINDS — those advance instantly, exactly
 * as before this module existed.
 */
export function computeRetryDelayMs(kind: string, retryAfterMs: number | undefined, attempt: number): number {
	if (!BACKOFF_FAILURE_KINDS.has(kind)) return 0;
	if (retryAfterMs !== undefined && retryAfterMs > 0 && Number.isFinite(retryAfterMs)) {
		return clampRetryAfterMs(retryAfterMs);
	}
	return equalJitterMs(Math.max(1, attempt));
}

/**
 * Sleep for `ms`, resolving early if `signal` aborts — a clamped Retry-After
 * or jittered backoff wait must never make a user-initiated cancel unresponsive.
 */
export function delayForRetry(ms: number, signal?: AbortSignal): Promise<void> {
	if (ms <= 0 || signal?.aborted) return Promise.resolve();
	return new Promise((resolve) => {
		const onAbort = () => {
			clearTimeout(timer);
			resolve();
		};
		const timer = setTimeout(() => {
			signal?.removeEventListener("abort", onAbort);
			resolve();
		}, ms);
		signal?.addEventListener("abort", onAbort, { once: true });
	});
}
