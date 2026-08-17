import { afterEach, describe, expect, test, vi } from "vitest";
import { setLogSink } from "../src/log.js";
import {
	clampRetryAfterMs,
	computeRetryDelayMs,
	delayForRetry,
	MAX_RETRY_AFTER_MS,
} from "../src/router/retry-backoff.js";

afterEach(() => setLogSink(undefined));

describe("computeRetryDelayMs", () => {
	test("non-backoff kinds (auth, invalid_request, refusal, network_error, server_error) get zero delay", () => {
		for (const kind of ["auth", "invalid_request", "refusal", "network_error", "server_error", "unknown"]) {
			expect(computeRetryDelayMs(kind, undefined, 1)).toBe(0);
			expect(computeRetryDelayMs(kind, 5000, 1)).toBe(0);
		}
	});

	test("honors a Retry-After value for rate_limit/overloaded", () => {
		expect(computeRetryDelayMs("rate_limit", 2500, 1)).toBe(2500);
		expect(computeRetryDelayMs("overloaded", 100, 3)).toBe(100);
	});

	test("clamps an unreasonably large Retry-After to the cap", () => {
		expect(computeRetryDelayMs("rate_limit", 10 * 60_000, 1)).toBe(MAX_RETRY_AFTER_MS);
		expect(clampRetryAfterMs(10 * 60_000)).toBe(MAX_RETRY_AFTER_MS);
		expect(clampRetryAfterMs(1000)).toBe(1000);
	});

	test("logs when clamping a Retry-After value", () => {
		const logged: Record<string, unknown>[] = [];
		setLogSink((entry) => logged.push(entry));
		computeRetryDelayMs("rate_limit", 999_999, 1);
		expect(logged).toHaveLength(1);
		expect(logged[0]).toMatchObject({ level: "warn", component: "ai.router" });
	});

	test("falls back to jittered exponential backoff with no Retry-After, within the equal-jitter band", () => {
		// attempt n -> band [c/2, c] where c = min(30_000, 1000 * 2^n).
		const bands: Record<number, [number, number]> = {
			1: [1000, 2000],
			2: [2000, 4000],
			3: [4000, 8000],
		};
		for (const [attempt, [low, high]] of Object.entries(bands)) {
			for (let i = 0; i < 50; i++) {
				const delay = computeRetryDelayMs("rate_limit", undefined, Number(attempt));
				expect(delay).toBeGreaterThanOrEqual(low);
				expect(delay).toBeLessThanOrEqual(high);
			}
		}
	});

	test("jittered backoff is not a fixed value across repeated calls", () => {
		const samples = new Set(Array.from({ length: 20 }, () => computeRetryDelayMs("overloaded", undefined, 2)));
		expect(samples.size).toBeGreaterThan(1);
	});

	test("jittered backoff caps out for large attempt numbers", () => {
		const delay = computeRetryDelayMs("rate_limit", undefined, 20);
		expect(delay).toBeGreaterThanOrEqual(15_000);
		expect(delay).toBeLessThanOrEqual(30_000);
	});

	test("a zero or negative Retry-After falls back to jitter instead of skipping the wait", () => {
		expect(computeRetryDelayMs("rate_limit", 0, 1)).toBeGreaterThan(0);
		expect(computeRetryDelayMs("rate_limit", -5, 1)).toBeGreaterThan(0);
	});
});

describe("delayForRetry", () => {
	test("resolves immediately for a zero delay", async () => {
		vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
		try {
			await delayForRetry(0);
		} finally {
			vi.useRealTimers();
		}
	});

	test("waits the requested duration", async () => {
		vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
		try {
			let resolved = false;
			const promise = delayForRetry(5000).then(() => {
				resolved = true;
			});
			await vi.advanceTimersByTimeAsync(4000);
			expect(resolved).toBe(false);
			await vi.advanceTimersByTimeAsync(1000);
			await promise;
			expect(resolved).toBe(true);
		} finally {
			vi.useRealTimers();
		}
	});

	test("resolves early when the signal aborts mid-wait", async () => {
		vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
		try {
			const controller = new AbortController();
			let resolved = false;
			const promise = delayForRetry(30_000, controller.signal).then(() => {
				resolved = true;
			});
			await vi.advanceTimersByTimeAsync(1000);
			expect(resolved).toBe(false);
			controller.abort();
			await promise;
			expect(resolved).toBe(true);
		} finally {
			vi.useRealTimers();
		}
	});

	test("resolves immediately when the signal is already aborted", async () => {
		const controller = new AbortController();
		controller.abort();
		let resolved = false;
		await delayForRetry(30_000, controller.signal).then(() => {
			resolved = true;
		});
		expect(resolved).toBe(true);
	});
});
