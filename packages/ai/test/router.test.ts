import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fauxAssistantMessage, registerFauxProvider } from "../src/providers/faux.js";
import { routedCompleteSimple, routedStreamSimple } from "../src/router/index.js";
import type { AssistantMessageEvent, Context } from "../src/types.js";

const context: Context = { messages: [{ role: "user", content: "hi", timestamp: Date.now() }] };

/**
 * The router now waits (Retry-After or jittered backoff) before advancing
 * past a rate_limit/overloaded failure — see retry-backoff.test.ts for the
 * delay math itself. Fake timers here just unblock that wait deterministically
 * instead of the test suite actually sleeping. Only `setTimeout`/`clearTimeout`
 * are faked: the faux provider's own scheduling runs on `queueMicrotask`
 * (see providers/faux.ts's `scheduleChunk`), which must stay real or the
 * faux stream itself would never advance.
 *
 * Advances in small steps rather than one big jump: a test that also does
 * real async I/O (e.g. the usage-ledger write) can reach the `setTimeout`
 * call itself sometime after this starts running, so a single upfront
 * `advanceTimersByTimeAsync(N)` can return having found nothing pending yet,
 * with no later call to advance the now-scheduled timer — stepping keeps
 * re-checking until `work()` actually settles (or a generous budget expires).
 */
async function runWithTimers<T>(work: () => Promise<T>, maxAdvanceMs = 10_000): Promise<T> {
	vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
	try {
		let settled = false;
		const promise = work();
		void promise.then(
			() => {
				settled = true;
			},
			() => {
				settled = true;
			},
		);
		const stepMs = 50;
		for (let elapsed = 0; !settled && elapsed < maxAdvanceMs; elapsed += stepMs) {
			await vi.advanceTimersByTimeAsync(stepMs);
		}
		return await promise;
	} finally {
		vi.useRealTimers();
	}
}

function rateLimited(text: string) {
	const message = fauxAssistantMessage(text, { stopReason: "error", errorMessage: "rate limited" });
	message.diagnostics = [
		{
			type: "provider_stream_failure",
			timestamp: Date.now(),
			details: { kind: "rate_limit", status: 429 },
		},
	];
	return message;
}

/** Fails with zero content blocks — nothing gets streamed before the terminal error. */
function rateLimitedNoContent() {
	const message = fauxAssistantMessage([], { stopReason: "error", errorMessage: "rate limited" });
	message.diagnostics = [
		{
			type: "provider_stream_failure",
			timestamp: Date.now(),
			details: { kind: "rate_limit", status: 429 },
		},
	];
	return message;
}

/** Fails AFTER streaming real content — the router must not retry once content is relayed. */
function failsAfterContent(partialText: string) {
	const message = fauxAssistantMessage(partialText, { stopReason: "error", errorMessage: "overloaded mid-stream" });
	message.diagnostics = [
		{
			type: "provider_stream_failure",
			timestamp: Date.now(),
			details: { kind: "overloaded", status: 529 },
		},
	];
	return message;
}

async function collectEvents(streamResult: AsyncIterable<AssistantMessageEvent>): Promise<AssistantMessageEvent[]> {
	const events: AssistantMessageEvent[] = [];
	for await (const event of streamResult) events.push(event);
	return events;
}

/** D12: a dropped connection mid-handshake (ECONNRESET et al.) — no provider
 * error body at all, previously classified "unknown" and never retried. */
function networkError(text: string) {
	const message = fauxAssistantMessage(text, { stopReason: "error", errorMessage: "connection reset" });
	message.diagnostics = [
		{
			type: "provider_stream_failure",
			timestamp: Date.now(),
			details: { kind: "network_error" },
		},
	];
	return message;
}

function invalidRequest(text: string) {
	const message = fauxAssistantMessage(text, { stopReason: "error", errorMessage: "bad request" });
	message.diagnostics = [
		{
			type: "provider_stream_failure",
			timestamp: Date.now(),
			details: { kind: "invalid_request", status: 400 },
		},
	];
	return message;
}

function rateLimitedWithRetryAfter(text: string, retryAfterMs: number) {
	const message = fauxAssistantMessage(text, { stopReason: "error", errorMessage: "rate limited" });
	message.diagnostics = [
		{
			type: "provider_stream_failure",
			timestamp: Date.now(),
			details: { kind: "rate_limit", status: 429, retryAfterMs },
		},
	];
	return message;
}

describe("provider router (module G)", () => {
	let registrations: ReturnType<typeof registerFauxProvider>[] = [];
	let ledgerDir: string;

	beforeEach(async () => {
		registrations = [];
		ledgerDir = await mkdtemp(join(tmpdir(), "zero-router-test-"));
	});

	afterEach(async () => {
		for (const reg of registrations) reg.unregister();
		await rm(ledgerDir, { recursive: true, force: true });
	});

	function register(provider: string) {
		const reg = registerFauxProvider({ provider });
		registrations.push(reg);
		return reg;
	}

	it("returns the first candidate's success without trying the rest", async () => {
		const primary = register("primary");
		const fallback = register("openrouter");
		primary.setResponses([fauxAssistantMessage("from primary")]);
		fallback.setResponses([fauxAssistantMessage("from fallback")]);

		const result = await routedCompleteSimple(
			[{ model: primary.getModel() }, { model: fallback.getModel() }],
			context,
		);

		expect(result.content).toEqual([{ type: "text", text: "from primary" }]);
		expect(fallback.state.callCount).toBe(0);
	});

	it("falls back to the next candidate on a retryable (rate-limit) failure, after a jittered backoff wait", async () => {
		const primary = register("primary");
		const fallback = register("openrouter");
		primary.setResponses([rateLimited("rate limited")]);
		fallback.setResponses([fauxAssistantMessage("from fallback")]);

		const result = await runWithTimers(() =>
			routedCompleteSimple([{ model: primary.getModel() }, { model: fallback.getModel() }], context),
		);

		expect(result.content).toEqual([{ type: "text", text: "from fallback" }]);
		expect(primary.state.callCount).toBe(1);
		expect(fallback.state.callCount).toBe(1);
	});

	it("waits approximately the provider's Retry-After value before retrying a rate-limited candidate", async () => {
		const primary = register("primary");
		const fallback = register("openrouter");
		primary.setResponses([rateLimitedWithRetryAfter("rate limited", 5000)]);
		fallback.setResponses([fauxAssistantMessage("from fallback")]);

		vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
		try {
			let resolved = false;
			const resultPromise = routedCompleteSimple(
				[{ model: primary.getModel() }, { model: fallback.getModel() }],
				context,
			).then((result) => {
				resolved = true;
				return result;
			});

			// Not yet at the 5s Retry-After: fallback must not have been called.
			await vi.advanceTimersByTimeAsync(4000);
			expect(resolved).toBe(false);
			expect(fallback.state.callCount).toBe(0);

			// Past the 5s Retry-After: the router advances to the fallback.
			await vi.advanceTimersByTimeAsync(1000);
			const result = await resultPromise;
			expect(resolved).toBe(true);
			expect(result.content).toEqual([{ type: "text", text: "from fallback" }]);
			expect(fallback.state.callCount).toBe(1);
		} finally {
			vi.useRealTimers();
		}
	});

	it("clamps an unreasonably large Retry-After instead of waiting the full amount", async () => {
		const primary = register("primary");
		const fallback = register("openrouter");
		// Far beyond the router's 60s cap — the router must not wait the full 10 minutes.
		primary.setResponses([rateLimitedWithRetryAfter("rate limited", 10 * 60_000)]);
		fallback.setResponses([fauxAssistantMessage("from fallback")]);

		vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
		try {
			let resolved = false;
			const resultPromise = routedCompleteSimple(
				[{ model: primary.getModel() }, { model: fallback.getModel() }],
				context,
			).then((result) => {
				resolved = true;
				return result;
			});

			// Just under the 60s cap: still waiting.
			await vi.advanceTimersByTimeAsync(59_000);
			expect(resolved).toBe(false);

			// At/just past the 60s cap: the router advances, well short of the requested 10 minutes.
			await vi.advanceTimersByTimeAsync(1000);
			const result = await resultPromise;
			expect(resolved).toBe(true);
			expect(result.content).toEqual([{ type: "text", text: "from fallback" }]);
		} finally {
			vi.useRealTimers();
		}
	});

	it("uses a non-zero, non-fixed jittered backoff when no Retry-After is present", async () => {
		const primary = register("primary");
		const fallback = register("openrouter");
		primary.setResponses([rateLimited("rate limited")]);
		fallback.setResponses([fauxAssistantMessage("from fallback")]);

		vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
		try {
			let resolved = false;
			const resultPromise = routedCompleteSimple(
				[{ model: primary.getModel() }, { model: fallback.getModel() }],
				context,
			).then((result) => {
				resolved = true;
				return result;
			});

			// Attempt 1's jitter band is [1000, 2000)ms — a zero/fixed delay would have
			// resolved already; the equal-jitter floor guarantees it hasn't at 1ms in.
			await vi.advanceTimersByTimeAsync(1);
			expect(resolved).toBe(false);

			await vi.advanceTimersByTimeAsync(2000);
			const result = await resultPromise;
			expect(resolved).toBe(true);
			expect(result.content).toEqual([{ type: "text", text: "from fallback" }]);
		} finally {
			vi.useRealTimers();
		}
	});

	it("falls back to the next candidate on a network-error failure (D12)", async () => {
		const primary = register("primary");
		const fallback = register("openrouter");
		primary.setResponses([networkError("connection reset")]);
		fallback.setResponses([fauxAssistantMessage("from fallback")]);

		const result = await routedCompleteSimple(
			[{ model: primary.getModel() }, { model: fallback.getModel() }],
			context,
		);

		expect(result.content).toEqual([{ type: "text", text: "from fallback" }]);
		expect(primary.state.callCount).toBe(1);
		expect(fallback.state.callCount).toBe(1);
	});

	it("does not fall back on a non-retryable failure", async () => {
		const primary = register("primary");
		const fallback = register("openrouter");
		primary.setResponses([invalidRequest("bad request")]);
		fallback.setResponses([fauxAssistantMessage("from fallback")]);

		const result = await routedCompleteSimple(
			[{ model: primary.getModel() }, { model: fallback.getModel() }],
			context,
		);

		expect(result.stopReason).toBe("error");
		expect(fallback.state.callCount).toBe(0);
	});

	it("surfaces the last candidate's failure once every candidate is exhausted", async () => {
		const primary = register("primary");
		const fallback = register("openrouter");
		primary.setResponses([rateLimited("rate limited primary")]);
		fallback.setResponses([rateLimited("rate limited fallback")]);

		const result = await runWithTimers(() =>
			routedCompleteSimple([{ model: primary.getModel() }, { model: fallback.getModel() }], context),
		);

		expect(result.stopReason).toBe("error");
		expect(primary.state.callCount).toBe(1);
		expect(fallback.state.callCount).toBe(1);
	});

	it("persists every attempt to the usage ledger", async () => {
		const primary = register("primary");
		const fallback = register("openrouter");
		primary.setResponses([rateLimited("rate limited")]);
		fallback.setResponses([fauxAssistantMessage("from fallback")]);
		const ledgerPath = join(ledgerDir, "usage.jsonl");

		// Real timers on purpose: this test verifies ledger persistence, not retry
		// timing, and the one rate_limit->fallback hop pays at most a ~2s jittered
		// backoff with no Retry-After set — real-waiting it avoids the fake-timer +
		// real fs-write interleaving flakiness that runWithTimers hit here.
		await routedCompleteSimple([{ model: primary.getModel() }, { model: fallback.getModel() }], context, {
			ledgerPath,
		});

		const contents = await readFile(ledgerPath, "utf8");
		const lines = contents
			.trim()
			.split("\n")
			.map((line) => JSON.parse(line));
		expect(lines).toHaveLength(2);
		expect(lines[0].outcome).toBe("error");
		expect(lines[0].provider).toBe("primary");
		expect(lines[1].outcome).toBe("success");
		expect(lines[1].provider).toBe("openrouter");
	});

	describe("streaming fallback", () => {
		it("falls back silently when a candidate fails before streaming any content", async () => {
			const primary = register("primary");
			const fallback = register("openrouter");
			primary.setResponses([rateLimitedNoContent()]);
			fallback.setResponses([fauxAssistantMessage("from fallback")]);

			const events = await runWithTimers(() =>
				collectEvents(routedStreamSimple([{ model: primary.getModel() }, { model: fallback.getModel() }], context)),
			);

			// The consumer never sees primary's start/error at all — only fallback's full stream.
			expect(events.filter((e) => e.type === "error")).toHaveLength(0);
			const doneEvent = events.find((e) => e.type === "done");
			expect(doneEvent?.type).toBe("done");
			expect(primary.state.callCount).toBe(1);
			expect(fallback.state.callCount).toBe(1);
		});

		it("commits to a candidate once content has started streaming, even if it then fails", async () => {
			const primary = register("primary");
			const fallback = register("openrouter");
			primary.setResponses([failsAfterContent("partial answer")]);
			fallback.setResponses([fauxAssistantMessage("from fallback")]);

			const events = await collectEvents(
				routedStreamSimple([{ model: primary.getModel() }, { model: fallback.getModel() }], context),
			);

			expect(events.some((e) => e.type === "text_delta")).toBe(true);
			expect(events.at(-1)?.type).toBe("error");
			// Fallback was never even called — the failed stream had already been relayed.
			expect(primary.state.callCount).toBe(1);
			expect(fallback.state.callCount).toBe(0);
		});

		it("relays a first candidate's success stream through untouched", async () => {
			const primary = register("primary");
			primary.setResponses([fauxAssistantMessage("hello from primary")]);

			const events = await collectEvents(routedStreamSimple([{ model: primary.getModel() }], context));

			const textDeltas = events
				.filter((e) => e.type === "text_delta")
				.map((e) => (e as any).delta)
				.join("");
			expect(textDeltas).toBe("hello from primary");
			expect(events.at(-1)?.type).toBe("done");
		});
	});
});
