import { type LogEntry, setLogSink } from "@zero-agent/ai";
import { afterEach, describe, expect, it } from "vitest";
import { createRlmLogErrorHostHandler } from "../../src/core/rlm-runtime.js";
import { createHarness, type Harness } from "./harness.js";

/**
 * `rlm.log_error(message, **context)` — lets the agent add its own findings
 * to the same structured error log a crashing process writes to (see
 * installClientCrashHandlers in core/logging.ts and `zero doctor`).
 */
describe("rlm.log_error", () => {
	const harnesses: Harness[] = [];

	afterEach(() => {
		while (harnesses.length > 0) harnesses.pop()?.cleanup();
		setLogSink(undefined);
	});

	it("writes the agent's message and context into the structured log", async () => {
		const harness = await createHarness();
		harnesses.push(harness);
		const entries: LogEntry[] = [];
		setLogSink((entry) => entries.push(entry));

		await harness.session.handleRlmLogError({
			message: "tool X returned malformed JSON",
			context: { tool: "X" },
		});

		expect(entries).toHaveLength(1);
		expect(entries[0]).toMatchObject({
			level: "error",
			component: "coding-agent.rlm-agent",
			msg: "tool X returned malformed JSON",
			source: "agent",
			tool: "X",
		});
	});

	it("logs without context fields when none are given", async () => {
		const harness = await createHarness();
		harnesses.push(harness);
		const entries: LogEntry[] = [];
		setLogSink((entry) => entries.push(entry));

		await harness.session.handleRlmLogError({ message: "recovered from a transient failure" });

		expect(entries).toHaveLength(1);
		expect(entries[0].msg).toBe("recovered from a transient failure");
	});

	it("rejects an empty or non-string message at the host-handler boundary", async () => {
		const handler = createRlmLogErrorHostHandler(async () => {});
		await expect(handler({ message: "" })).rejects.toThrow(/non-empty string/);
		await expect(handler({ message: 123 as never })).rejects.toThrow(/non-empty string/);
	});

	it("rejects a non-object context at the host-handler boundary", async () => {
		const handler = createRlmLogErrorHostHandler(async () => {});
		await expect(handler({ message: "ok", context: "nope" as never })).rejects.toThrow(/context must be an object/);
		await expect(handler({ message: "ok", context: ["nope"] as never })).rejects.toThrow(/context must be an object/);
	});
});
