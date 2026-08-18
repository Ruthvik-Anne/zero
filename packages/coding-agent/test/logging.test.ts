import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../src/config.js", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../src/config.js")>();
	return { ...actual, appendRotatingLog: vi.fn(), getClientErrorLogPath: () => "/fake/logs/client-errors.log" };
});

import { appendRotatingLog } from "../src/config.js";

/**
 * The interactive/foreground client process otherwise has no top-level
 * uncaughtException/unhandledRejection handler (unlike daemon-mode.ts) — a
 * crash there prints Node's default trace and vanishes with no logged trail.
 *
 * `installClientCrashHandlers` no-ops under the test runner (NODE_ENV=test)
 * — this repo's own suite calls `main()` directly, many times, in-process
 * (package-command-paths.test.ts); a real `process.exit(1)` here the first
 * time one of those hit an unhandled rejection would take down the whole
 * shared vitest worker. These tests exercise the real logic by temporarily
 * clearing NODE_ENV and reloading the module fresh (so the install-once
 * guard doesn't carry over between cases), and always invoke the captured
 * listeners directly rather than actually emitting on `process`, so a real
 * crash in this file can't cascade into `process.exit` killing the worker.
 */
describe("installClientCrashHandlers", () => {
	const originalNodeEnv = process.env.NODE_ENV;

	beforeEach(() => {
		vi.resetModules();
	});

	afterEach(() => {
		process.env.NODE_ENV = originalNodeEnv;
		vi.restoreAllMocks();
		vi.mocked(appendRotatingLog).mockClear();
	});

	async function installAndCaptureListeners(): Promise<{
		uncaughtException: (error: unknown) => void;
		unhandledRejection: (reason: unknown) => void;
	}> {
		const { installClientCrashHandlers } = await import("../src/core/logging.js");
		const beforeUncaught = new Set(process.listeners("uncaughtException"));
		const beforeUnhandled = new Set(process.listeners("unhandledRejection"));
		installClientCrashHandlers();
		const uncaughtException = process
			.listeners("uncaughtException")
			.find((listener) => !beforeUncaught.has(listener)) as (error: unknown) => void;
		const unhandledRejection = process
			.listeners("unhandledRejection")
			.find((listener) => !beforeUnhandled.has(listener)) as (reason: unknown) => void;
		if (uncaughtException) process.removeListener("uncaughtException", uncaughtException);
		if (unhandledRejection) process.removeListener("unhandledRejection", unhandledRejection);
		return { uncaughtException, unhandledRejection };
	}

	it('is a no-op under the test runner, where NODE_ENV is already "test"', async () => {
		expect(process.env.NODE_ENV).toBe("test");
		const { uncaughtException, unhandledRejection } = await installAndCaptureListeners();

		expect(uncaughtException).toBeUndefined();
		expect(unhandledRejection).toBeUndefined();
	});

	it("logs an uncaught exception's stack to the client error log and exits", async () => {
		delete process.env.NODE_ENV;
		const exit = vi.spyOn(process, "exit").mockImplementation(() => undefined as never);
		const { uncaughtException } = await installAndCaptureListeners();

		uncaughtException(new Error("boom"));

		expect(appendRotatingLog).toHaveBeenCalledTimes(1);
		const [path, message] = vi.mocked(appendRotatingLog).mock.calls[0];
		expect(path).toBe("/fake/logs/client-errors.log");
		expect(message).toContain("uncaught exception:");
		expect(message).toContain("Error: boom");
		expect(exit).toHaveBeenCalledWith(1);
	});

	it("logs an unhandled rejection reason and exits", async () => {
		delete process.env.NODE_ENV;
		const exit = vi.spyOn(process, "exit").mockImplementation(() => undefined as never);
		const { unhandledRejection } = await installAndCaptureListeners();

		unhandledRejection("plain string rejection reason");

		expect(appendRotatingLog).toHaveBeenCalledTimes(1);
		const [, message] = vi.mocked(appendRotatingLog).mock.calls[0];
		expect(message).toContain("unhandled rejection:");
		expect(message).toContain("plain string rejection reason");
		expect(exit).toHaveBeenCalledWith(1);
	});

	it("only installs once per process even if called again", async () => {
		delete process.env.NODE_ENV;
		const { installClientCrashHandlers } = await import("../src/core/logging.js");
		const beforeUncaught = new Set(process.listeners("uncaughtException"));

		installClientCrashHandlers();
		installClientCrashHandlers();
		const added = process.listeners("uncaughtException").filter((listener) => !beforeUncaught.has(listener));
		for (const listener of added) process.removeListener("uncaughtException", listener);

		expect(added).toHaveLength(1);
	});
});
