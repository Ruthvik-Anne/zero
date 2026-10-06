import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
	AUTO_UPDATE_RELAUNCHED_ENV,
	maybeRunAutomaticUpdate,
	shouldAttemptAutomaticUpdate,
} from "../src/cli/auto-update.js";
import { SELF_UPDATE_NOT_ATTEMPTED_EXIT_CODE } from "../src/config.js";

describe("automatic self-update", () => {
	it("runs only for an online interactive foreground launch", () => {
		expect(shouldAttemptAutomaticUpdate([], true, {})).toBe(true);
		expect(shouldAttemptAutomaticUpdate(["agents"], true, {})).toBe(true);
		expect(shouldAttemptAutomaticUpdate([], false, {})).toBe(false);
		expect(shouldAttemptAutomaticUpdate(["--print"], true, {})).toBe(false);
		expect(shouldAttemptAutomaticUpdate(["update"], true, {})).toBe(false);
		expect(shouldAttemptAutomaticUpdate(["--daemon-socket", "/tmp/zero.sock", "stop", "agent"], true, {})).toBe(
			false,
		);
		expect(shouldAttemptAutomaticUpdate([], true, { ZERO_OFFLINE: "1" })).toBe(false);
		expect(shouldAttemptAutomaticUpdate([], true, { ZERO_SKIP_VERSION_CHECK: "1" })).toBe(false);
		expect(shouldAttemptAutomaticUpdate([], true, { [AUTO_UPDATE_RELAUNCHED_ENV]: "1" })).toBe(false);
	});

	it("continues without relaunch when no update is available", () => {
		const spawn = vi.fn(() => ({ status: SELF_UPDATE_NOT_ATTEMPTED_EXIT_CODE, signal: null }));
		const env: NodeJS.ProcessEnv = {};
		const result = maybeRunAutomaticUpdate(["--model", "test"], {
			entrypoint: "cli.js",
			execPath: "node",
			execArgv: [],
			env,
			cwd: "/workspace",
			spawnSync: spawn,
		});

		expect(result).toEqual({ handled: false });
		expect(spawn).toHaveBeenCalledTimes(1);
	});

	it("relaunches once after a successful update", () => {
		const spawn = vi
			.fn()
			.mockReturnValueOnce({ status: 0, signal: null })
			.mockReturnValueOnce({ status: 7, signal: null });
		const result = maybeRunAutomaticUpdate(["--model", "test"], {
			entrypoint: "cli.js",
			execPath: "node",
			execArgv: ["--enable-source-maps"],
			env: { HOME: "/home/test" },
			cwd: "/workspace",
			spawnSync: spawn,
		});

		expect(result).toEqual({ handled: true, exitCode: 7 });
		expect(spawn).toHaveBeenNthCalledWith(
			2,
			"node",
			["--enable-source-maps", "cli.js", "--model", "test"],
			expect.objectContaining({
				env: expect.objectContaining({ HOME: "/home/test", [AUTO_UPDATE_RELAUNCHED_ENV]: "1" }),
				stdio: "inherit",
			}),
		);
		expect(spawn.mock.calls[1]?.[2]).not.toHaveProperty("shell");
	});

	it("bounds the update run with a timeout so startup cannot hang", () => {
		const spawn = vi.fn(() => ({ status: SELF_UPDATE_NOT_ATTEMPTED_EXIT_CODE, signal: null }));
		maybeRunAutomaticUpdate([], {
			entrypoint: "cli.js",
			execPath: "node",
			execArgv: [],
			env: {},
			cwd: "/workspace",
			spawnSync: spawn,
		});

		expect(spawn).toHaveBeenCalledWith(
			"node",
			["cli.js", "update"],
			expect.objectContaining({ timeout: expect.any(Number) }),
		);
	});

	it("treats a timed-out update as not handled", () => {
		const spawn = vi.fn().mockReturnValueOnce({ status: null, signal: "SIGTERM", error: new Error("ETIMEDOUT") });
		const result = maybeRunAutomaticUpdate([], {
			entrypoint: "cli.js",
			execPath: "node",
			execArgv: [],
			env: {},
			cwd: "/workspace",
			spawnSync: spawn,
		});

		expect(result).toEqual({ handled: false });
		expect(spawn).toHaveBeenCalledTimes(1);
	});

	it("throttles repeated startup checks", () => {
		const directory = mkdtempSync(join(tmpdir(), "zero-auto-update-test-"));
		const statePath = join(directory, "check.json");
		const spawn = vi.fn(() => ({ status: SELF_UPDATE_NOT_ATTEMPTED_EXIT_CODE, signal: null }));
		const runtime = {
			entrypoint: "cli.js",
			execPath: "node",
			execArgv: [],
			env: {},
			cwd: "/workspace",
			spawnSync: spawn,
			statePath,
			now: 1000,
		};
		try {
			maybeRunAutomaticUpdate([], runtime);
			maybeRunAutomaticUpdate([], runtime);
			expect(spawn).toHaveBeenCalledTimes(1);
		} finally {
			rmSync(directory, { force: true, recursive: true });
		}
	});
});
