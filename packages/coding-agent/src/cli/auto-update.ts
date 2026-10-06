import { type SpawnSyncOptions, spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import {
	AUTO_UPDATE_CHILD_ENV,
	AUTO_UPDATE_RELAUNCHED_ENV,
	getAgentDir,
	SELF_UPDATE_NOT_ATTEMPTED_EXIT_CODE,
} from "../config.js";
import { parseArgs } from "./args.js";
import { PUBLIC_COMMAND_NAMES } from "./command-registry.js";

export { AUTO_UPDATE_RELAUNCHED_ENV };

const AUTO_UPDATE_CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000;
const AUTO_UPDATE_TIMEOUT_MS = 3 * 60 * 1000;

interface SpawnResult {
	status: number | null;
	signal: NodeJS.Signals | null;
	error?: Error;
}

interface AutomaticUpdateRuntime {
	entrypoint: string;
	execPath: string;
	execArgv: string[];
	env: NodeJS.ProcessEnv;
	cwd: string;
	spawnSync: (command: string, args: string[], options: SpawnSyncOptions) => SpawnResult;
	statePath?: string;
	now?: number;
}

export interface AutomaticUpdateResult {
	handled: boolean;
	exitCode?: number;
}

function enabled(value: string | undefined): boolean {
	return value === "1" || value?.toLowerCase() === "true" || value?.toLowerCase() === "yes";
}

function checkIsDue(path: string, now: number): boolean {
	try {
		const parsed = JSON.parse(readFileSync(path, "utf8")) as { checkedAt?: unknown };
		return (
			typeof parsed.checkedAt !== "number" ||
			parsed.checkedAt > now ||
			now - parsed.checkedAt >= AUTO_UPDATE_CHECK_INTERVAL_MS
		);
	} catch {
		return true;
	}
}

function recordCheck(path: string, now: number): void {
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	const temporary = `${path}.${process.pid}.tmp`;
	try {
		writeFileSync(temporary, `${JSON.stringify({ checkedAt: now })}\n`, { flag: "wx", mode: 0o600 });
		renameSync(temporary, path);
	} finally {
		rmSync(temporary, { force: true });
	}
}

function claimCheck(path: string, now: number): boolean {
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	const lock = `${path}.lock`;
	for (let attempt = 0; ; attempt++) {
		try {
			mkdirSync(lock, { mode: 0o700 });
			break;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
			let modifiedAt: number;
			try {
				modifiedAt = statSync(lock).mtimeMs;
			} catch (statError) {
				if ((statError as NodeJS.ErrnoException).code === "ENOENT") continue;
				throw statError;
			}
			if (attempt > 0 || now - modifiedAt < 60_000) return false;
			rmSync(lock, { force: true, recursive: true });
		}
	}
	try {
		if (!checkIsDue(path, now)) return false;
		recordCheck(path, now);
		return true;
	} finally {
		rmSync(lock, { force: true, recursive: true });
	}
}

/** Automatic updates are limited to foreground TUI launches, never commands or protocol modes. */
export function shouldAttemptAutomaticUpdate(
	args: string[],
	stdinIsTTY: boolean,
	env: NodeJS.ProcessEnv = process.env,
): boolean {
	if (
		!stdinIsTTY ||
		enabled(env.ZERO_OFFLINE) ||
		enabled(env.ZERO_SKIP_VERSION_CHECK) ||
		enabled(env[AUTO_UPDATE_CHILD_ENV]) ||
		enabled(env[AUTO_UPDATE_RELAUNCHED_ENV])
	) {
		return false;
	}
	const command = args[0];
	const commandIndex = command === "--daemon-socket" ? 2 : 0;
	const publicCommand = args[commandIndex];
	if (publicCommand && publicCommand !== "agents" && PUBLIC_COMMAND_NAMES.has(publicCommand)) return false;
	const parsed = parseArgs(publicCommand === "agents" ? args.slice(commandIndex + 1) : args);
	return (
		!parsed.diagnostics.some((diagnostic) => diagnostic.type === "error") &&
		!parsed.offline &&
		!parsed.help &&
		!parsed.version &&
		!parsed.export &&
		!parsed.listModels &&
		!parsed.print &&
		(parsed.mode === undefined || parsed.mode === "text")
	);
}

/** Run the updater out-of-process, then relaunch once so no loaded code is replaced in place. */
export function maybeRunAutomaticUpdate(
	args: string[],
	runtime: AutomaticUpdateRuntime = {
		entrypoint: process.argv[1] ?? "",
		execPath: process.execPath,
		execArgv: process.execArgv,
		env: process.env,
		cwd: process.cwd(),
		spawnSync,
		statePath: join(getAgentDir(), "auto-update-check.json"),
	},
): AutomaticUpdateResult {
	if (!runtime.entrypoint) return { handled: false };
	const now = runtime.now ?? Date.now();
	if (runtime.statePath) {
		try {
			if (!claimCheck(runtime.statePath, now)) return { handled: false };
		} catch {
			return { handled: false };
		}
	}
	const update = runtime.spawnSync(runtime.execPath, [...runtime.execArgv, runtime.entrypoint, "update"], {
		cwd: runtime.cwd,
		env: { ...runtime.env, [AUTO_UPDATE_CHILD_ENV]: "1" },
		stdio: "ignore",
		timeout: AUTO_UPDATE_TIMEOUT_MS,
		windowsHide: true,
	});
	if (update.status === SELF_UPDATE_NOT_ATTEMPTED_EXIT_CODE) {
		return { handled: false };
	}
	if (update.error || update.status !== 0) {
		return { handled: false };
	}
	// Relaunch this same Node binary and entrypoint, so no PATH or cwd lookup can pick another program.
	const relaunch = runtime.spawnSync(runtime.execPath, [...runtime.execArgv, runtime.entrypoint, ...args], {
		cwd: runtime.cwd,
		env: { ...runtime.env, [AUTO_UPDATE_RELAUNCHED_ENV]: "1" },
		stdio: "inherit",
		windowsHide: true,
	});
	return { handled: true, exitCode: relaunch.error ? 1 : (relaunch.status ?? (relaunch.signal ? 1 : 0)) };
}
