import { getLogger, type LogEntry, setLogSink, stringifyLogEntry } from "@zero-agent/ai";
import { appendRotatingLog, getAgentLogPath, getClientErrorLogPath } from "../config.js";

const AGENT_LOG_MAX_BYTES = 20 * 1024 * 1024;

let context: Record<string, unknown> = {};

/** Merge late-bound fields (e.g. mode, sessionId) into every subsequent log entry. */
export function setLogContext(fields: Record<string, unknown>): void {
	Object.assign(context, fields);
}

/**
 * Route all structured logging (coding-agent and pi-ai) to the shared JSONL
 * log at ~/.zero/agent/logs/agent.jsonl. One master file, filterable by the
 * pid/context fields; writes are best-effort and size-bounded.
 */
export function installFileLogSink(fields?: Record<string, unknown>): void {
	context = { pid: process.pid, ...fields };
	setLogSink((entry: LogEntry) => {
		appendRotatingLog(getAgentLogPath(), stringifyLogEntry({ ...entry, ...context }), AGENT_LOG_MAX_BYTES);
	});
}

let clientCrashHandlersInstalled = false;

/**
 * A crash outside any command handler otherwise prints Node's default trace
 * to stderr — easy to miss behind the TUI's alt-screen buffer — and the
 * process vanishes with no trail. Mirrors daemon-mode.ts's own
 * installCrashHandlers, scoped to the client/foreground process (interactive,
 * rpc, acp, json); the daemon keeps installing its own instead, tagged with
 * its socket path, so call this only for non-daemon app modes.
 *
 * A no-op under the test runner and idempotent otherwise: the coding-agent
 * test suite calls `main()` directly, many times, in-process (e.g.
 * package-command-paths.test.ts) — a real `process.exit(1)` here would take
 * down the whole shared vitest worker (and every other test file scheduled
 * on it) the first time any of those calls hit an unhandled rejection.
 */
export function installClientCrashHandlers(): void {
	if (clientCrashHandlersInstalled || process.env.NODE_ENV === "test") {
		return;
	}
	clientCrashHandlersInstalled = true;
	const log = getLogger("coding-agent.client");
	const handle = (kind: "uncaught exception" | "unhandled rejection", error: unknown): void => {
		const detail = error instanceof Error ? (error.stack ?? error.message) : String(error);
		log.error(`${kind}: ${detail}`);
		appendRotatingLog(getClientErrorLogPath(), `[${new Date().toISOString()}] ${kind}: ${detail}`);
		process.exit(1);
	};
	process.on("uncaughtException", (error) => handle("uncaught exception", error));
	process.on("unhandledRejection", (reason) => handle("unhandled rejection", reason));
}
