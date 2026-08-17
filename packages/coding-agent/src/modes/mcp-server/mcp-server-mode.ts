import { Writable } from "node:stream";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createZeroMcpServer } from "../../core/mcp-server/server.js";
import { flushRawStdout, writeRawStdout } from "../../core/output-guard.js";

export interface McpServerModeOptions {
	cwd: string;
	agentDir?: string;
}

/** Forwards raw writes to writeRawStdout so the protocol stream survives the stdout->stderr takeover every other non-interactive mode applies. */
function createProtocolStdout(): Writable {
	return new Writable({
		write(chunk, _encoding, callback) {
			writeRawStdout(typeof chunk === "string" ? chunk : chunk.toString());
			callback();
		},
	});
}

/**
 * Runs Zero as an MCP server over stdio — the daemon-exposed transport
 * module J calls for, alongside the existing TUI/RPC/ACP modes: `zero
 * --mode mcp-server` speaks the MCP protocol on stdin/stdout so any MCP
 * client (Claude Desktop, Claude Code, another orchestrator) can spawn it
 * as a subprocess delegate worker.
 */
export async function runMcpServerMode(options: McpServerModeOptions): Promise<number> {
	const { server, cancelAllTasks } = createZeroMcpServer({ cwd: options.cwd, agentDir: options.agentDir });
	const transport = new StdioServerTransport(process.stdin, createProtocolStdout());

	let resolveStop: (() => void) | undefined;
	const stopped = new Promise<void>((resolve) => {
		resolveStop = resolve;
	});
	transport.onclose = () => resolveStop?.();
	const signalHandler = () => resolveStop?.();
	process.on("SIGINT", signalHandler);
	// (D13) SIGTERM is a documented no-op on native Windows — Node never emits
	// it there, and process.kill(pid, "SIGTERM") from a parent immediately and
	// unconditionally terminates the child instead of delivering a signal for
	// it to catch (Windows has no equivalent "ask nicely" primitive). Kept for
	// POSIX; SIGBREAK (Ctrl+Break) is the actual Windows-console analogue and
	// is the one this needs there. `transport.onclose` (stdin closing, the
	// normal way an MCP client disconnects) remains the primary shutdown path
	// on every platform regardless of which of these fires.
	process.on("SIGTERM", signalHandler);
	process.on("SIGBREAK", signalHandler);

	try {
		await server.connect(transport);
		await stopped;
	} finally {
		process.off("SIGINT", signalHandler);
		process.off("SIGTERM", signalHandler);
		process.off("SIGBREAK", signalHandler);
		// Release every still-live task's session/kernel before the process
		// exits — a task left waiting on an unanswered question would
		// otherwise leak for as long as the process happened to stay alive.
		cancelAllTasks();
		await server.close().catch(() => {});
		await flushRawStdout();
	}
	return 0;
}
