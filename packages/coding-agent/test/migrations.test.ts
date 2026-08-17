import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CONFIG_DIR_NAME, ENV_AGENT_DIR } from "../src/config.js";
import {
	migrateLegacyConfigDir,
	migrateLegacySessionDirsToSessionRoot,
	migrateSessionsFromAgentRoot,
} from "../src/migrations.js";

describe("session migrations", () => {
	const tempDirs: string[] = [];
	const previousAgentDir = process.env[ENV_AGENT_DIR];

	afterEach(() => {
		if (previousAgentDir === undefined) {
			delete process.env[ENV_AGENT_DIR];
		} else {
			process.env[ENV_AGENT_DIR] = previousAgentDir;
		}
		for (const dir of tempDirs.splice(0)) {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("moves legacy per-cwd session files into the flat session root", () => {
		const agentDir = mkdtempSync(join(tmpdir(), "prime-agent-migrations-"));
		tempDirs.push(agentDir);
		process.env[ENV_AGENT_DIR] = agentDir;

		const sessionsDir = join(agentDir, "sessions");
		const legacyDir = join(sessionsDir, "--tmp-project--");
		mkdirSync(legacyDir, { recursive: true });
		const legacyFile = join(legacyDir, "session-1.jsonl");
		const sessionLines = [
			{
				type: "session",
				version: 3,
				id: "session-1",
				timestamp: new Date().toISOString(),
				cwd: "/tmp/project",
			},
			{
				type: "message",
				id: "entry-1",
				parentId: null,
				timestamp: new Date().toISOString(),
				message: { role: "user", content: "hello", timestamp: Date.now() },
			},
		];
		writeFileSync(legacyFile, `${sessionLines.map((line) => JSON.stringify(line)).join("\n")}\n`);

		migrateLegacySessionDirsToSessionRoot();

		const migratedFile = join(sessionsDir, "session-1.jsonl");
		expect(existsSync(legacyFile)).toBe(false);
		expect(existsSync(legacyDir)).toBe(false);
		expect(readFileSync(migratedFile, "utf8")).toContain('"id":"session-1"');
	});

	it("moves root session files using only the JSONL header", () => {
		const agentDir = mkdtempSync(join(tmpdir(), "prime-agent-migrations-"));
		tempDirs.push(agentDir);
		process.env[ENV_AGENT_DIR] = agentDir;

		const legacyFile = join(agentDir, "session-root.jsonl");
		writeFileSync(
			legacyFile,
			`${JSON.stringify({
				type: "session",
				version: 3,
				id: "session-root",
				timestamp: new Date().toISOString(),
				cwd: "/tmp/project",
			})}\n${"x".repeat(128 * 1024)}\n`,
		);

		migrateSessionsFromAgentRoot();

		const migratedFile = join(agentDir, "sessions", "session-root.jsonl");
		expect(existsSync(legacyFile)).toBe(false);
		expect(readFileSync(migratedFile, "utf8")).toContain('"id":"session-root"');
	});

	it("does not move session files from non-legacy subdirectories", () => {
		const agentDir = mkdtempSync(join(tmpdir(), "prime-agent-migrations-"));
		tempDirs.push(agentDir);
		process.env[ENV_AGENT_DIR] = agentDir;

		const sessionsDir = join(agentDir, "sessions");
		const nonLegacyDir = join(sessionsDir, "exports");
		mkdirSync(nonLegacyDir, { recursive: true });
		const nestedFile = join(nonLegacyDir, "session-2.jsonl");
		writeFileSync(
			nestedFile,
			`${JSON.stringify({
				type: "session",
				version: 3,
				id: "session-2",
				timestamp: new Date().toISOString(),
				cwd: "/tmp/project",
			})}\n`,
		);

		migrateLegacySessionDirsToSessionRoot();

		expect(existsSync(nestedFile)).toBe(true);
		expect(existsSync(join(sessionsDir, "session-2.jsonl"))).toBe(false);
	});
});

describe("legacy config-dir migration (A1)", () => {
	const tempDirs: string[] = [];

	afterEach(() => {
		for (const dir of tempDirs.splice(0)) {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	function makeBaseDir(): string {
		const baseDir = mkdtempSync(join(tmpdir(), "zero-legacy-config-dir-"));
		tempDirs.push(baseDir);
		return baseDir;
	}

	it("moves an existing .prime/agent to .zero/agent, preserving contents", () => {
		const baseDir = makeBaseDir();
		const legacyDir = join(baseDir, ".prime", "agent");
		mkdirSync(legacyDir, { recursive: true });
		writeFileSync(join(legacyDir, "auth.json"), '{"anthropic":{"type":"api_key","key":"secret"}}', {
			mode: 0o600,
		});

		migrateLegacyConfigDir(baseDir, "test");

		const currentDir = join(baseDir, CONFIG_DIR_NAME);
		expect(existsSync(legacyDir)).toBe(false);
		expect(existsSync(currentDir)).toBe(true);
		expect(readFileSync(join(currentDir, "auth.json"), "utf8")).toContain("secret");
	});

	it("does nothing when there is no legacy directory (fresh install)", () => {
		const baseDir = makeBaseDir();

		expect(() => migrateLegacyConfigDir(baseDir, "test")).not.toThrow();
		expect(existsSync(join(baseDir, CONFIG_DIR_NAME))).toBe(false);
	});

	it("never merges or overwrites when both the legacy and current dirs already exist", () => {
		const baseDir = makeBaseDir();
		const legacyDir = join(baseDir, ".prime", "agent");
		const currentDir = join(baseDir, CONFIG_DIR_NAME);
		mkdirSync(legacyDir, { recursive: true });
		writeFileSync(join(legacyDir, "marker.txt"), "legacy");
		mkdirSync(currentDir, { recursive: true });
		writeFileSync(join(currentDir, "marker.txt"), "current");

		migrateLegacyConfigDir(baseDir, "test");

		expect(existsSync(legacyDir)).toBe(true);
		expect(readFileSync(join(legacyDir, "marker.txt"), "utf8")).toBe("legacy");
		expect(readFileSync(join(currentDir, "marker.txt"), "utf8")).toBe("current");
	});
});
